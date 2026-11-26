// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Protected Group approvals of a deploy job (UI-72), as `mydc compose up`:
// the begin-app original is prepared once and kept in the job; every realm
// its blueprint uses is planned with it as Origin (vault-approval-plan);
// a Group without an existing approval waits for the requester's password,
// which goes over SecretInput (mode approve) to the plan's approver node
// and is never stored. When every Group is approved the same original is
// sent.

// approvalRealms are the realms the planned artifact's services read
// secrets from. ok=false: the artifact is not a blueprint this build can
// decode (the fake adapter plans the YAML itself); then only the tenant's
// own realm is tried and "denied" means no use.
func approvalRealms(artifact []byte, requester [32]byte, tenant string) ([]string, bool, error) {
	b, err := deployment.DecodeBlueprint(artifact)
	if err != nil {
		return []string{tenant}, false, nil
	}
	uses, err := b.ApprovalUses(requester)
	if err != nil {
		return nil, true, err
	}
	var out []string
	for r := range uses {
		out = append(out, r)
	}
	slices.Sort(out)
	return out, true, nil
}

// deployApprovals prepares the begin-app original (once) and refreshes the
// job's Group approvals. ready: none is still required.
func (s *Server) deployApprovals(ctx context.Context, c mydc.Conn, ws *webSession, parent *store.Op, prune bool) (bool, error) {
	j := parent.Deploy
	if len(j.Origin) == 0 {
		ch, err := s.deployChange(ctx, c, ws, j, prune)
		if err != nil {
			return false, err
		}
		who, err := c.Whoami(ctx)
		if err != nil {
			return false, err
		}
		op, err := c.Prepare(ctx, ch, who.RootFor(ch.Action))
		if err != nil {
			return false, err
		}
		j.Origin = op
		if err := s.saveOp(parent); err != nil {
			return false, err
		}
	}
	origin, err := mydc.DecodeOperation(mydc.SignedOp(j.Origin))
	if err != nil {
		return false, err
	}
	realms, known, err := approvalRealms(j.Document, origin.Session.Key, j.Tenant)
	if err != nil {
		return false, &httpErr{http.StatusUnprocessableEntity, "invalid", "the planned app's secret uses cannot be read"}
	}
	next, ready, err := planApprovals(ctx, c, j.Tenant, "compose/"+j.UploadID, &origin, realms, known, j.Approvals)
	if err != nil {
		return false, err
	}
	j.Approvals = next
	return ready, nil
}

// planApprovals plans each realm for origin (vault-approval-plan, id the
// approval journal ID) and keeps what prev already knew. known=false: a
// realm may have no use, and "denied" then means none. ready: no Group is
// still required.
func planApprovals(ctx context.Context, c mydc.Conn, tenant, id string, origin *mydc.UserOperation, realms []string, known bool, prev []store.DeployApproval) ([]store.DeployApproval, bool, error) {
	before := map[string]string{}
	for _, a := range prev {
		before[a.Realm+"/"+a.Group] = a.State
	}
	var next []store.DeployApproval
	ready := true
	for _, realm := range realms {
		plan, err := c.PlanVaultApprovals(ctx, tenant, mydc.VaultApprovalPlanRequest{Realm: realm, ID: id, Origin: origin})
		var me *mydc.Error
		if err != nil && !known && errors.As(err, &me) && me.Code == mydc.CodeDenied {
			continue // no use of this realm
		}
		if err != nil {
			return nil, false, err
		}
		for _, t := range plan.Targets {
			a := store.DeployApproval{Realm: t.Target.Realm, Group: t.Target.Group, Services: t.Target.Services, State: "required"}
			a.Target, _ = json.Marshal(t.Target)
			if t.Approver != nil {
				a.Approver, _ = json.Marshal(t.Approver)
			}
			switch {
			case t.Existing != nil, before[a.Realm+"/"+a.Group] == "approved":
				a.State = "approved"
			case t.Approver == nil:
				return nil, false, &httpErr{http.StatusConflict, "no-approver", "the Group " + a.Group + " has no current approver"}
			case before[a.Realm+"/"+a.Group] == "unknown":
				a.State = "unknown"
			}
			if a.State != "approved" {
				ready = false
			}
			next = append(next, a)
		}
	}
	return next, ready, nil
}

// POST /t/{t}/apps/deploy/{opId}/approve {realm?, group, password} → the
// Group's password to its approver; then the deploy job continues.
func (s *Server) handleDeployApprove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	req, pw, ok := readApprove(w, r)
	if !ok {
		return
	}
	defer clear(pw)
	tenant := r.PathValue("t")
	parent, err := s.opt.Store.GetOp(ws.user.ID, r.PathValue("op"))
	if errors.Is(err, store.ErrNotFound) || err == nil && (parent.Deploy == nil || parent.Deploy.Tenant != tenant) {
		writeError(w, http.StatusNotFound, "not-found", "no such deploy job")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	j := parent.Deploy
	i := slices.IndexFunc(j.Approvals, func(a store.DeployApproval) bool { return a.Realm == req.Realm && a.Group == req.Group })
	if parent.ErrorCode != "approval-required" || i < 0 || len(j.Origin) == 0 {
		writeError(w, http.StatusConflict, "not-required", "this deploy job does not wait for that Group")
		return
	}
	a := &j.Approvals[i]
	if a.State == "approved" {
		writeError(w, http.StatusConflict, "already-approved", "this Group is already approved")
		return
	}
	origin, err := mydc.DecodeOperation(mydc.SignedOp(j.Origin))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "stored approval")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		err := approveGroup(ctx, c, tenant, a, &origin, pw)
		parent.UpdatedAt = s.now()
		if e := s.saveOp(parent); e != nil {
			return e
		}
		if a.State != "approved" {
			return err
		}
		return s.runDeploy(ctx, c, ws, parent, false)
	})
	writeApproveOutcome(w, ws, s, a, parent, err)
}

type approveReq struct {
	Realm string
	Group string
}

// readApprove reads {realm?, group, password}; the realm defaults to the
// tenant. The caller clears pw.
func readApprove(w http.ResponseWriter, r *http.Request) (approveReq, []byte, bool) {
	var req struct {
		Realm    string `json:"realm,omitempty"`
		Group    string `json:"group"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return approveReq{}, nil, false
	}
	// Known limit: the decoded Go string cannot be wiped; only this copy is.
	pw := []byte(req.Password)
	req.Password = ""
	if len(pw) == 0 || len(pw) > 1024 || strings.ContainsAny(string(pw), "\r\n\x00") {
		clear(pw)
		writeError(w, http.StatusBadRequest, "bad-request", "password: one line, 1 to 1024 bytes")
		return approveReq{}, nil, false
	}
	if req.Realm == "" {
		req.Realm = r.PathValue("t")
	}
	return approveReq{req.Realm, req.Group}, pw, true
}

// writeApproveOutcome answers an approve call after the Group's state.
func writeApproveOutcome(w http.ResponseWriter, ws *webSession, s *Server, a *store.DeployApproval, parent *store.Op, err error) {
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	switch a.State {
	case "required":
		writeError(w, http.StatusForbidden, "approval-denied", "the password was not accepted for this Group")
		return
	case "unknown":
		writeError(w, http.StatusBadGateway, "approval-unknown", "the approver's answer was lost; send the password again")
		return
	}
	writeJSON(w, opStatus(parent), map[string]any{"op": viewOp(parent)})
}

// approveGroup sends the Group's password to its approver for origin
// (SecretInput mode approve) and sets a.State: approved, required (the
// password was not accepted) or unknown (the answer was lost).
func approveGroup(ctx context.Context, c mydc.Conn, tenant string, a *store.DeployApproval, origin *mydc.UserOperation, pw []byte) error {
	var target secrets.Target
	var approver config.Peer
	if json.Unmarshal(a.Target, &target) != nil || json.Unmarshal(a.Approver, &approver) != nil {
		return &httpErr{http.StatusInternalServerError, "internal", "stored approval"}
	}
	code, err := c.ApproveVault(ctx, tenant, approver, mydc.VaultApprove{Target: target, Password: pw, Origin: origin})
	switch {
	case err != nil:
		a.State = "unknown"
	case code == "ok":
		a.State = "approved"
	case code == "denied":
		a.State = "required"
	default:
		a.State = "unknown"
	}
	return err
}

// GET /t/{t}/vault/approvals → {items: [{opId, app, realm, group, services,
// state, updatedAt}]}: this user's deploy jobs in the tenant that wait for
// a Group password (web-own job records).
func (s *Server) handleVaultApprovals(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	ops, err := s.opt.Store.ListOps(ws.user.ID, store.OpRunning, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	items := []map[string]any{}
	for _, o := range ops {
		if o.ErrorCode != "approval-required" {
			continue
		}
		at := o.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")
		switch {
		case o.Deploy != nil && o.Deploy.Tenant == tenant:
			for _, a := range o.Deploy.Approvals {
				item := map[string]any{"opId": o.ID, "kind": "deploy", "app": o.Deploy.App, "realm": a.Realm, "group": a.Group,
					"services": append([]string{}, a.Services...), "state": a.State, "updatedAt": at}
				if sa := o.Deploy.Standalone; sa != nil {
					item["kind"], item["standalone"] = "standalone", sa.Name
					delete(item, "app")
				}
				items = append(items, item)
			}
		case o.BuildApproval != nil && o.BuildApproval.Tenant == tenant:
			for _, a := range o.BuildApproval.Approvals {
				items = append(items, map[string]any{"opId": o.ID, "kind": "build", "context": o.BuildApproval.Context, "build": o.BuildApproval.Job,
					"realm": a.Realm, "group": a.Group, "services": append([]string{}, a.Services...), "state": a.State, "updatedAt": at})
			}
		case o.RegistryBind != nil && o.RegistryBind.Tenant == tenant:
			for _, a := range o.RegistryBind.Approvals {
				items = append(items, map[string]any{"opId": o.ID, "kind": "registry-bind", "source": o.RegistryBind.Source, "node": o.RegistryBind.Node,
					"realm": a.Realm, "group": a.Group, "services": append([]string{}, a.Services...), "state": a.State, "updatedAt": at})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// cdSelection reads ?candidate=<hex> / ?operation=<id> (or the same body
// fields) into an approval selection.
func cdSelection(candidate, operation string) (mydc.AppApprovalSelection, error) {
	var sel mydc.AppApprovalSelection
	switch {
	case candidate != "" && operation == "":
		d, err := hex.DecodeString(candidate)
		if err != nil || len(d) != 32 {
			return sel, invalid("candidate: 64 hex characters (the app's cd.candidateDigest)")
		}
		c := [32]byte(d)
		sel.Candidate = &c
	case operation != "" && candidate == "":
		sel.Operation = operation
	default:
		return sel, invalid("give one of candidate or operation")
	}
	if !sel.Valid() {
		return sel, invalid("candidate or operation")
	}
	return sel, nil
}

// cdApprovals plans every realm of a CD registration for its selection.
func cdApprovals(ctx context.Context, c mydc.Conn, tenant, app string, sel mydc.AppApprovalSelection) (mydc.AppCDRegistration, []mydc.VaultApprovalTarget, error) {
	reg, err := c.AppDeliveryRegistration(ctx, tenant, app, sel)
	if err != nil {
		return reg, nil, err
	}
	var out []mydc.VaultApprovalTarget
	for _, realm := range reg.Realms {
		plan, err := c.PlanVaultApprovals(ctx, tenant, mydc.VaultApprovalPlanRequest{Realm: realm, ID: "compose/" + app + "/cd", Origin: &reg.Origin, Selection: &reg.Selection})
		if err != nil {
			return reg, nil, err
		}
		out = append(out, plan.Targets...)
	}
	return reg, out, nil
}

func cdApprovalViews(targets []mydc.VaultApprovalTarget) []approvalView {
	out := []approvalView{}
	for _, t := range targets {
		state := "required"
		if t.Existing != nil {
			state = "approved"
		}
		out = append(out, approvalView{t.Target.Realm, t.Target.Group, append([]string{}, t.Target.Services...), state})
	}
	return out
}

// GET /t/{t}/apps/{app}/cd/approvals?candidate=|operation= → {app,
// approvals:[{realm, group, services, state}]}: the protected Groups a CD
// candidate (or pending CD operation) needs from its registrant.
func (s *Server) handleCDApprovals(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app := r.PathValue("t"), r.PathValue("app")
	sel, err := cdSelection(r.URL.Query().Get("candidate"), r.URL.Query().Get("operation"))
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		_, targets, err := cdApprovals(ctx, c, tenant, app, sel)
		if err != nil {
			return nil, err
		}
		return map[string]any{"app": app, "approvals": cdApprovalViews(targets)}, nil
	})
}

// POST /t/{t}/apps/{app}/cd/approvals {candidate?|operation?, realm?, group,
// password} → the Group's password to its approver for that CD selection,
// as `mydc cd approve`. Reply {app, approvals}. Errors as deploy approve.
func (s *Server) handleCDApprove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Candidate string `json:"candidate,omitempty"`
		Operation string `json:"operation,omitempty"`
		Realm     string `json:"realm,omitempty"`
		Group     string `json:"group"`
		Password  string `json:"password"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	// Known limit: the decoded Go string cannot be wiped; only this copy is.
	pw := []byte(req.Password)
	req.Password = ""
	defer clear(pw)
	if len(pw) == 0 || len(pw) > 1024 || strings.ContainsAny(string(pw), "\r\n\x00") {
		writeError(w, http.StatusBadRequest, "bad-request", "password: one line, 1 to 1024 bytes")
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	if req.Realm == "" {
		req.Realm = tenant
	}
	sel, err := cdSelection(req.Candidate, req.Operation)
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var views []approvalView
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		reg, targets, err := cdApprovals(ctx, c, tenant, app, sel)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(targets, func(t mydc.VaultApprovalTarget) bool {
			return t.Target.Realm == req.Realm && t.Target.Group == req.Group
		})
		switch {
		case i < 0:
			return &httpErr{http.StatusConflict, "not-required", "this candidate does not need that Group"}
		case targets[i].Existing != nil:
			return &httpErr{http.StatusConflict, "already-approved", "this Group is already approved"}
		case targets[i].Approver == nil:
			return &httpErr{http.StatusConflict, "no-approver", "the Group has no current approver"}
		}
		code, err := c.ApproveVault(ctx, tenant, *targets[i].Approver, mydc.VaultApprove{Target: targets[i].Target, Password: pw, Origin: &reg.Origin, Selection: &reg.Selection})
		switch {
		case err != nil || code != "ok" && code != "denied":
			return &httpErr{http.StatusBadGateway, "approval-unknown", "the approver's answer was lost; send the password again"}
		case code == "denied":
			return &httpErr{http.StatusForbidden, "approval-denied", "the password was not accepted for this Group"}
		}
		targets[i].Existing = &secrets.Approval{} // just approved
		views = cdApprovalViews(targets)
		return nil
	})
	if err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"app": app, "approvals": views})
}

// grantedApproval is one PublicRead vault-approvals row. Issuer is the
// hex key of the server that checked the password; revoking = a revoke
// was accepted and the approval's consumers are being released.
type grantedApproval struct {
	ID         string   `json:"id"`
	Realm      string   `json:"realm"`
	Tenant     string   `json:"tenant"`
	Group      string   `json:"group"`
	User       string   `json:"user"`
	App        string   `json:"app,omitempty"`
	Standalone string   `json:"standalone,omitempty"`
	Deployment string   `json:"deployment,omitempty"`
	Purpose    string   `json:"purpose,omitempty"`
	Services   []string `json:"services"`
	Nodes      []string `json:"nodes"`
	ApprovedAt int64    `json:"approvedAt"`
	ExpiresAt  int64    `json:"expiresAt,omitempty"`
	Issuer     string   `json:"issuer"`
	Revoking   bool     `json:"revoking"`
	Consumers  int      `json:"consumers"`
}

// GET /t/{t}/vault/approvals/granted?app=&after= → {items:[row], next,
// collection}: the realm's committed Group approvals (REQ-42 PublicRead
// vault-approvals, one page; next goes back as after unread). collection
// is vault-revoke-approval's expected.
func (s *Server) handleGrantedApprovals(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, q := r.PathValue("t"), r.URL.Query()
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		p, err := c.PublicRead(ctx, "vault-approvals", tenant, control.PublicReadQuery{App: q.Get("app")}, q.Get("after"))
		if err != nil {
			return nil, err
		}
		items := []grantedApproval{}
		for _, row := range p.Rows {
			if a := row.Approval; a != nil {
				items = append(items, grantedApproval{ID: a.ID, Realm: a.Realm, Tenant: a.Tenant, Group: a.Group, User: a.User, App: a.App, Standalone: a.Standalone,
					Deployment: a.Deployment, Purpose: a.Purpose, Services: append([]string{}, a.Services...), Nodes: append([]string{}, a.Nodes...),
					ApprovedAt: a.ApprovedAt, ExpiresAt: a.ExpiresAt, Issuer: hex.EncodeToString(a.Issuer[:]), Revoking: a.Revoking, Consumers: a.Consumers})
			}
		}
		out := map[string]any{"items": items, "next": p.Next, "total": p.Total}
		// the list does not depend on the revoke Expected: without it the
		// revoke reads it again (and fails there)
		if rev, err := approvalRevision(ctx, c, tenant); err == nil {
			out["collection"] = rev
		} else if ctx.Err() != nil {
			return nil, err
		}
		return out, nil
	})
}

// approvalRevision: vault-revoke-approval's Expected (the Vault approval
// book revision, which the vault read carries).
func approvalRevision(ctx context.Context, c mydc.Conn, tenant string) (uint64, error) {
	p, err := c.Vault(ctx, tenant, "")
	return p.ApprovalRevision, err
}

// POST /t/{t}/vault/approvals/granted/{id}/revoke {opId, expected?} →
// vault-revoke-approval {ID} (Expected = the list's collection; mydcd
// decides who may revoke).
func (s *Server) handleRevokeApproval(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		rev, err := approvalRevision(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		return mydc.ActionVaultRevokeApproval, mydc.VaultApprovalSelection{ID: id}, expectedOr(req.Expected, rev), "approval/" + id, nil
	})
}
