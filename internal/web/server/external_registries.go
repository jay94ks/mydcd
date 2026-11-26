// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagesource"
	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// External image registry sources in mydcd's real contract (REQ-17,
// docs/reference/external-registries.md; canvas RegistryExternal: list,
// add, credential swap, reader server, login test, users). A source holds
// vault references only; mydcd checks the definition, reads the vault,
// judges permissions and keeps the record CAS (Expected = the record
// Revision, 0 for a new ID). The web reads with the person's session,
// reshapes rows and keeps nothing but its own op records.

const maxExternalPages = 40 // 8 a page; mydcd keeps at most 256 sources

type registryReaderView struct {
	Node       string `json:"node"`
	Owner      string `json:"owner"`
	Generation uint64 `json:"generation"`
	Draining   bool   `json:"draining"`
}

type registryPullView struct {
	Node        string `json:"node"`
	Stage       string `json:"stage"`
	Code        string `json:"code"`
	CompletedAt int64  `json:"completedAt"`
	ReportedAt  int64  `json:"reportedAt"`
	Stale       bool   `json:"stale"`
}

type externalRegistryView struct {
	ID         string                            `json:"id"`
	Authority  string                            `json:"authority"`
	Repository string                            `json:"repository"`
	Enabled    bool                              `json:"enabled"`
	Auth       string                            `json:"auth"`
	Credential *imagesource.Credential           `json:"credential,omitempty"`
	CA         *imagesource.CertificateAuthority `json:"ca,omitempty"`
	Revision   uint64                            `json:"revision"`
	Deleted    bool                              `json:"deleted"`
	Reader     *registryReaderView               `json:"reader,omitempty"`
	Pulls      []registryPullView                `json:"pulls"`
}

// externalSources reads every page of `external-registries`, again from
// the start when the root revision moves between pages.
func externalSources(ctx context.Context, c mydc.Conn, tenant string) ([]control.ExternalRegistryView, uint64, error) {
	for range 3 {
		var out []control.ExternalRegistryView
		var root uint64
		after, moved := "", false
		for range maxExternalPages {
			p, err := c.ExternalRegistryPage(ctx, tenant, after)
			if err != nil {
				return nil, 0, err
			}
			if root != 0 && p.RootRevision != root {
				moved = true
				break
			}
			root = p.RootRevision
			out = append(out, p.Items...)
			if p.Next == "" {
				return out, root, nil
			}
			after = p.Next
		}
		if !moved {
			return nil, 0, &httpErr{http.StatusBadGateway, "too-many", "external-registries: too many pages"}
		}
	}
	return nil, 0, &httpErr{http.StatusConflict, "changed", "the sources kept changing; read again"}
}

func findExternalSource(ctx context.Context, c mydc.Conn, tenant, id string) (*control.ExternalRegistryView, error) {
	rows, _, err := externalSources(ctx, c, tenant)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(rows, func(x control.ExternalRegistryView) bool { return x.Spec.ID == id })
	if i < 0 {
		return nil, nil
	}
	return &rows[i], nil
}

// registryPulls reads the pages of `external-registry-pulls` (at most
// maxExternalPages), again from the start once when the rows change
// between pages.
func registryPulls(ctx context.Context, c mydc.Conn, tenant string) ([]control.RegistryPullView, error) {
	var me *mydc.Error
	for try := 0; ; try++ {
		var out []control.RegistryPullView
		after := ""
		var err error
		for range maxExternalPages {
			var p control.RegistryPullPage
			if p, err = c.RegistryPulls(ctx, tenant, after); err != nil {
				break
			}
			out = append(out, p.Rows...)
			if after = p.Next; after == "" {
				break
			}
		}
		if err == nil {
			return out, nil
		}
		if try > 0 || !errors.As(err, &me) || me.Code != mydc.CodeConflict {
			return nil, err
		}
	}
}

func viewExternalSource(x control.ExternalRegistryView, pulls []control.RegistryPullView) externalRegistryView {
	s := x.Spec
	v := externalRegistryView{ID: s.ID, Authority: s.Authority, Repository: s.Repository, Enabled: s.Enabled, Auth: s.Auth,
		Credential: s.Credential, CA: s.CA, Revision: x.Revision, Deleted: x.Deleted, Pulls: []registryPullView{}}
	if r := x.Reader; r != nil {
		v.Reader = &registryReaderView{r.Node, hex.EncodeToString(r.Owner[:]), r.Generation, r.Draining}
	}
	for _, p := range pulls {
		if p.Source == s.ID && p.Authority == s.Authority {
			v.Pulls = append(v.Pulls, registryPullView{p.Node, p.Stage, lowerCode(p.Code), int64(p.CompletedAt / 1000), int64(p.ReportedAt / 1000), p.Stale})
		}
	}
	return v
}

// lowerCode: mydcd's bounded codes (OK, NOT_FOUND, …) as ok, not-found.
func lowerCode(code string) string {
	return strings.ReplaceAll(strings.ToLower(code), "_", "-")
}

// GET /t/{t}/external-registries → {items, revision, asOf}: every source
// (deleted ones whose reader still drains too) with its reader and the
// latest real pull per server.
func (s *Server) handleExternalRegistries(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		rows, root, err := externalSources(ctx, c, tenant)
		if err != nil {
			return listPage{}, err
		}
		pulls, err := registryPulls(ctx, c, tenant)
		if err != nil {
			return listPage{}, err
		}
		items := make([]externalRegistryView, 0, len(rows))
		for _, x := range rows {
			items = append(items, viewExternalSource(x, pulls))
		}
		return s.page(items, "", root), nil
	})
}

type imageUsageView struct {
	App        string `json:"app,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Node       string `json:"node,omitempty"`
	Service    string `json:"service,omitempty"`
	Instance   string `json:"instance,omitempty"`
	Image      string `json:"image"`
	Kind       string `json:"kind"`
	Match      string `json:"match"`
	Unknown    bool   `json:"unknown,omitempty"`
}

// GET /t/{t}/external-registries/{id}/users?after= → {items, next, asOf}:
// the running app tasks and standalone containers whose image this source
// logs in for (`image-usages` with ExternalSource).
func (s *Server) handleExternalRegistryUsers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, id := r.PathValue("t"), r.PathValue("id")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (listPage, error) {
		p, err := c.ImageUsages(ctx, tenant, control.ImageUsageQuery{ExternalSource: id}, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		items := make([]imageUsageView, 0, len(p.Rows))
		for _, u := range p.Rows {
			items = append(items, imageUsageView{u.App, u.Deployment, u.Node, u.Service, u.Instance, u.Image, u.Kind, u.Match, u.Unknown})
		}
		return s.page(items, p.Next, 0), nil
	})
}

type registryProbeView struct {
	ID         string                     `json:"id"`
	Generation uint64                     `json:"generation"`
	Owner      string                     `json:"owner"`
	At         int64                      `json:"at"`
	Code       string                     `json:"code"`
	Image      *registryclient.Resolution `json:"image,omitempty"`
	Pull       *registryclient.PullCheck  `json:"pull,omitempty"`
}

// POST /t/{t}/external-registries/{id}/test {image?} → one login (and,
// with image, a pull check) through the source's bound reader. Not an op;
// only the result comes back. 409 when no reader is bound.
func (s *Server) handleTestExternalRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Image string `json:"image,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Image) > 512 {
		s.writeOpOutcome(w, ws, nil, 0, invalid("image: at most 512 characters"))
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (registryProbeView, error) {
		res, err := c.ProbeExternalRegistry(ctx, r.PathValue("t"), control.ExternalRegistryProbeQuery{ID: r.PathValue("id"), Image: req.Image})
		var me *mydc.Error
		if errors.As(err, &me) && me.Code == mydc.CodeConflict {
			return registryProbeView{}, &httpErr{http.StatusConflict, "not-bound", "bind the source to a server first"}
		}
		if err != nil {
			return registryProbeView{}, err
		}
		return registryProbeView{res.Selection.ID, res.Selection.Generation, hex.EncodeToString(res.Owner[:]), res.At, lowerCode(res.Code), res.Image, res.Pull}, nil
	})
}

// PUT /t/{t}/external-registries/{id} {opId, authority, repository,
// enabled?, auth, credential?{realm, id, usernameKey, passwordKey},
// ca?{realm, id, key}, expected?} → put-external-registry {Spec}. The whole
// definition each time; a credential swap is a put with another vault
// reference. Authority and repository stay fixed for an ID. A put drains
// the bound reader: bind again afterwards.
func (s *Server) handlePutExternalRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string                            `json:"opId"`
		Authority  string                            `json:"authority"`
		Repository string                            `json:"repository"`
		Enabled    *bool                             `json:"enabled,omitempty"`
		Auth       string                            `json:"auth"`
		Credential *imagesource.Credential           `json:"credential,omitempty"`
		CA         *imagesource.CertificateAuthority `json:"ca,omitempty"`
		Expected   uint64                            `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		spec := imagesource.Source{Tenant: tenant, ID: id, Authority: req.Authority, Repository: req.Repository, Enabled: req.Enabled == nil || *req.Enabled,
			Auth: req.Auth, Credential: req.Credential, CA: req.CA}
		if spec.Repository == "" {
			spec.Repository = "**"
		}
		if err := spec.Validate(); err != nil {
			return "", nil, 0, "", invalid("the source: id, authority, repository (path, prefix/** or **), auth none/password/token with credential only for password/token, vault references in this workspace")
		}
		cur, err := findExternalSource(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		var rev uint64
		if cur != nil {
			if cur.Spec.Authority != spec.Authority || cur.Spec.Repository != spec.Repository {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "scope-fixed", "authority and repository stay fixed for an ID: add a new ID"}
			}
			rev = cur.Revision
		}
		return mydc.ActionPutExternalRegistry, control.ExternalRegistryPut{Spec: spec}, expectedOr(req.Expected, rev), "external-registry/" + id, nil
	})
}

// selectionChange: delete/unbind {Tenant, ID} with Expected = the record
// Revision; 404 for an ID mydcd does not list.
func (s *Server) selectionChange(w http.ResponseWriter, r *http.Request, ws *webSession, action string, check func(*control.ExternalRegistryView) error) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	body := struct {
		Action string
		Req    any
	}{action, req}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		cur, err := findExternalSource(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		if cur == nil || cur.Deleted {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such source"}
		}
		if err := check(cur); err != nil {
			return "", nil, 0, "", err
		}
		return action, control.RegistrySelection{Tenant: tenant, ID: id}, expectedOr(req.Expected, cur.Revision), "external-registry/" + id, nil
	})
}

// DELETE /t/{t}/external-registries/{id} {opId, expected?} →
// delete-external-registry. Running containers keep running; the reader
// drains and later pulls go without this login.
func (s *Server) handleDeleteExternalRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.selectionChange(w, r, ws, mydc.ActionDeleteExternalRegistry, func(*control.ExternalRegistryView) error { return nil })
}

// POST /t/{t}/external-registries/{id}/unbind {opId, expected?} →
// unbind-external-registry: the reader stops (drains, then its server
// closes it).
func (s *Server) handleUnbindExternalRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.selectionChange(w, r, ws, mydc.ActionUnbindExternalRegistry, func(x *control.ExternalRegistryView) error {
		if x.Reader == nil || x.Reader.Draining {
			return &httpErr{http.StatusConflict, "not-bound", "the source has no reader to stop"}
		}
		return nil
	})
}

// Bind approvals (as `mydc registry external-bind`): the bind original is
// signed once; each realm the plan uses is planned with it as Origin
// (vault-approval-plan ID "registry-bind/<request ID>"), and a protected
// Group waits for the requester's password (approve below, never stored).
// When every Group is approved the same original is sent.

func refreshBindApprovals(ctx context.Context, c mydc.Conn, o *store.Op) (bool, error) {
	j := o.RegistryBind
	origin, err := mydc.DecodeOperation(mydc.SignedOp(o.Signed))
	if err != nil {
		return false, err
	}
	next, ready, err := planApprovals(ctx, c, j.Tenant, "registry-bind/"+o.RequestID, &origin, j.Realms, false, j.Approvals)
	if err != nil {
		return false, err
	}
	j.Approvals = next
	return ready, nil
}

func holdBind(job *store.RegistryBindJob) holdFunc {
	return func(ctx context.Context, c mydc.Conn, o *store.Op, op mydc.SignedOp) (bool, error) {
		if len(job.Realms) == 0 {
			return false, nil // no secret: nothing to approve
		}
		o.Signed, o.RegistryBind = op, job
		ready, err := refreshBindApprovals(ctx, c, o)
		if err != nil || ready {
			o.Signed, o.RegistryBind = nil, nil
			return false, err
		}
		o.State, o.ErrorCode = store.OpRunning, "approval-required"
		return true, nil
	}
}

func (s *Server) sendHeldBind(ctx context.Context, c mydc.Conn, o *store.Op) error {
	ready, err := refreshBindApprovals(ctx, c, o)
	if err != nil || !ready {
		return err
	}
	res, err := c.Submit(ctx, mydc.SignedOp(o.Signed))
	o.State, o.ErrorCode = store.OpPending, ""
	settleSubmit(o, res, err, s.now())
	if o.State == store.OpFailed && o.ErrorCode == "" {
		// approvals are checked together at one time; bind again
		o.ErrorCode = "approval-rejected"
	}
	return nil
}

// POST /t/{t}/external-registries/{id}/bind {opId, node} →
// bind-external-registry with external-registry-bind-plan's Selection and
// Expected: the source's reader runs on that server (mydcd checks
// ManageRegistry and the server's Deploy right). With protected Groups the
// op waits (running, approval-required, approvals) for the approve call.
func (s *Server) handleBindExternalRegistry(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Node string `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	job := &store.RegistryBindJob{Tenant: tenant, Source: id, Node: req.Node}
	s.sharedCreateHold(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		q := control.ExternalRegistryBindQuery{ID: id, Node: req.Node}
		if !q.Valid() {
			return "", nil, 0, "", invalid("node: a server name")
		}
		plan, err := c.PlanExternalRegistryBind(ctx, tenant, q)
		var me *mydc.Error
		if errors.As(err, &me) && me.Code == mydc.CodeConflict {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "not-bindable", "only an enabled source without a reader can be bound; stop the current reader first"}
		}
		if err != nil {
			return "", nil, 0, "", err
		}
		for realm := range plan.Uses {
			job.Realms = append(job.Realms, realm)
		}
		slices.Sort(job.Realms)
		return mydc.ActionBindExternalRegistry, plan.Selection, plan.Expected, "external-registry/" + id, nil
	}, holdBind(job))
}

// POST /t/{t}/external-registries/{id}/bind/{op}/approve {realm?, group,
// password} → the Group's password to its approver for the bind started
// with opId op; when none is still required the bind is sent → {op}.
func (s *Server) handleBindApprove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, id := r.PathValue("t"), r.PathValue("id")
	s.approveHeld(w, r, ws, "bind", func(o *store.Op) ([]store.DeployApproval, bool) {
		if j := o.RegistryBind; j == nil || j.Tenant != tenant || j.Source != id {
			return nil, false
		}
		return o.RegistryBind.Approvals, true
	}, s.sendHeldBind)
}
