// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// CD apps beyond Git: the services the web adds apart from Git (REQ-15
// mock), approve/reject of a candidate with a reason, and the per-app
// approver grant. mydcd merges the documents, checks name conflicts and
// judges permissions.

// GET /t/{t}/apps/{app}/cd/local → {tenant, app, revision, document,
// services, gitServices, conflicts?}: the web-added part (an app.yaml
// fragment with only services:) and the Git services it may not change.
func (s *Server) handleCDLocal(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (mydc.AppCDLocal, error) {
		l, err := c.AppDeliveryLocal(ctx, r.PathValue("t"), r.PathValue("app"))
		if l.Services == nil {
			l.Services = []string{}
		}
		if l.GitServices == nil {
			l.GitServices = []string{}
		}
		return l, err
	})
}

// PUT /t/{t}/apps/{app}/cd/local {opId, document, expected?}: the
// web-added services, as `mydc cd put-local` / `clear-local` send them.
// A document goes up as an app upload (begin-app-upload → put-app-part × n)
// and put-app-local-services names it, one job under opId (sending the same
// opId again continues it); document "" sends clear-app-local-services.
// Nothing runs now: the next sync or approval runs Git's document with
// these services. Expected defaults to the CD revision and then pins the
// execution the change was made against (as the CLI without
// --if-revision); a given expected is used as it is.
func (s *Server) handlePutCDLocal(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Document string `json:"document"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	change := func(cur mydc.AppCDLocal) mydc.AppLocalChange {
		q := mydc.AppLocalChange{Tenant: tenant, App: app, Registration: cur.Registration, Revision: cur.LocalRevision}
		if req.Expected == 0 {
			t := cur.Target
			q.Target = &t
		}
		return q
	}
	if req.Document == "" {
		s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			cur, err := c.AppDeliveryLocal(ctx, tenant, app)
			if err != nil {
				return "", nil, 0, "", err
			}
			if len(cur.Services) == 0 {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "there are no web-added services"}
			}
			return mydc.ActionClearAppLocalServices, change(cur), expectedOr(req.Expected, cur.Revision), "app/" + app, nil
		})
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	doc := []byte(req.Document)
	if len(doc) > deployment.ArtifactMaxBytes {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "document: at most 1 MiB")
		return
	}
	// The names are signed metadata; mydcd checks them against the exact
	// uploaded document and judges the document itself.
	var frag struct {
		Services map[string]yaml.Node `yaml:"services"`
	}
	names := []string{}
	if yaml.Unmarshal(doc, &frag) == nil {
		for name := range frag.Services {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if len(names) == 0 || len(names) > 128 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "document: an app.yaml fragment with 1 to 128 services")
		return
	}
	sum := sha256.Sum256(doc)
	dsum := sha256.Sum256(append([]byte(fmt.Sprintf("cd-local\x00%s\x00%s\x00%d\x00", tenant, app, req.Expected)), sum[:]...))
	dg := hex.EncodeToString(dsum[:])
	parent, err := s.opt.Store.GetOp(ws.user.ID, req.OpID)
	switch {
	case err == nil:
		if parent.Digest != dg || parent.Deploy == nil || parent.Deploy.Local == nil {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
	case errors.Is(err, store.ErrNotFound):
		parent = nil
	default:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		if parent == nil {
			row, _, err := cdRow(ctx, c, tenant, app)
			if err != nil {
				return err
			}
			cur, err := c.AppDeliveryLocal(ctx, tenant, app)
			if err != nil {
				return err
			}
			if cur.Target == ([32]byte{}) {
				return &httpErr{http.StatusConflict, "not-deployed", "the app has no deployment to add services to yet"}
			}
			q := change(cur)
			q.Upload, q.Digest, q.Services = "local-"+req.OpID, sum, names
			raw, err := json.Marshal(q)
			if err != nil {
				return err
			}
			now := s.now()
			parent = &store.Op{ID: req.OpID, User: ws.user.ID, Username: ws.user.Username, Action: mydc.ActionPutAppLocalServices, Tenant: tenant, Target: "app/" + app,
				Digest: dg, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now,
				Deploy: &store.DeployJob{Tenant: tenant, App: app, Deployment: row.Deployment, UploadID: q.Upload, Document: doc, Digest: hex.EncodeToString(sum[:]),
					Parts: (len(doc) + mydc.AppPartBytes - 1) / mydc.AppPartBytes, Local: &store.LocalJob{Change: raw, Expected: expectedOr(req.Expected, cur.Revision)}}}
			existing, err := s.opt.Store.CreateOp(parent)
			if err != nil {
				return err
			}
			if existing != nil {
				parent = existing
			}
		}
		return s.runDeploy(ctx, c, ws, parent, false)
	})
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, opStatus(parent), map[string]any{"op": viewOp(parent)})
}

// POST /t/{t}/apps/{app}/cd/candidate/approve {opId, candidate, reason?,
// expected?} → cd-approve; POST …/cd/candidate/reject {opId, candidate,
// reason?, expected?} → cd-reject. candidate is cd.candidateDigest as shown
// (409 candidate-changed when the row moved on). mydcd runs an approved
// candidate itself; a rejected commit stays out until a new commit or
// replan. The reason (≤ 512) is signed into the op, as X-MyDC-Reason would
// be (one or the other). A given expected must be the CD revision exactly
// (Strict); without it mydcd takes any revision not newer than the row's.
func (s *Server) handleCDDecision(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID      string `json:"opId"`
			Candidate string `json:"candidate"`
			Reason    string `json:"reason,omitempty"`
			Expected  uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		if req.Reason != "" {
			if r.Header.Get("X-MyDC-Reason") != "" {
				writeError(w, http.StatusBadRequest, "bad-request", "reason: in the body or X-MyDC-Reason, not both")
				return
			}
			r.Header.Set("X-MyDC-Reason", url.PathEscape(req.Reason))
		}
		tenant, app := r.PathValue("t"), r.PathValue("app")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			if len(req.Candidate) != 64 {
				return "", nil, 0, "", invalid("candidate: cd.candidateDigest as shown")
			}
			_, cd, err := cdRow(ctx, c, tenant, app)
			if err != nil {
				return "", nil, 0, "", err
			}
			if cd.Candidate == "" || cd.CandidateDigest == ([32]byte{}) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "no-candidate", "there is no source candidate to decide on"}
			}
			if req.Candidate != hex.EncodeToString(cd.CandidateDigest[:]) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "candidate-changed", "the source candidate changed; read the app again"}
			}
			return action, mydc.CDDecision{Strict: req.Expected != 0, Tenant: tenant, App: app, Candidate: cd.CandidateDigest, Target: cd.Target},
				expectedOr(req.Expected, cd.Revision), "app/" + app, nil
		})
	}
}

// cdApproverNames maps the CD record's approver IDs to usernames (tenant
// members; an ID that is not a member stays as it is).
func cdApproverNames(ctx context.Context, c mydc.Conn, ws *webSession, tenant string, cd *mydc.AppCD) []string {
	names := ownerNames(ctx, c, ws, tenant)
	out := []string{}
	for _, id := range cd.Approvers {
		if n, ok := names[id]; ok {
			id = n
		}
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// GET /t/{t}/apps/{app}/cd/approvers → {app, approvers: [username]}: who
// may approve or reject this app's candidates (and nothing else), from the
// CD record.
func (s *Server) handleCDApprovers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, app := r.PathValue("t"), r.PathValue("app")
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		_, cd, err := cdRow(ctx, c, tenant, app)
		if err != nil {
			return nil, err
		}
		return map[string]any{"app": app, "approvers": cdApproverNames(ctx, c, ws, tenant, cd)}, nil
	})
}

// POST /t/{t}/apps/{app}/cd/approvers {opId, user | userId, expected?} →
// grant-cd-approver; DELETE …/cd/approvers {opId, user | userId, expected?}
// → revoke-cd-approver. user is a tenant member's username (for revoke also
// an approver ID shown as is); userId is the user ID mydcd takes (the
// automation account, which need not be a member). Expected defaults to the
// CD revision.
func (s *Server) handleCDApprover(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			User     string `json:"user,omitempty"`
			UserID   string `json:"userId,omitempty"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, app := r.PathValue("t"), r.PathValue("app")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			if (req.User == "") == (req.UserID == "") || len(req.User) > 128 || len(req.UserID) > 128 {
				return "", nil, 0, "", invalid("user: a username, or userId: a user ID (one of them)")
			}
			_, cd, err := cdRow(ctx, c, tenant, app)
			if err != nil {
				return "", nil, 0, "", err
			}
			id := req.UserID
			for uid, n := range ownerNames(ctx, c, ws, tenant) {
				if req.User == "" {
					break
				}
				if n == req.User {
					id = uid
				}
			}
			if id == "" && action == mydc.ActionDropCDApprover && slices.Contains(cd.Approvers, req.User) {
				id = req.User
			}
			if id == "" {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such member of the work space"}
			}
			return action, mydc.CDApproverGrant{Tenant: tenant, App: app, User: id}, expectedOr(req.Expected, cd.Revision), "app/" + app, nil
		})
	}
}
