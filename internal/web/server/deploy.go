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

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

type deployReq struct {
	OpID       string `json:"opId"`
	YAML       string `json:"yaml"`
	Digest     string `json:"digest,omitempty"` // hex SHA-256 of yaml, as shown with the plan
	Deployment string `json:"deployment,omitempty"`
	Node       string `json:"node,omitempty"`
	Prune      bool   `json:"prune,omitempty"`
}

func (d *deployReq) digest() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("deploy\x00%s\x00%s\x00%s\x00%t\x00", d.Deployment, d.Node, d.YAML, d.Prune)))
	return hex.EncodeToString(h[:])
}

// POST /api/v1/t/{t}/apps/deploy: one app.yaml through the normal path
// (begin-app-upload → put-app-part × n → begin-app) under one web opId.
// Each step is its own original op, stored before it is sent. Sending the
// same opId again continues from the next step; a step whose outcome is
// unknown stops the job until it is settled with /ops/{id}/result.
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req deployReq
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	doc := []byte(req.YAML)
	if len(doc) == 0 || len(doc) > 4<<20 {
		writeError(w, http.StatusBadRequest, "bad-request", "yaml is required and at most 4 MiB")
		return
	}
	sum := sha256.Sum256(doc)
	if req.Digest != "" && req.Digest != hex.EncodeToString(sum[:]) {
		writeError(w, http.StatusConflict, "digest-mismatch", "yaml changed since the reviewed plan")
		return
	}
	dg := req.digest()

	parent, err := s.opt.Store.GetOp(ws.user.ID, req.OpID)
	switch {
	case err == nil:
		if parent.Digest != dg || parent.Deploy == nil || parent.Deploy.Tenant != tenant {
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
			plan, err := c.AppPlan(ctx, mydc.AppPlanRequest{Tenant: tenant, Document: doc, Deployment: req.Deployment, Node: req.Node})
			if err != nil {
				return err
			}
			if plan.App == "" {
				return &httpErr{http.StatusUnprocessableEntity, "invalid", "the plan names no app"}
			}
			now := s.now()
			// The upload is mydcd's planned artifact (the blueprint the
			// plan stream returned), as the CLI uploads it.
			art := plan.Data
			if len(art) == 0 || len(art) > 4<<20 || plan.Length != len(art) || sha256.Sum256(art) != plan.Digest {
				return &httpErr{http.StatusBadGateway, "plan-invalid", "the plan artifact does not match its digest"}
			}
			parent = &store.Op{ID: req.OpID, User: ws.user.ID, Username: ws.user.Username, Action: "deploy", Tenant: tenant, Target: plan.App,
				Digest: dg, State: store.OpRunning, SubmittedAt: now, UpdatedAt: now,
				Deploy: &store.DeployJob{Tenant: tenant, App: plan.App, Deployment: req.Deployment, Node: req.Node, UploadID: "web-" + req.OpID,
					Document: art, Digest: hex.EncodeToString(plan.Digest[:]), Parts: (len(art) + mydc.AppPartBytes - 1) / mydc.AppPartBytes}}
			existing, err := s.opt.Store.CreateOp(parent)
			if err != nil {
				return err
			}
			if existing != nil {
				parent = existing
			}
		}
		return s.runDeploy(ctx, c, ws, parent, req.Prune)
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

func stepID(parent string, step int) string { return fmt.Sprintf("%s.%d", parent, step) }

// runDeploy sends the remaining steps of a deploy job in order.
func (s *Server) runDeploy(ctx context.Context, c mydc.Conn, ws *webSession, parent *store.Op, prune bool) error {
	j := parent.Deploy
	defer func() {
		parent.UpdatedAt = s.now()
		if err := s.saveOp(parent); err != nil {
			s.log.Error("update deploy job", "op", parent.ID, "err", err)
		}
	}()
	for j.Step <= j.Parts+1 {
		id := stepID(parent.ID, j.Step)
		child, err := s.opt.Store.GetOp(ws.user.ID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if child == nil && j.Step == j.Parts+1 && j.Move == nil && j.Local == nil {
			// begin-app: prepare the original, get every protected Group
			// approved for it, then send it unchanged.
			ready, err := s.deployApprovals(ctx, c, ws, parent, prune)
			if err != nil {
				return err
			}
			if !ready {
				parent.State, parent.ErrorCode = store.OpRunning, "approval-required"
				return nil
			}
			action := mydc.ActionBeginApp
			if j.Standalone != nil {
				action = mydc.ActionStandaloneUp
			}
			child = &store.Op{ID: id, User: ws.user.ID, Username: ws.user.Username, Action: action, Tenant: j.Tenant, Target: j.App, Parent: parent.ID, Digest: parent.Digest}
			if existing, err := s.sendPrepared(ctx, c, child, mydc.SignedOp(j.Origin)); err != nil {
				return err
			} else if existing != nil {
				child = existing
			}
		}
		if child == nil {
			ch, err := s.deployChange(ctx, c, ws, j, prune)
			if err != nil {
				return err
			}
			who, err := c.Whoami(ctx)
			if err != nil {
				return err
			}
			child = &store.Op{ID: id, User: ws.user.ID, Username: ws.user.Username, Action: ch.Action, Tenant: j.Tenant, Target: j.App, Parent: parent.ID, Digest: parent.Digest}
			if existing, err := s.sendStored(ctx, c, child, ch, who.RootFor(ch.Action)); err != nil {
				return err
			} else if existing != nil {
				child = existing
			}
		}
		switch child.State {
		case store.OpApplied:
			if j.Move != nil && j.Step == j.Parts+1 && len(j.Origin) == 0 {
				j.Origin = child.Signed // the move's original, for its approvals
			}
			j.Step++
			continue
		case store.OpPending, store.OpUnknown:
			parent.State, parent.ErrorCode = store.OpUnknown, "step-unknown"
			return nil
		default: // failed, rejected
			parent.State, parent.ErrorCode = child.State, child.ErrorCode
			if parent.ErrorCode == "" && child.Result != nil {
				parent.ErrorCode = fmt.Sprintf("result-%d", child.Result.Code)
			}
			parent.Result = child.Result
			return nil
		}
	}
	if j.Move != nil && !j.Move.CD {
		// A move is accepted first; its app operation then waits for the
		// protected Group approvals of the begin-volume-move original.
		ready, err := s.deployApprovals(ctx, c, ws, parent, false)
		if err != nil {
			return err
		}
		if !ready {
			parent.State, parent.ErrorCode = store.OpRunning, "approval-required"
			return nil
		}
	}
	parent.State, parent.ErrorCode = store.OpApplied, ""
	return nil
}

// deployChange builds the change of the job's current step.
func (s *Server) deployChange(ctx context.Context, c mydc.Conn, ws *webSession, j *store.DeployJob, prune bool) (mydc.Change, error) {
	var action string
	var expected uint64
	var payload any
	switch {
	case j.Step == 0:
		var dg [32]byte
		raw, _ := hex.DecodeString(j.Digest)
		copy(dg[:], raw)
		action, expected = mydc.ActionBeginAppUpload, 0
		payload = control.AppUploadBegin{Tenant: j.Tenant, App: j.App, Deployment: j.Deployment, ID: j.UploadID, Length: len(j.Document), Digest: dg}
	case j.Step <= j.Parts:
		i := j.Step - 1
		end := min(len(j.Document), (i+1)*mydc.AppPartBytes)
		rev, err := s.uploadRevision(ctx, c, j)
		if err != nil {
			return mydc.Change{}, err
		}
		action, expected = mydc.ActionPutAppPart, rev
		payload = control.AppUploadPart{Tenant: j.Tenant, ID: j.UploadID, Index: i, Data: j.Document[i*mydc.AppPartBytes : end]}
	case j.Move != nil:
		raw := append([]byte(nil), j.Move.Begin...)
		return mydc.Change{Schema: 1, Action: mydc.ActionBeginVolumeMove, Principal: ws.user.ID, Expected: j.Move.Expected, Payload: raw}, nil
	case j.Local != nil:
		raw := append([]byte(nil), j.Local.Change...)
		return mydc.Change{Schema: 1, Action: mydc.ActionPutAppLocalServices, Principal: ws.user.ID, Expected: j.Local.Expected, Payload: raw}, nil
	case j.Standalone != nil:
		raw := append([]byte(nil), j.Standalone.Begin...)
		return mydc.Change{Schema: 1, Action: mydc.ActionStandaloneUp, Principal: ws.user.ID, Expected: j.Standalone.Expected, Payload: raw}, nil
	default:
		rev, err := s.appRevision(ctx, c, j.Tenant, j.App)
		if err != nil {
			return mydc.Change{}, err
		}
		action, expected = mydc.ActionBeginApp, rev
		payload = control.AppBegin{Tenant: j.Tenant, App: j.App, Deployment: j.Deployment, Upload: j.UploadID, Operation: j.UploadID, Prune: prune, DefaultNode: j.Node}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return mydc.Change{}, err
	}
	return mydc.Change{Schema: 1, Action: action, Principal: ws.user.ID, Expected: expected, Payload: raw}, nil
}

// uploadRevision finds the current revision of the job's upload.
func (s *Server) uploadRevision(ctx context.Context, c mydc.Conn, j *store.DeployJob) (uint64, error) {
	after := ""
	for {
		p, err := c.AppUploads(ctx, j.Tenant, after)
		if err != nil {
			return 0, err
		}
		for _, u := range p.Items {
			if u.ID == j.UploadID {
				return u.Revision, nil
			}
		}
		if p.Next == "" {
			return 0, &httpErr{http.StatusConflict, "upload-missing", "the upload of this deploy is gone (aborted or expired); start a new deploy"}
		}
		after = p.Next
	}
}

// appRevision is the current AppView.Revision (0 for a new app).
func (s *Server) appRevision(ctx context.Context, c mydc.Conn, tenant, app string) (uint64, error) {
	after := ""
	for {
		p, err := c.Apps(ctx, tenant, after)
		if err != nil {
			return 0, err
		}
		for _, a := range p.Items {
			if a.App == app {
				if a.Retiring {
					return 0, nil
				}
				return a.Revision, nil
			}
		}
		if p.Next == "" {
			return 0, nil
		}
		after = p.Next
	}
}
