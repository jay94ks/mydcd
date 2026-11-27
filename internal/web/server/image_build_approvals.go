// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Build-secret approvals (sfcd f4e1a7e, as `sfcli registry build-job
// start`): when a build context mounts a Secret whose Group needs the
// requester's approval, the begin-image-build original is signed once and
// kept unsent in web bbolt; each realm of the context's secrets is planned
// with it as Origin (vault-approval-plan ID "compose/<request ID>"), and a
// Group without an approval waits for the requester's password, which goes
// over SecretInput (mode approve) to the plan's approver node and is never
// stored. When every Group is approved the same original is sent.

// buildRealms are the realms a context's secrets read from.
func buildRealms(ctx context.Context, c sfc.Conn, tenant, id string) ([]string, error) {
	x, err := realContext(ctx, c, tenant, id)
	if err != nil || x == nil {
		return nil, err
	}
	var out []string
	for _, m := range x.Spec.Secrets {
		if !slices.Contains(out, m.Realm) {
			out = append(out, m.Realm)
		}
	}
	slices.Sort(out)
	return out, nil
}

// refreshBuildApprovals plans the job's Groups again for its original.
func refreshBuildApprovals(ctx context.Context, c sfc.Conn, o *store.Op) (bool, error) {
	j := o.BuildApproval
	origin, err := sfc.DecodeOperation(sfc.SignedOp(o.Signed))
	if err != nil {
		return false, err
	}
	realms, err := buildRealms(ctx, c, j.Tenant, j.Context)
	if err != nil {
		return false, err
	}
	next, ready, err := planApprovals(ctx, c, j.Tenant, "compose/"+o.RequestID, &origin, realms, false, j.Approvals)
	if err != nil {
		return false, err
	}
	j.Approvals = next
	return ready, nil
}

// holdBuild keeps a begin-image-build original unsent while a Group of the
// context's secrets still needs the requester's approval.
func holdBuild(tenant, buildCtx, job string) holdFunc {
	return func(ctx context.Context, c sfc.Conn, o *store.Op, op sfc.SignedOp) (bool, error) {
		o.Signed = op
		o.BuildApproval = &store.BuildApprovalJob{Tenant: tenant, Context: buildCtx, Job: job}
		ready, err := refreshBuildApprovals(ctx, c, o)
		if err != nil || ready {
			o.Signed, o.BuildApproval = nil, nil
			return false, err
		}
		o.State, o.ErrorCode = store.OpRunning, "approval-required"
		return true, nil
	}
}

// sendHeldBuild sends the kept original once every Group is approved.
func (s *Server) sendHeldBuild(ctx context.Context, c sfc.Conn, o *store.Op) error {
	ready, err := refreshBuildApprovals(ctx, c, o)
	if err != nil || !ready {
		return err
	}
	res, err := c.Submit(ctx, sfc.SignedOp(o.Signed))
	o.State, o.ErrorCode = store.OpPending, ""
	settleSubmit(o, res, err, s.now())
	if o.State == store.OpFailed && o.ErrorCode == "" {
		// sfcd checks the approvals together at one ApprovedAt; a late
		// approval can leave an earlier one past MaxApprovalAge. The result
		// is final for this original: start the build again.
		o.ErrorCode = "approval-rejected"
	}
	return nil
}

// POST /t/{t}/build-approvals/{op}/approve {realm?, group, password} → the
// Group's password to its approver for the build started with opId op;
// when none is still required the build's original is sent → {op}.
func (s *Server) handleBuildApprove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.PathValue("t")
	s.approveHeld(w, r, ws, "build", func(o *store.Op) ([]store.DeployApproval, bool) {
		if o.BuildApproval == nil || o.BuildApproval.Tenant != tenant {
			return nil, false
		}
		return o.BuildApproval.Approvals, true
	}, s.sendHeldBuild)
}

// heldApprovals: the Group rows of an op whose signed original is kept
// unsent until they are approved.
func heldApprovals(o *store.Op) []store.DeployApproval {
	switch {
	case o.BuildApproval != nil:
		return o.BuildApproval.Approvals
	case o.RegistryBind != nil:
		return o.RegistryBind.Approvals
	}
	return nil
}

// approveHeld gives one Group's password (never stored) to its approver
// for the held op {op} of this kind; when none is still required, send
// re-plans and sends the kept original → {op}.
func (s *Server) approveHeld(w http.ResponseWriter, r *http.Request, ws *webSession, kind string, rows func(*store.Op) ([]store.DeployApproval, bool),
	send func(ctx context.Context, c sfc.Conn, o *store.Op) error) {
	req, pw, ok := readApprove(w, r)
	if !ok {
		return
	}
	defer clear(pw)
	o, err := s.opt.Store.GetOp(ws.user.ID, r.PathValue("op"))
	var list []store.DeployApproval
	found := err == nil
	if found {
		list, found = rows(o)
	}
	if errors.Is(err, store.ErrNotFound) || err == nil && !found {
		writeError(w, http.StatusNotFound, "not-found", "no such "+kind+" waiting for approval")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	i := slices.IndexFunc(list, func(a store.DeployApproval) bool { return a.Realm == req.Realm && a.Group == req.Group })
	if o.ErrorCode != "approval-required" || i < 0 {
		writeError(w, http.StatusConflict, "not-required", "this "+kind+" does not wait for that Group")
		return
	}
	a := &list[i]
	if a.State == "approved" {
		writeError(w, http.StatusConflict, "already-approved", "this Group is already approved")
		return
	}
	origin, err := sfc.DecodeOperation(sfc.SignedOp(o.Signed))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "stored approval")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var state string
	err = ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		err := approveGroup(ctx, c, r.PathValue("t"), a, &origin, pw)
		state = a.State
		o.UpdatedAt = s.now()
		if e := s.saveOp(o); e != nil {
			return e
		}
		if a.State != "approved" {
			return err
		}
		err = send(ctx, c, o)
		if e := s.saveOp(o); e != nil {
			return e
		}
		return err
	})
	// the answer is about this Group, even after a re-plan
	writeApproveOutcome(w, ws, s, &store.DeployApproval{State: state}, o, err)
}
