// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// opRequest is the generic management change from the browser. Screen
// endpoints build the same request and share submitOp.
type opRequest struct {
	OpID         string          `json:"opId"`
	Action       string          `json:"action"`
	Principal    string          `json:"principal"`
	Expected     uint64          `json:"expected"`
	Payload      json.RawMessage `json:"payload,omitempty"`
	RootRevision uint64          `json:"rootRevision"`
	Tenant       string          `json:"tenant,omitempty"` // display/filter only
	Target       string          `json:"target,omitempty"` // display only
}

func (o *opRequest) digest() string {
	raw, _ := json.Marshal(struct {
		A, P string
		E, R uint64
		L    json.RawMessage
	}{o.Action, o.Principal, o.Expected, o.RootRevision, o.Payload})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// opView is the browser view of a stored op.
type opView struct {
	ID          string `json:"id"`
	RequestID   string `json:"requestId"`
	Action      string `json:"action"`
	Tenant      string `json:"tenant,omitempty"`
	Target      string `json:"target,omitempty"`
	State       string `json:"state"`
	ErrorCode   string `json:"errorCode,omitempty"`
	ResultFound bool   `json:"resultFound"`
	ResultCode  *int   `json:"resultCode,omitempty"`
	Index       uint64 `json:"index,omitempty"`
	Revision    uint64 `json:"revision,omitempty"`
	SubmittedAt string `json:"submittedAt"`
	UpdatedAt   string `json:"updatedAt"`
	Parent      string `json:"parent,omitempty"`
	// deploy jobs: next step and total steps (begin + parts + begin-app)
	Step  int `json:"step,omitempty"`
	Steps int `json:"steps,omitempty"`
	// deploy jobs: protected Groups that need the requester's password
	Approvals []approvalView `json:"approvals,omitempty"`
	// volume move jobs
	Move *moveView `json:"move,omitempty"`
	// REQ-9 display-only reason sent with the op
	Reason *store.OpReason `json:"reason,omitempty"`
}

type moveView struct {
	Volume string `json:"volume"`
	ID     string `json:"id"`
	From   string `json:"from"`
	To     string `json:"to"`
	CD     bool   `json:"cd,omitempty"`
}

type approvalView struct {
	Realm    string   `json:"realm"`
	Group    string   `json:"group"`
	Services []string `json:"services"`
	State    string   `json:"state"`
}

func viewOp(o *store.Op) opView {
	v := opView{ID: o.ID, RequestID: o.RequestID, Action: o.Action, Tenant: o.Tenant, Target: o.Target, State: o.State, ErrorCode: o.ErrorCode,
		SubmittedAt: o.SubmittedAt.UTC().Format(time.RFC3339), UpdatedAt: o.UpdatedAt.UTC().Format(time.RFC3339)}
	v.Parent, v.Reason = o.Parent, o.Reason
	if o.Deploy != nil {
		v.Step, v.Steps = o.Deploy.Step, o.Deploy.Parts+2
		for _, a := range o.Deploy.Approvals {
			v.Approvals = append(v.Approvals, approvalView{a.Realm, a.Group, append([]string{}, a.Services...), a.State})
		}
		if m := o.Deploy.Move; m != nil {
			v.Move = &moveView{m.Volume, m.ID, m.From, m.To, m.CD}
		}
	}
	if o.BuildApproval != nil || o.RegistryBind != nil {
		for _, a := range heldApprovals(o) {
			v.Approvals = append(v.Approvals, approvalView{a.Realm, a.Group, append([]string{}, a.Services...), a.State})
		}
	}
	if o.State == store.OpPending {
		// Stored before sending; delivery is not known. The UI offers
		// result/resume only, never a new submission.
		v.State = store.OpUnknown
	}
	if o.Result != nil {
		v.ResultFound = o.Result.Found
		if o.Result.Found {
			c := o.Result.Code
			v.ResultCode = &c
			v.Index, v.Revision = o.Result.Index, o.Result.Revision
		}
	}
	return v
}

func opStatus(o *store.Op) int {
	if o.State == store.OpUnknown || o.State == store.OpPending || o.State == store.OpRunning {
		return http.StatusAccepted
	}
	return http.StatusOK
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req opRequest
	if !readJSON(w, r, &req) {
		return
	}
	o, status, err := s.submitOp(r, ws, &req)
	s.writeOpOutcome(w, ws, o, status, err)
}

func (s *Server) writeOpOutcome(w http.ResponseWriter, ws *webSession, o *store.Op, status int, err error) {
	if err != nil {
		var he *httpErr
		if errors.As(err, &he) {
			writeError(w, he.status, he.code, he.msg)
			return
		}
		var ce *compileErr
		if errors.As(err, &ce) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]apiError{"error": {Code: "compile-error", Message: "the source does not compile", Diagnostics: ce.items}})
			return
		}
		if writeLimitOver(w, err) {
			return
		}
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, status, map[string]any{"op": viewOp(o)})
}

type httpErr struct {
	status    int
	code, msg string
}

func (e *httpErr) Error() string { return e.code + ": " + e.msg }

// submitOp signs, stores, then sends one management change. The signed
// original is durable in bbolt before it is sent, so a lost reply leaves an
// "unknown" op that is settled with result/resume of the same original and
// never by a new ID.
func (s *Server) submitOp(r *http.Request, ws *webSession, req *opRequest) (*store.Op, int, error) {
	if !uuidRE.MatchString(req.OpID) {
		return nil, 0, &httpErr{http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4"}
	}
	if req.Action == "" {
		return nil, 0, &httpErr{http.StatusBadRequest, "bad-request", "action is required"}
	}
	reason, err := opReasonOf(r)
	if err != nil {
		return nil, 0, &httpErr{http.StatusBadRequest, "bad-request", err.Error()}
	}
	dg := req.digest()
	if reason != nil {
		// keeps the digest of ops without a reason as it was
		raw, _ := json.Marshal([]any{dg, reason})
		h := sha256.Sum256(raw)
		dg = hex.EncodeToString(h[:])
	}
	if old, err := s.opt.Store.GetOp(ws.user.ID, req.OpID); err == nil {
		if old.Digest != dg {
			return nil, 0, &httpErr{http.StatusConflict, "op-conflict", "this opId was already used for a different change"}
		}
		return old, opStatus(old), nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, 0, err
	}

	ctx, cancel := s.callCtx(r)
	defer cancel()
	var o *store.Op
	status := http.StatusOK
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		root := req.RootRevision
		if root == 0 {
			// The browser does not track the root revision; use the current
			// one, as the CLI does right before submit. Expected still
			// guards the target resource.
			who, err := c.Whoami(ctx)
			if err != nil {
				return err
			}
			root = who.RootFor(req.Action)
		}
		o = &store.Op{ID: req.OpID, User: ws.user.ID, Username: ws.user.Username, Action: req.Action, Tenant: req.Tenant, Target: req.Target, Digest: dg, Reason: reason}
		ch := mydc.Change{Schema: 1, Action: req.Action, Principal: req.Principal, Expected: req.Expected, Payload: req.Payload}
		existing, err := s.sendStored(ctx, c, o, ch, root)
		if err != nil {
			return err
		}
		if existing != nil { // a concurrent request with the same opId won
			if existing.Digest != dg {
				return &httpErr{http.StatusConflict, "op-conflict", "this opId was already used for a different change"}
			}
			o = existing
		}
		status = opStatus(o)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	s.log.Info("submit", "user", ws.user.Username, "action", o.Action, "op", o.ID, "state", o.State)
	return o, status, nil
}

// sendStored signs change, stores o with the signed original, and only then
// submits it. When a row with o's ID already exists it is returned and
// nothing is sent. Errors before the store mean nothing was sent.
func (s *Server) sendStored(ctx context.Context, c mydc.Conn, o *store.Op, ch mydc.Change, root uint64) (*store.Op, error) {
	var op mydc.SignedOp
	var err error
	if o.Reason != nil {
		op, err = c.PrepareReason(ctx, ch, root, mydc.OperationReason{Reason: o.Reason.Reason, Incident: o.Reason.Incident})
	} else {
		op, err = c.Prepare(ctx, ch, root)
	}
	if err != nil {
		return nil, err
	}
	return s.sendPrepared(ctx, c, o, op)
}

// prepareHold signs ch and asks hold whether to keep it unsent; a held
// original is stored as o (hold set its state), otherwise it is sent.
func (s *Server) prepareHold(ctx context.Context, c mydc.Conn, o *store.Op, ch mydc.Change, root uint64, hold holdFunc) (*store.Op, error) {
	var op mydc.SignedOp
	var err error
	if o.Reason != nil {
		op, err = c.PrepareReason(ctx, ch, root, mydc.OperationReason{Reason: o.Reason.Reason, Incident: o.Reason.Incident})
	} else {
		op, err = c.Prepare(ctx, ch, root)
	}
	if err != nil {
		return nil, err
	}
	reqID, err := mydc.OperationID(op)
	if err != nil {
		return nil, err
	}
	o.RequestID = reqID
	held, err := hold(ctx, c, o, op)
	if err != nil {
		return nil, err
	}
	if !held {
		return s.sendPrepared(ctx, c, o, op)
	}
	now := s.now()
	o.Signed, o.SubmittedAt, o.UpdatedAt = op, now, now
	return s.opt.Store.CreateOp(o)
}

// sendPrepared stores an already signed original as o, then sends it.
func (s *Server) sendPrepared(ctx context.Context, c mydc.Conn, o *store.Op, op mydc.SignedOp) (*store.Op, error) {
	reqID, err := mydc.OperationID(op)
	if err != nil {
		return nil, err
	}
	now := s.now()
	o.RequestID, o.Signed, o.State, o.SubmittedAt, o.UpdatedAt = reqID, op, store.OpPending, now, now
	existing, err := s.opt.Store.CreateOp(o)
	if err != nil || existing != nil {
		return existing, err
	}
	res, sendErr := c.Submit(ctx, op)
	settleSubmit(o, res, sendErr, s.now())
	if err := s.saveOp(o); err != nil {
		s.log.Error("update op after submit", "op", o.ID, "err", err)
	}
	return nil, nil
}

// settleSubmit applies the outcome of the first submit to an op.
func settleSubmit(o *store.Op, res mydc.Result, err error, now time.Time) {
	o.UpdatedAt = now
	if err == nil {
		setResult(o, res)
		return
	}
	var me *mydc.Error
	if !errors.As(err, &me) {
		o.State, o.ErrorCode = store.OpUnknown, "disconnected"
		return
	}
	switch me.Code {
	case mydc.CodeDenied, mydc.CodeInvalid, mydc.CodeUnsupported, mydc.CodeExpired, mydc.CodeLedgerFull, mydc.CodeNotSessionIssuer, mydc.CodeTransport, mydc.CodeNotLoggedIn, mydc.CodeSessionExpired:
		// mydcd answered and refused before execution, or the exchange
		// failed locally before anything was sent.
		o.State, o.ErrorCode = store.OpRejected, string(me.Code)
	default:
		// unknown, not-leader, unavailable, closed: delivery or execution is
		// not disproven. Keep the original for result/resume.
		o.State, o.ErrorCode = store.OpUnknown, string(me.Code)
	}
}

func setResult(o *store.Op, res mydc.Result) {
	o.Result = &store.OpResult{Found: true, Code: int(res.Code), Index: res.Index, Revision: res.Revision, Generation: res.Generation}
	// a count limit gets its own code; others have none
	o.ErrorCode = mydc.LimitCode(res.Code)
	if res.Code == mydc.ResultApplied {
		o.State = store.OpApplied
	} else {
		o.State = store.OpFailed
	}
}

func (s *Server) handleListOps(w http.ResponseWriter, r *http.Request, ws *webSession) {
	state := r.URL.Query().Get("state")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var ops []*store.Op
	var err error
	if state == store.OpUnknown {
		// pending rows are shown as unknown
		ops, err = s.opt.Store.ListOps(ws.user.ID, store.OpUnknown, limit)
		if err == nil {
			var p []*store.Op
			p, err = s.opt.Store.ListOps(ws.user.ID, store.OpPending, limit)
			ops = append(ops, p...)
		}
	} else {
		ops, err = s.opt.Store.ListOps(ws.user.ID, state, limit)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	children := r.URL.Query().Get("children") == "1"
	views := make([]opView, 0, len(ops))
	for _, o := range ops {
		if o.Parent != "" && !children {
			continue
		}
		views = append(views, viewOp(o))
	}
	writeJSON(w, http.StatusOK, s.page(views, "", 0))
}

func (s *Server) loadOp(w http.ResponseWriter, r *http.Request, ws *webSession) *store.Op {
	o, err := s.opt.Store.GetOp(ws.user.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such operation for this user")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil
	}
	return o
}

func (s *Server) handleGetOp(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if o := s.loadOp(w, r, ws); o != nil {
		writeJSON(w, http.StatusOK, map[string]any{"op": viewOp(o)})
	}
}

// handleOpResult asks mydcd for the original result of the stored op.
// "Not found" is not proof that it did not run, so the op stays unknown.
func (s *Server) handleOpResult(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.settleStored(w, r, ws, false)
}

// handleOpResume explicitly resumes the same original op with the current
// session's authority.
func (s *Server) handleOpResume(w http.ResponseWriter, r *http.Request, ws *webSession) {
	s.settleStored(w, r, ws, true)
}

func (s *Server) settleStored(w http.ResponseWriter, r *http.Request, ws *webSession, resume bool) {
	o := s.loadOp(w, r, ws)
	if o == nil {
		return
	}
	if o.Action == "exec" {
		if resume {
			writeError(w, http.StatusConflict, "exec", "an exec is never resumed; reconnect with the same opId or read its status")
			return
		}
		s.execStatus(w, r, ws, o)
		return
	}
	if o.Deploy != nil {
		writeError(w, http.StatusConflict, "job", "a deploy job has no single original; settle its step ops and send the deploy again with the same opId")
		return
	}
	if resume && (o.BuildApproval != nil || o.RegistryBind != nil) && o.ErrorCode == "approval-required" {
		writeError(w, http.StatusConflict, "approval-required", "the change waits for Group approvals; it is sent when they are given")
		return
	}
	if o.VaultWrite != nil {
		writeError(w, http.StatusConflict, "job", "a Vault write job has no single original; settle its step ops and send the write again with the same opId")
		return
	}
	if resume && store.Settled(o.State) {
		writeError(w, http.StatusConflict, "settled", "the operation already has a final result")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	op := mydc.SignedOp(o.Signed)
	var res mydc.Result
	var found bool
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if resume {
			res, found, err = c.Resume(ctx, op)
		} else {
			res, found, err = c.Result(ctx, op)
		}
		return err
	})
	if err != nil {
		// A failed lookup or a refused resume says nothing about whether the
		// original ran; the stored state is unchanged.
		s.writeBackendError(w, ws, err)
		return
	}
	o.UpdatedAt = s.now()
	if found {
		setResult(o, res)
	} else {
		o.Result = &store.OpResult{Found: false}
		if o.State == store.OpPending {
			o.State = store.OpUnknown
		}
	}
	if err := s.saveOp(o); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if o.Action == mydc.ActionDownApp && o.State == store.OpFailed {
		// The down did not apply: drop the archive row saved for it.
		if err := s.opt.Store.DeleteArchivedByOp(o.Tenant, o.ID); err != nil {
			s.log.Error("drop archive of failed down", "op", o.ID, "err", err)
		}
	}
	writeJSON(w, opStatus(o), map[string]any{"op": viewOp(o)})
}
