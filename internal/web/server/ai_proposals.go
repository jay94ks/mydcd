// SPDX-License-Identifier: Apache-2.0

package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/web/store"
)

// Coordinator proposals: a change tool call becomes a card. Approving it
// sends the tool's screen route on the person's session with their opId,
// exactly as the screen's own button would; nothing else can send it.

var aiArgLabels = map[string]string{
	"t": "작업 공간", "app": "앱", "node": "서버", "name": "이름", "id": "ID", "service": "서비스", "instance": "인스턴스",
	"plan": "계획", "reason": "사유", "target": "대상", "leaveBlocked": "못 옮기는 작업은 남겨 둠",
}

func aiPreview(a *aiArgs) []store.AIPreviewRow {
	masked := maskArgs(a.raw)
	keys := make([]string, 0, len(masked))
	for k := range masked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []store.AIPreviewRow{}
	for _, k := range keys {
		label := aiArgLabels[k]
		if label == "" {
			label = k
		}
		out = append(out, store.AIPreviewRow{Label: label, Value: masked[k]})
	}
	return out
}

// maskPayload is the card's editable payload: the arguments with their
// types, secret-like ones hidden.
func maskPayload(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok && (secretKeyRE.MatchString(k) || secretEnvRE.MatchString(s)) {
			v = aiMasked
		}
		out[k] = v
	}
	return out
}

func aiBasisHash(tool, method, path string, body []byte) string {
	raw, _ := json.Marshal([]string{tool, method, path, string(body)})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// fillProposal sets the parts that follow from the arguments.
func fillProposal(p *store.AIProposal, d aiToolDef, a *aiArgs, input json.RawMessage) {
	body, _ := json.Marshal(a.body)
	p.Tool, p.Action, p.Tenant, p.Target = d.Name, d.Action, a.tenant, a.fill(d.Target)
	p.Title, p.Method, p.Path, p.Body = a.fill(d.Title), d.Method, a.path, body
	p.Args, _ = json.Marshal(maskPayload(a.raw))
	p.Preview, p.Impact, p.Revert, p.Irreversible = aiPreview(a), d.Impact, d.Revert, d.Irreversible
	p.ConfirmName = ""
	if d.Confirm != "" {
		p.ConfirmName, _ = a.raw[d.Confirm].(string)
	}
	p.BasisHash = aiBasisHash(d.Name, d.Method, a.path, body)
}

// newProposal stores a pending proposal; earlier proposals of the same
// turn come first (after).
func (s *Server) newProposal(ws *webSession, conv string, d aiToolDef, a *aiArgs, input json.RawMessage, earlier []string) (*store.AIProposal, error) {
	now := s.now()
	p := &store.AIProposal{ID: "p-" + randomID(10), User: ws.user.ID, Conversation: conv, Index: len(earlier) + 1, Total: len(earlier) + 1,
		CreatedAt: now, ExpiresAt: now.Add(aiProposalTTL), State: store.ProposalPending}
	if n := len(earlier); n > 0 {
		p.After = earlier[n-1]
	}
	fillProposal(p, d, a, input)
	return p, s.opt.Store.PutAIProposal(p)
}

type aiProposalView struct {
	ID           string               `json:"id"`
	Conversation string               `json:"conversation"`
	Title        string               `json:"title"`
	Index        int                  `json:"index"`
	Total        int                  `json:"total"`
	After        string               `json:"after,omitempty"`
	Tool         string               `json:"tool"`
	Action       string               `json:"action"`
	Tenant       string               `json:"tenant,omitempty"`
	Target       string               `json:"target"`
	Payload      json.RawMessage      `json:"payload"`
	Preview      []store.AIPreviewRow `json:"preview"`
	Impact       string               `json:"impact"`
	Revert       string               `json:"revert"`
	Irreversible bool                 `json:"irreversible"`
	ConfirmName  string               `json:"confirmName,omitempty"`
	Expected     uint64               `json:"expected"`
	BasisHash    string               `json:"basisHash"`
	ExpiresAt    string               `json:"expiresAt"`
	Edited       bool                 `json:"edited"`
	State        string               `json:"state"`
	DecidedBy    string               `json:"decidedBy,omitempty"`
	DecidedAt    string               `json:"decidedAt,omitempty"`
	Op           string               `json:"op,omitempty"`
	Reason       string               `json:"reason,omitempty"`
	MCP          *store.AIProposalMCP `json:"mcp,omitempty"`
}

func (s *Server) viewProposal(p *store.AIProposal) aiProposalView {
	v := aiProposalView{ID: p.ID, Conversation: p.Conversation, Title: p.Title, Index: p.Index, Total: p.Total, After: p.After,
		Tool: p.Tool, Action: p.Action, Tenant: p.Tenant, Target: p.Target, Payload: p.Args, Preview: p.Preview,
		Impact: p.Impact, Revert: p.Revert, Irreversible: p.Irreversible, ConfirmName: p.ConfirmName, Expected: p.Expected,
		BasisHash: p.BasisHash, ExpiresAt: rfc3339(p.ExpiresAt), Edited: p.Edited, State: p.State, DecidedBy: p.DecidedBy,
		Op: p.Op, Reason: p.Reason, MCP: p.MCP}
	if !p.DecidedAt.IsZero() {
		v.DecidedAt = rfc3339(p.DecidedAt)
	}
	if v.State == store.ProposalPending && !s.now().Before(p.ExpiresAt) {
		v.State = store.ProposalExpired
	}
	return v
}

func (s *Server) loadProposal(w http.ResponseWriter, r *http.Request, ws *webSession) *store.AIProposal {
	p, err := s.opt.Store.GetAIProposal(ws.user.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not-found", "no such proposal")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil
	}
	return p
}

// GET /ai/proposals/{id}
func (s *Server) handleAIProposal(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if p := s.loadProposal(w, r, ws); p != nil {
		writeJSON(w, http.StatusOK, s.viewProposal(p))
	}
}

// aiNote tells the model about a decision at its next turn.
func (s *Server) aiNote(ws *webSession, conv, note string) {
	_, err := s.opt.Store.UpdateAIConversation(ws.user.ID, conv, func(c *store.AIConversation) error {
		c.Notes = append(c.Notes, note)
		return nil
	})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.Error("ai note", "err", err)
	}
}

// pendingOr writes the error for a proposal that cannot be decided.
func (s *Server) pendingOr(w http.ResponseWriter, p *store.AIProposal) bool {
	switch v := s.viewProposal(p); v.State {
	case store.ProposalPending:
		return true
	case store.ProposalExpired:
		writeError(w, http.StatusGone, "expired", "the proposal expired; ask the coordinator to plan again")
	default:
		writeError(w, http.StatusConflict, "proposal-"+v.State, "the proposal is already "+v.State)
	}
	return false
}

// POST /ai/proposals/{id}/approve {opId, basisHash, confirmName?} → {op}.
// The tool's route runs on the person's session with opId, so the op is
// theirs and a repeat with the same opId returns the same op.
func (s *Server) handleAIApprove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID        string `json:"opId"`
		BasisHash   string `json:"basisHash"`
		ConfirmName string `json:"confirmName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	p := s.loadProposal(w, r, ws)
	if p == nil {
		return
	}
	repeat := p.State == store.ProposalApproved && p.Op == req.OpID
	if !repeat && !s.pendingOr(w, p) {
		return
	}
	if req.BasisHash != p.BasisHash {
		writeError(w, http.StatusConflict, "proposal-changed", "the proposal changed; read it again")
		return
	}
	if p.Irreversible && req.ConfirmName != p.ConfirmName {
		writeError(w, http.StatusUnprocessableEntity, "confirm-name", "type the name again to confirm")
		return
	}
	if p.After != "" && !repeat {
		prev, err := s.opt.Store.GetAIProposal(ws.user.ID, p.After)
		ready := err == nil && prev.State == store.ProposalApproved
		if ready && prev.MCP != nil {
			ready = prev.Reason == ""
		} else if ready {
			o, err := s.opt.Store.GetOp(ws.user.ID, prev.Op)
			ready = err == nil && o.State == store.OpApplied
		}
		if !ready {
			writeError(w, http.StatusConflict, "waiting", "approve the earlier step first and wait until it is applied: "+p.After)
			return
		}
	}
	if p.MCP != nil {
		s.approveMCP(w, r, ws, p, req.OpID, repeat)
		return
	}
	body := map[string]any{}
	if len(p.Body) > 0 {
		_ = json.Unmarshal(p.Body, &body)
	}
	body["opId"] = req.OpID
	raw, _ := json.Marshal(body)
	status, out := s.dispatch(r.Context(), ws, p.Method, p.Path, nil, raw)
	var res struct {
		Op    *opView   `json:"op"`
		Error *apiError `json:"error"`
	}
	_ = json.Unmarshal(out, &res)
	if status >= 400 || res.Op == nil {
		code := "error"
		if res.Error != nil {
			code = res.Error.Code
		}
		if status >= 400 && status < 500 && status != http.StatusUnauthorized && !repeat {
			// The change no longer fits (plan moved, refused input): the
			// card is done; the model plans again.
			_, _ = s.opt.Store.UpdateAIProposal(ws.user.ID, p.ID, func(p *store.AIProposal) error {
				p.State, p.Reason = store.ProposalInvalid, code
				return nil
			})
			s.aiNote(ws, p.Conversation, fmt.Sprintf("%s (%s) could not be sent: %s; plan again if still needed", p.ID, p.Title, code))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(out)
		return
	}
	if !repeat {
		now := s.now()
		_, err := s.opt.Store.UpdateAIProposal(ws.user.ID, p.ID, func(p *store.AIProposal) error {
			p.State, p.Op, p.DecidedBy, p.DecidedAt = store.ProposalApproved, req.OpID, ws.user.Username, now
			return nil
		})
		if err != nil {
			s.log.Error("ai proposal", "err", err)
		}
		s.aiAudit(ws, store.AIAudit{Kind: "proposal-approved", Role: roleCoordinator, Proposal: p.ID, Decision: "approved"})
		s.aiNote(ws, p.Conversation, fmt.Sprintf("%s (%s) approved by the person; operation %s is %s (read it with ops_get)", p.ID, p.Title, req.OpID, res.Op.State))
		s.log.Info("ai proposal approved", "user", ws.user.Username, "proposal", p.ID, "action", p.Action, "op", req.OpID)
	}
	writeJSON(w, status, map[string]any{"op": res.Op})
}

// POST /ai/proposals/{id}/reject {reason} → 204.
func (s *Server) handleAIReject(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !utf8.ValidString(req.Reason) || utf8.RuneCountInString(req.Reason) > 500 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "reason: at most 500 characters")
		return
	}
	p := s.loadProposal(w, r, ws)
	if p == nil || !s.pendingOr(w, p) {
		return
	}
	now := s.now()
	if _, err := s.opt.Store.UpdateAIProposal(ws.user.ID, p.ID, func(p *store.AIProposal) error {
		p.State, p.Reason, p.DecidedBy, p.DecidedAt = store.ProposalRejected, req.Reason, ws.user.Username, now
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.aiAudit(ws, store.AIAudit{Kind: "proposal-rejected", Role: roleCoordinator, Proposal: p.ID, Decision: "rejected"})
	note := fmt.Sprintf("%s (%s) rejected by the person", p.ID, p.Title)
	if req.Reason != "" {
		note += ": " + oneLine(req.Reason, 500)
	}
	s.aiNote(ws, p.Conversation, note)
	w.WriteHeader(http.StatusNoContent)
}

// PUT /ai/proposals/{id} {payload} → the proposal: the person's edit in the
// card. The payload is the tool's arguments, checked again with its schema;
// the target (path) cannot change. Preview and basisHash are new and
// edited becomes true.
func (s *Server) handleAIEditProposal(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Payload json.RawMessage `json:"payload"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p := s.loadProposal(w, r, ws)
	if p == nil || !s.pendingOr(w, p) {
		return
	}
	if p.MCP != nil {
		s.editMCPProposal(w, r, ws, p, req.Payload)
		return
	}
	d, ok := aiToolByName(p.Tool)
	if !ok {
		writeError(w, http.StatusConflict, "proposal-invalid", "the tool of this proposal is gone")
		return
	}
	a, err := d.check(req.Payload)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if a.path != p.Path {
		writeError(w, http.StatusUnprocessableEntity, "target-changed", "the edit cannot change the target; reject and ask for a new proposal")
		return
	}
	for k, v := range maskArgs(a.raw) {
		if v == aiMasked {
			// A masked value sent back unchanged would be stored as «가림».
			if s, _ := a.raw[k].(string); strings.Contains(s, aiMasked) {
				writeError(w, http.StatusUnprocessableEntity, "invalid", k+": enter the value itself")
				return
			}
		}
	}
	np, err := s.opt.Store.UpdateAIProposal(ws.user.ID, p.ID, func(p *store.AIProposal) error {
		fillProposal(p, d, a, req.Payload)
		p.Edited = true
		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var parts []string
	for _, row := range np.Preview {
		parts = append(parts, row.Label+"="+row.Value)
	}
	s.aiNote(ws, p.Conversation, fmt.Sprintf("%s edited by the person in the card: %s", p.ID, strings.Join(parts, ", ")))
	writeJSON(w, http.StatusOK, s.viewProposal(np))
}
