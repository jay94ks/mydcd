// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jay94ks/seafield/internal/web/ai"
	"github.com/jay94ks/seafield/internal/web/store"
)

// aiToolKind is one kind of coordinator tool (R19). A call reads or makes
// a proposal; approve and edit act on a proposal the kind made. A new kind
// implements this and is picked in toolKind and proposalKind; nothing else
// branches on the kind.
type aiToolKind interface {
	call(ctx context.Context, t *aiTurn, c ai.ToolCall) ai.ToolResult
	approve(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, opID string, repeat bool)
	edit(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, payload json.RawMessage)
	// done: an approved p has taken effect, so the next step may go.
	done(ws *webSession, p *store.AIProposal) bool
}

// screenTool: a tool of aiCatalog (one screen API route).
type screenTool struct {
	s *Server
	d aiToolDef
}

func (k screenTool) call(ctx context.Context, t *aiTurn, c ai.ToolCall) ai.ToolResult {
	return t.runScreenTool(ctx, c, k.d)
}

func (k screenTool) approve(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, opID string, repeat bool) {
	k.s.approveScreen(w, r, ws, p, opID, repeat)
}

func (k screenTool) edit(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, payload json.RawMessage) {
	k.s.editScreenProposal(w, r, ws, p, payload)
}

func (k screenTool) done(ws *webSession, p *store.AIProposal) bool {
	o, err := k.s.opt.Store.GetOp(ws.user.ID, p.Op)
	return err == nil && o.State == store.OpApplied
}

// mcpTool: a tool of a connected MCP server.
type mcpTool struct {
	s *Server
	x aiMCPTool
}

func (k mcpTool) call(ctx context.Context, t *aiTurn, c ai.ToolCall) ai.ToolResult {
	return t.runMCPTool(ctx, c, k.x)
}

func (k mcpTool) approve(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, opID string, repeat bool) {
	k.s.approveMCP(w, r, ws, p, opID, repeat)
}

func (k mcpTool) edit(w http.ResponseWriter, r *http.Request, ws *webSession, p *store.AIProposal, payload json.RawMessage) {
	k.s.editMCPProposal(w, r, ws, p, payload)
}

func (k mcpTool) done(ws *webSession, p *store.AIProposal) bool { return p.Reason == "" }

// toolKind finds a tool the model called this turn.
func (t *aiTurn) toolKind(name string) (aiToolKind, bool) {
	if d, ok := aiToolByName(name); ok {
		return screenTool{t.s, d}, true
	}
	if x, ok := t.mcp[name]; ok {
		return mcpTool{t.s, x}, true
	}
	return nil, false
}

// proposalKind is the kind that made p (the tool itself is looked up
// again when needed: it may be gone since).
func (s *Server) proposalKind(p *store.AIProposal) aiToolKind {
	if p.MCP != nil {
		return mcpTool{s: s}
	}
	return screenTool{s: s}
}
