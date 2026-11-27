// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// RQ4 node-pair link reconnect in sfcd's real shape
// (docs/reference/tunnel-reconnect.md): tunnel-reconnect-plan {Node, Peer}
// → signed reconnect-tunnel control.TunnelChange{Operation, Plan}
// (Expected 0) → tunnel-reconnect-status {Operation}. sfcd admits only
// system administrators; the web does not judge that itself. Node is the
// owner that dials (the server that saw the link down), Peer the other end.

// tunnelLinkView: one server pair of a TUN network (mesh-links rows whose
// both ends carry the network).
type tunnelLinkView struct {
	Tenant  string `json:"tenant"`
	Network string `json:"network"`
	PairID  string `json:"pairId"`
	From    string `json:"from"`
	To      string `json:"to"`
	State   string `json:"state"`
	Since   int64  `json:"since"`
}

// GET /t/{t}/networks/{name}/tunnels → {items:[{tenant, network, pairId,
// from, to, state(up/degraded/down/pending), since}]}. sfcd has no
// per-network link read: the network row's servers and mesh-links are
// joined by PairID.
func (s *Server) handleNetworkTunnels(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant, name := r.PathValue("t"), r.PathValue("name")
	readList(s, w, r, ws, func(ctx context.Context, c sfc.Conn) ([]tunnelLinkView, error) {
		n, _, err := findNetwork(ctx, c, tenant, name)
		if err != nil {
			return nil, err
		}
		var links []sfc.MeshLinkView
		for after := ""; ; {
			p, err := c.MeshLinks(ctx, tenant, "", after)
			if err != nil {
				return nil, err
			}
			links = append(links, p.Links...)
			if after = p.Next; after == "" {
				break
			}
		}
		out := []tunnelLinkView{}
		for _, l := range links {
			if !slices.Contains(n.Nodes, l.NodeA) || !slices.Contains(n.Nodes, l.NodeB) {
				continue
			}
			a, b := min(l.NodeA, l.NodeB), max(l.NodeA, l.NodeB)
			out = append(out, tunnelLinkView{Tenant: tenant, Network: name, PairID: observability.PairID(a, b), From: a, To: b, State: l.State, Since: newMeshView(l).LastChangeAt})
		}
		return out, nil
	})
}

// tunnelOperation: the reconnect-tunnel Operation of a web opId.
func tunnelOperation(opID string) string { return "op-" + opID }

// POST /t/{t}/networks/{name}/tunnels/reconnect {opId, from, to} and
// POST /nodes/{node}/tunnels/{peer}/reconnect {opId} → reconnect-tunnel.
// from (node) dials to (peer). Only a down link is planned: 409 not-down.
// The job's progress: GET /tunnel-reconnects/{operation}, operation
// "op-"+opId.
func (s *Server) handleReconnectTunnel(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		From string `json:"from,omitempty"`
		To   string `json:"to,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if n := r.PathValue("node"); n != "" {
		req.From, req.To = n, r.PathValue("peer")
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.From == "" || req.To == "" || req.From == req.To {
			return "", nil, 0, "", invalid("from, to: two different servers")
		}
		plan, err := c.PlanTunnelReconnect(ctx, req.From, req.To)
		if isSfcCode(err, sfc.CodeConflict) {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "not-down", "the link is not down (or a server is not an active member); only a down link is reconnected"}
		}
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionReconnectTunnel, control.TunnelChange{Operation: tunnelOperation(req.OpID), Plan: plan}, 0, "tunnel/" + plan.PairID, nil
	})
}

type tunnelStatusView struct {
	Operation    string `json:"operation"`
	User         string `json:"user,omitempty"`
	State        string `json:"state"` // queued / running / done / failed
	Node         string `json:"node"`
	Peer         string `json:"peer"`
	PairID       string `json:"pairId"`
	At           uint64 `json:"at"`
	Revision     uint64 `json:"revision"`
	Result       string `json:"result,omitempty"` // reconnected / already-connected / failed
	Code         string `json:"code,omitempty"`
	Error        string `json:"error,omitempty"`
	HandshakeAt  uint64 `json:"handshakeAt,omitempty"` // Unix ms
	KeptExisting bool   `json:"keptExisting,omitempty"`
}

// GET /tunnel-reconnects/{operation} → tunnel-reconnect-status. An
// unknown operation is 404.
func (s *Server) handleTunnelReconnectStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (tunnelStatusView, error) {
		st, err := c.TunnelReconnectStatus(ctx, r.PathValue("operation"))
		if isSfcCode(err, sfc.CodeConflict) {
			return tunnelStatusView{}, &httpErr{http.StatusNotFound, "not-found", "no such reconnect"}
		}
		if err != nil {
			return tunnelStatusView{}, err
		}
		v := tunnelStatusView{Operation: st.Operation, User: st.User, State: st.State, Node: st.Plan.Node, Peer: st.Plan.Peer, PairID: st.Plan.PairID, At: st.At, Revision: st.Revision}
		if res := st.Result; res != nil {
			v.Result, v.Code, v.Error, v.HandshakeAt, v.KeptExisting = res.State, res.Code, res.Error, res.HandshakeAt, res.KeptExisting
		}
		return v, nil
	})
}
