// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Virtual bridges (UI-5D, devel/design/virtual-bridge.md 5). The rows are
// resources bridge/<owner>/<name>; this file takes create-virtual-bridge,
// approve-virtual-bridge and close-virtual-bridge. The daemon refuses what it
// can see from this tenant's rows; sfcd decides permission, the other
// tenant's bridge-inbound and freshness, and its refusal reasons come back as
// the op's errorCode.

// bridgeState is the row's state for this tenant: open, closing,
// waiting-me (this side has not approved) or waiting-peer.
func bridgeState(tenant string, b *sfc.Bridge) string {
	switch b.Phase {
	case string(tenancy.BridgeOpen):
		return "open"
	case string(tenancy.BridgeClosing):
		return "closing"
	}
	for _, a := range b.Approvals {
		if a.Tenant == tenant {
			return "waiting-peer"
		}
	}
	return "waiting-me"
}

// tenantBridges reads the bridges with a side in tenant, and the networks
// revision.
func tenantBridges(ctx context.Context, c sfc.Conn, tenant string) ([]sfc.Bridge, uint64, error) {
	var out []sfc.Bridge
	for after := ""; ; {
		p, err := screenResources(ctx, c, tenant, after)
		if err != nil {
			return nil, 0, err
		}
		for _, e := range p.Items {
			if e.Bridge != nil {
				out = append(out, *e.Bridge)
			}
		}
		if p.Next == "" {
			return out, p.Collection, nil
		}
		after = p.Next
	}
}

var bridgeDirections = []string{string(tenancy.BridgeBoth), string(tenancy.BridgeAToB), string(tenancy.BridgeBToA)}

// POST /t/{t}/bridges {opId, name, network, peer:{tenant?, network},
// direction?, protocol?, ports?, expected?} → create-virtual-bridge.
// Expected = the networks revision.
func (s *Server) handleBridgeCreate(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string `json:"opId"`
		Name    string `json:"name"`
		Network string `json:"network"`
		Peer    struct {
			Tenant  string `json:"tenant,omitempty"`
			Network string `json:"network"`
		} `json:"peer"`
		Direction string            `json:"direction,omitempty"`
		Protocol  string            `json:"protocol,omitempty"`
		Ports     []json.RawMessage `json:"ports,omitempty"`
		Expected  uint64            `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		peerTenant := req.Peer.Tenant
		if peerTenant == "" {
			peerTenant = tenant
		}
		if !validName(req.Name) || !validName(req.Network) || !validName(req.Peer.Network) || !validName(peerTenant) {
			return "", nil, 0, "", invalid("name, network and peer.network")
		}
		if req.Network == tenancy.SystemNetwork || req.Peer.Network == tenancy.SystemNetwork {
			return "", nil, 0, "", invalid("the system network is never bridged")
		}
		q := control.BridgeProposal{ID: req.Name, A: tenancy.BridgeEnd{Tenant: tenant, Network: req.Network}, B: tenancy.BridgeEnd{Tenant: peerTenant, Network: req.Peer.Network}, Direction: tenancy.BridgeBoth}
		if q.A == q.B {
			return "", nil, 0, "", invalid("peer: another network")
		}
		if req.Direction != "" {
			if !slices.Contains(bridgeDirections, req.Direction) {
				return "", nil, 0, "", invalid("direction: both, a-to-b or b-to-a")
			}
			q.Direction = tenancy.BridgeDirection(req.Direction)
		}
		switch req.Protocol {
		case "", "all":
			if len(req.Ports) != 0 {
				return "", nil, 0, "", invalid("ports: needs protocol tcp or udp")
			}
		case "tcp", "udp":
			q.Protocol = map[string]uint8{"tcp": 6, "udp": 17}[req.Protocol]
			if len(req.Ports) != 0 {
				ports, err := parsePorts(req.Ports)
				if err != nil {
					return "", nil, 0, "", err
				}
				q.Ports = ports
			}
		default:
			return "", nil, 0, "", invalid("protocol: all, tcp or udp")
		}
		own, rev, err := findNetwork(ctx, c, tenant, req.Network)
		if err != nil {
			return "", nil, 0, "", err
		}
		if own.Kind != "tun" {
			return "", nil, 0, "", invalid("network: a TUN network")
		}
		changing := func(n *sfc.Network) bool {
			return slices.ContainsFunc(n.Members, func(m sfc.NetworkMember) bool { return m.Draining || activeChange(m.Change) })
		}
		if changing(own) {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "network-changing", "finish the change on " + req.Network + " first"}
		}
		if peerTenant == tenant {
			peer, _, err := findNetwork(ctx, c, tenant, req.Peer.Network)
			if err != nil {
				return "", nil, 0, "", err
			}
			if changing(peer) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "network-changing", "finish the change on " + req.Peer.Network + " first"}
			}
		}
		bridges, _, err := tenantBridges(ctx, c, tenant)
		if err != nil {
			return "", nil, 0, "", err
		}
		for _, b := range bridges {
			x := [2]sfc.BridgeEnd{b.A, b.B}
			want := sfc.BridgeEnd{Tenant: q.A.Tenant, Network: q.A.Network}
			other := sfc.BridgeEnd{Tenant: q.B.Tenant, Network: q.B.Network}
			if x == [2]sfc.BridgeEnd{want, other} || x == [2]sfc.BridgeEnd{other, want} {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "bridge-exists", "a bridge already links these two networks"}
			}
		}
		return sfc.ActionCreateVirtualBridge, q, expectedOr(req.Expected, rev), "bridge/" + req.Name, nil
	})
}

// POST /t/{t}/bridges/{owner}/{name}/approve | close {opId, expected?} →
// approve-virtual-bridge / close-virtual-bridge for this tenant's side.
// Expected = the bridge revision (expected, else the current one).
func (s *Server) handleBridgeSelect(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		tenant, owner, name := r.PathValue("t"), r.PathValue("owner"), r.PathValue("name")
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			bridges, _, err := tenantBridges(ctx, c, tenant)
			if err != nil {
				return "", nil, 0, "", err
			}
			for _, b := range bridges {
				if b.Owner != owner || b.Name != name {
					continue
				}
				if b.Phase == string(tenancy.BridgeClosing) {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "closing", "this bridge is closing"}
				}
				if action == sfc.ActionApproveVirtualBridge {
					if b.Phase != string(tenancy.BridgePending) || b.B.Tenant != tenant {
						return "", nil, 0, "", &httpErr{http.StatusConflict, "already-approved", "this workspace has nothing to approve on the bridge"}
					}
				}
				return action, control.BridgeSelection{Tenant: tenant, Owner: owner, ID: name}, expectedOr(req.Expected, b.Revision), "bridge/" + name, nil
			}
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such bridge"}
		})
	}
}

// GET /t/{t}/bridge-endpoints?tenant= → {tenant, items:[{tenant, network}]}:
// another workspace's networks that take bridges (bridge-inbound on and no
// member changing), for the create dialog's B side. sfcd lets any session
// that manages networks somewhere read it.
func (s *Server) handleBridgeEndpoints(w http.ResponseWriter, r *http.Request, ws *webSession) {
	other := r.URL.Query().Get("tenant")
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		if other == "" || other == r.PathValue("t") {
			return nil, invalid("tenant: another workspace")
		}
		_, rows, err := publicReadAll(ctx, c, "bridge-endpoints", other, control.PublicReadQuery{})
		if err != nil {
			return nil, err
		}
		items := []map[string]string{}
		for _, row := range rows {
			if e := row.BridgeEndpoint; e != nil {
				items = append(items, map[string]string{"tenant": e.Tenant, "network": e.Network})
			}
		}
		return map[string]any{"tenant": other, "items": items}, nil
	})
}
