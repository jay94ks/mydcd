// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"slices"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Network change and retirement (UI-50 row menu, UI-51 steps). The daemon
// builds every payload from the network's member rows; mydcd decides. A
// member goes plan (reserved) → drain (draining) → fence (fenced) → commit;
// a reserved change can be cancelled. Fence and a bridge network's retire
// carry the owner node's signed NetworkClosure (network-closure, REQ-33).

// findNetwork reads a tenant network row by name and the Networks revision.
func findNetwork(ctx context.Context, c mydc.Conn, tenant, name string) (*mydc.Network, uint64, error) {
	after := ""
	for {
		p, err := c.Resources(ctx, tenant, after)
		if err != nil {
			return nil, 0, err
		}
		for _, e := range p.Items {
			if e.Network != nil && e.Network.Name == name && e.Tenant == tenant {
				return e.Network, p.Collection, nil
			}
		}
		if p.Next == "" {
			return nil, 0, &httpErr{http.StatusNotFound, "not-found", "no such network"}
		}
		after = p.Next
	}
}

func memberOn(n *mydc.Network, node string) (*mydc.NetworkMember, error) {
	for i := range n.Members {
		if n.Members[i].Node == node {
			return &n.Members[i], nil
		}
	}
	return nil, &httpErr{http.StatusUnprocessableEntity, "invalid", "node: not a member of this network"}
}

type changeMemberView struct {
	Node     string `json:"node"`
	ID       string `json:"id"`
	CIDR     string `json:"cidr"`
	Tunnel   string `json:"tunnel,omitempty"`
	Revision uint64 `json:"revision"`
	Draining bool   `json:"draining"`
	// Phase: none / reserved / draining / fenced / committed / cancelled.
	Phase  string              `json:"phase"`
	Target string              `json:"target"`
	Change *mydc.NetworkChange `json:"change,omitempty"`
}

type changeView struct {
	Name             string             `json:"name"`
	Kind             string             `json:"kind"`
	NetworksRevision uint64             `json:"networksRevision"`
	DNSEnabled       bool               `json:"dnsEnabled"`
	Members          []changeMemberView `json:"members"`
	// Next is the step the change waits for: plan / drain / fence / commit
	// ("" when nothing is in progress and nothing to do).
	Next string `json:"next"`
	// Closure: the closure report of each drained member (what still uses
	// it, or closed); null when no member is drained.
	Closure []closureView `json:"closure"`
}

func networkChangeView(n *mydc.Network, rev uint64) changeView {
	v := changeView{Name: n.Name, Kind: n.Kind, NetworksRevision: rev, DNSEnabled: n.DNS != nil && n.DNS.Enabled, Members: []changeMemberView{}}
	phases := map[string]int{}
	for _, m := range n.Members {
		mv := changeMemberView{Node: m.Node, ID: m.ID, CIDR: m.CIDR, Tunnel: m.Tunnel, Revision: m.Revision, Draining: m.Draining, Phase: "none", Target: m.CIDR}
		if m.Change != nil {
			mv.Change = m.Change
			if activeChange(m.Change) {
				mv.Phase, mv.Target = m.Change.Phase, m.Change.TargetCIDR
				phases[m.Change.Phase]++
			}
		}
		v.Members = append(v.Members, mv)
	}
	switch {
	case phases["reserved"] > 0:
		v.Next = "drain"
	case phases["draining"] > 0:
		v.Next = "fence"
	case phases["fenced"] > 0:
		v.Next = "commit"
	}
	return v
}

func activeChange(c *mydc.NetworkChange) bool {
	return c != nil && c.Phase != string(tenancy.ChangeCommitted) && c.Phase != string(tenancy.ChangeCancelled)
}

// GET /t/{t}/networks/{name}/change
func (s *Server) handleNetworkChangeStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (changeView, error) {
		n, rev, err := findNetwork(ctx, c, r.PathValue("t"), r.PathValue("name"))
		if err != nil {
			return changeView{}, err
		}
		v := networkChangeView(n, rev)
		if v.Closure, err = closures(ctx, c, n); err != nil {
			return v, err
		}
		return v, nil
	})
}

// networkStep is a network change endpoint: build gets the network row and
// the Networks revision.
func (s *Server) networkStep(w http.ResponseWriter, r *http.Request, ws *webSession, opID string, body any,
	build func(ctx context.Context, c mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error)) {
	tenant, name := r.PathValue("t"), r.PathValue("name")
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		if !validName(name) {
			return "", nil, 0, "", invalid("network name")
		}
		n, rev, err := findNetwork(ctx, c, tenant, name)
		if err != nil {
			return "", nil, 0, "", err
		}
		action, payload, expected, err := build(ctx, c, n, rev)
		return action, payload, expected, "network/" + name, err
	})
}

// POST /t/{t}/networks/{name}/change {opId, node, cidr, gateway?}
// → plan-network-change for that member (Expected: the member's revision).
// The change ID is "chg-" + opId.
func (s *Server) handleNetworkChangePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string `json:"opId"`
		Node    string `json:"node"`
		CIDR    string `json:"cidr"`
		Gateway string `json:"gateway,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, _ uint64) (string, any, uint64, error) {
		m, err := memberOn(n, req.Node)
		if err != nil {
			return "", nil, 0, err
		}
		if len(m.Source.Pools) == 0 {
			return "", nil, 0, &httpErr{http.StatusConflict, "no-pool", "the member has no address pool"}
		}
		if activeChange(m.Change) {
			return "", nil, 0, &httpErr{http.StatusConflict, "change-pending", "this server already has a change in progress"}
		}
		pool, err := netPool(req.CIDR, req.Gateway, m.Source.Pools[0].MTU)
		if err != nil {
			return "", nil, 0, err
		}
		pool.ID, pool.IPAM = m.Source.Pools[0].ID, m.Source.Pools[0].IPAM
		target := m.Source
		target.Pools = slices.Clone(m.Source.Pools)
		target.Pools[0] = pool
		// A plan target is a definition: mydcd (tenancy.validDefinition)
		// refuses one that still carries the member's state.
		target.Owner, target.Draining, target.PendingChange = [32]byte{}, false, 0
		target.Generation, target.Revision = 0, 0
		q := control.NetworkChangePlan{Tenant: target.Tenant, ID: m.ID, Change: "chg-" + req.OpID, Target: target}
		return mydc.ActionPlanNetworkChange, q, m.Revision, nil
	})
}

// POST /t/{t}/networks/{name}/change/drain {opId, node} → drain-network of
// that member: new use stops and a reserved change becomes draining.
func (s *Server) handleNetworkChangeDrain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Node string `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, _ uint64) (string, any, uint64, error) {
		m, err := memberOn(n, req.Node)
		if err != nil {
			return "", nil, 0, err
		}
		return mydc.ActionDrainNetwork, control.NetworkSelection{Tenant: m.Source.Tenant, ID: m.ID}, m.Revision, nil
	})
}

// POST /t/{t}/networks/{name}/change/cancel {opId, node} → cancel-network-change
// of a reserved (not yet drained) change.
func (s *Server) handleNetworkChangeCancel(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Node string `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, _ uint64) (string, any, uint64, error) {
		m, err := memberOn(n, req.Node)
		if err != nil {
			return "", nil, 0, err
		}
		if m.Change == nil || m.Change.Phase != string(tenancy.ChangeReserved) {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-reserved", "only a planned change that has not been drained can be cancelled"}
		}
		q := control.NetworkChangeCancel{Tenant: m.Source.Tenant, ID: m.ID, Generation: m.Change.Generation}
		return mydc.ActionCancelNetworkChange, q, m.Change.Revision, nil
	})
}

// changeVersions: every member's change version; all must be fenced.
func changeVersions(n *mydc.Network) ([]tenancy.NetworkChangeVersion, error) {
	var out []tenancy.NetworkChangeVersion
	for _, m := range n.Members {
		if m.Change == nil || m.Change.Phase != string(tenancy.ChangeFenced) {
			return nil, &httpErr{http.StatusConflict, "not-fenced", "every server of the network must be fenced first (" + m.Node + ")"}
		}
		out = append(out, tenancy.NetworkChangeVersion{Tenant: m.Source.Tenant, ID: m.ID, Generation: m.Change.Generation, Revision: m.Change.Revision})
	}
	if len(out) == 0 {
		return nil, &httpErr{http.StatusConflict, "not-fenced", "the network has no members"}
	}
	return out, nil
}

// expectedOr: the browser's networksRevision when given, else the current one.
func expectedOr(given, current uint64) uint64 {
	if given != 0 {
		return given
	}
	return current
}

// POST /t/{t}/networks/{name}/change/commit {opId, expected?}
// → commit-network-change with every member's change version (TUN networks;
// Expected: Networks revision).
func (s *Server) handleNetworkChangeCommit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error) {
		if n.Kind != "tun" {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-tun", "mydcd commits network changes only for TUN networks"}
		}
		versions, err := changeVersions(n)
		if err != nil {
			return "", nil, 0, err
		}
		tenant := r.PathValue("t")
		return mydc.ActionCommitNetworkChange, control.NetworkChangeCommit{Tenant: tenant, Network: n.Name, Members: versions}, expectedOr(req.Expected, rev), nil
	})
}

// POST /t/{t}/networks/{name}/reconfigure {opId, members:[{node, cidr?,
// gateway?, tunnel?}], tunnelCidr?, expected?} → reconfigure-tun-network: the
// full new member list. A kept server keeps its pool and tunnel address
// unless given; a new one needs cidr and a tunnel (or tunnelCidr). Every
// current member must be fenced.
func (s *Server) handleNetworkReconfigure(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type member struct {
		Node    string `json:"node"`
		CIDR    string `json:"cidr,omitempty"`
		Gateway string `json:"gateway,omitempty"`
		Tunnel  string `json:"tunnel,omitempty"`
	}
	var req struct {
		OpID       string   `json:"opId"`
		Members    []member `json:"members"`
		TunnelCIDR string   `json:"tunnelCidr,omitempty"`
		Expected   uint64   `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Members == nil {
		req.Members = []member{}
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error) {
		if n.Kind != "tun" {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-tun", "only a TUN network has members to reconfigure"}
		}
		if len(req.Members) == 0 {
			return "", nil, 0, invalid("members: at least one server (use retire to remove the network)")
		}
		if len(req.Members) > 32 {
			return "", nil, 0, invalid("members: at most 32")
		}
		// The network keeps its toggles; one that does not allow the new
		// server count must be turned off first.
		for _, t := range tenancy.NetworkToggles() {
			if !tenancy.ToggleAllowed(t, slices.Contains(n.Toggles, t), len(req.Members)) {
				return "", nil, 0, &httpErr{http.StatusConflict, "toggle-not-allowed", fmt.Sprintf("turn %s off before changing to %d servers", t, len(req.Members))}
			}
		}
		versions, err := changeVersions(n)
		if err != nil {
			return "", nil, 0, err
		}
		tenant := r.PathValue("t")
		mtu := 1500
		if len(n.Members) > 0 && len(n.Members[0].Source.Pools) > 0 && n.Members[0].Source.Pools[0].MTU != 0 {
			mtu = n.Members[0].Source.Pools[0].MTU
		}
		d, err := tunDefinition(tenant, n.Name, mtu, req.TunnelCIDR, func(yield func(node, cidr, gateway, tunnel string) error) error {
			for _, m := range req.Members {
				cidr, gateway, tunnel := m.CIDR, m.Gateway, m.Tunnel
				for _, cur := range n.Members {
					if cur.Node != m.Node || len(cur.Source.Pools) == 0 {
						continue
					}
					if cidr == "" {
						cidr, gateway = cur.Source.Pools[0].Prefix.String(), cur.Source.Pools[0].Gateway.String()
					}
					if tunnel == "" && len(cur.Source.TunnelAddresses) > 0 && req.TunnelCIDR == "" {
						tunnel = cur.Source.TunnelAddresses[0].Addr().String()
					}
				}
				if err := yield(m.Node, cidr, gateway, tunnel); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return "", nil, 0, err
		}
		d.Toggles = slices.Clone(n.Toggles)
		return mydc.ActionReconfigureTUN, control.NetworkReconfigure{Target: d, Members: versions}, expectedOr(req.Expected, rev), nil
	})
}

// POST /t/{t}/networks/{name}/members {opId, node, cidr, gateway?, tunnel,
// expected?} → join-tun-network: one server joins a TUN network at its MTU.
// The other servers keep their device; only their routes change. 409
// member-changing while a member drains or has a change in progress.
func (s *Server) handleNetworkJoin(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Node     string `json:"node"`
		CIDR     string `json:"cidr"`
		Gateway  string `json:"gateway,omitempty"`
		Tunnel   string `json:"tunnel"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error) {
		if n.Kind != "tun" {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-tun", "only a TUN network takes more servers"}
		}
		if req.Tunnel == "" {
			return "", nil, 0, invalid("tunnel: the new server's tunnel address")
		}
		for _, t := range tenancy.NetworkToggles() {
			if !tenancy.ToggleAllowed(t, slices.Contains(n.Toggles, t), len(n.Members)+1) {
				return "", nil, 0, &httpErr{http.StatusConflict, "toggle-not-allowed", fmt.Sprintf("turn %s off before adding a server", t)}
			}
		}
		mtu := 0
		for _, m := range n.Members {
			if m.Node == req.Node {
				return "", nil, 0, &httpErr{http.StatusConflict, "already-member", "the server is already in this network"}
			}
			if m.Draining || activeChange(m.Change) {
				return "", nil, 0, &httpErr{http.StatusConflict, "member-changing", "finish the change on " + m.Node + " first"}
			}
			if mtu == 0 && len(m.Source.Pools) > 0 {
				mtu = m.Source.Pools[0].MTU
			}
		}
		tenant := r.PathValue("t")
		d, err := tunDefinition(tenant, n.Name, mtu, "", func(yield func(node, cidr, gateway, tunnel string) error) error {
			return yield(req.Node, req.CIDR, req.Gateway, req.Tunnel)
		})
		if err != nil {
			return "", nil, 0, err
		}
		for _, m := range n.Members {
			for _, p := range m.Source.Pools {
				if p.Prefix.Overlaps(d.Members[0].Pools[0].Prefix) || p.Prefix.Contains(d.Members[0].Addresses[0].Addr()) {
					return "", nil, 0, invalid("cidr and tunnel must not overlap another server's pool")
				}
			}
			if slices.Contains(m.Source.TunnelAddresses, d.Members[0].Addresses[0]) || d.Members[0].Pools[0].Prefix.Contains(firstAddr(m.Source.TunnelAddresses)) {
				return "", nil, 0, invalid("cidr and tunnel must not overlap another server's tunnel address")
			}
		}
		return mydc.ActionJoinTUN, control.NetworkJoin{Tenant: tenant, Name: n.Name, Member: d.Members[0]}, expectedOr(req.Expected, rev), nil
	})
}

// POST /t/{t}/networks/{name}/members/leave {opId, node} → leave-tun-network:
// one drained server (POST …/change/drain first: 409 not-drained) leaves on
// its owner's signed closure (409 in-use while containers use it). When the
// last server leaves, the network is deleted; its DNS must be off first
// (409 dns-enabled).
func (s *Server) handleNetworkLeave(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Node string `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, n *mydc.Network, _ uint64) (string, any, uint64, error) {
		m, err := memberOn(n, req.Node)
		if err != nil {
			return "", nil, 0, err
		}
		// The last server leaving deletes the network; its DNS goes off first.
		if len(n.Members) == 1 && n.DNS != nil && n.DNS.Enabled {
			return "", nil, 0, &httpErr{http.StatusConflict, "dns-enabled", "turn the network's DNS off before the last server leaves"}
		}
		if !m.Draining {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-drained", "drain the server first (POST …/change/drain)"}
		}
		closed, err := memberClosed(ctx, c, m)
		if err != nil {
			return "", nil, 0, err
		}
		return mydc.ActionLeaveTUN, closed, m.Revision, nil
	})
}

// POST /t/{t}/networks/{name}/toggles {opId, toggle, on, expected?} →
// set-network-toggle: one toggle of a TUN network on or off. Nothing on the
// servers is cut. 422 for an unknown toggle; 409 toggle-not-allowed when
// the network's servers do not allow the value (local on with more than one
// server), same-value when it already holds it, member-changing while a
// server drains or changes.
func (s *Server) handleNetworkToggle(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Toggle   string `json:"toggle"`
		On       bool   `json:"on"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error) {
		t := tenancy.NetworkToggle(req.Toggle)
		if !slices.Contains(tenancy.NetworkToggles(), t) {
			return "", nil, 0, invalid(fmt.Sprintf("toggle: one of %v", tenancy.NetworkToggles()))
		}
		if n.Kind != "tun" {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-tun", "only a TUN network has toggles"}
		}
		for _, m := range n.Members {
			if m.Draining || activeChange(m.Change) {
				return "", nil, 0, &httpErr{http.StatusConflict, "member-changing", "finish the change on " + m.Node + " first"}
			}
		}
		if slices.Contains(n.Toggles, t) == req.On {
			return "", nil, 0, &httpErr{http.StatusConflict, "same-value", "the toggle already has this value"}
		}
		if !tenancy.ToggleAllowed(t, req.On, len(n.Members)) {
			return "", nil, 0, &httpErr{http.StatusConflict, "toggle-not-allowed", fmt.Sprintf("%s cannot be %v with %d servers", t, req.On, len(n.Members))}
		}
		return mydc.ActionSetNetworkToggle, control.NetworkToggleSet{Tenant: r.PathValue("t"), Name: n.Name, Toggle: t, On: req.On}, expectedOr(req.Expected, rev), nil
	})
}

// firstAddr is the first address of a tunnel list (invalid when empty).
func firstAddr(v []netip.Prefix) netip.Addr {
	if len(v) == 0 {
		return netip.Addr{}
	}
	return v[0].Addr()
}

// POST /t/{t}/networks/{name}/retire {opId, expected?}: a TUN network is
// retired by reconfigure-tun-network with no members (every member fenced,
// DNS off first: 409 dns-enabled). Removing the servers one by one with
// …/members/leave also deletes it, and needs no planned change.
func (s *Server) handleNetworkRetire(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(_ context.Context, _ mydc.Conn, n *mydc.Network, rev uint64) (string, any, uint64, error) {
		if n.DNS != nil && n.DNS.Enabled {
			return "", nil, 0, &httpErr{http.StatusConflict, "dns-enabled", "turn the network's DNS off first"}
		}
		versions, err := changeVersions(n)
		if err != nil {
			return "", nil, 0, err
		}
		target := tenancy.TUNDefinition{Tenant: r.PathValue("t"), Name: n.Name, Members: []tenancy.TUNNode{}}
		return mydc.ActionReconfigureTUN, control.NetworkReconfigure{Target: target, Members: versions}, expectedOr(req.Expected, rev), nil
	})
}

// memberClosed reads the member's closure (REQ-33 PublicRead
// network-closure): the owner-signed proof once nothing uses the drained
// member, else 409 in-use / unreachable.
func memberClosed(ctx context.Context, c mydc.Conn, m *mydc.NetworkMember) (mydc.NetworkClosure, error) {
	v, err := readClosure(ctx, c, m.Source.Tenant, m.ID)
	if err != nil {
		return mydc.NetworkClosure{}, err
	}
	switch {
	case v.State == "unreachable":
		return mydc.NetworkClosure{}, &httpErr{http.StatusConflict, "unreachable", "the server of " + m.Node + " does not answer"}
	case v.State != "closed" || v.Closure == nil:
		msg := "containers on " + m.Node + " still use the network"
		if v.PendingEndpoints != nil {
			msg = fmt.Sprintf("%d %s", *v.PendingEndpoints, msg)
		}
		return mydc.NetworkClosure{}, &httpErr{http.StatusConflict, "in-use", msg}
	}
	return *v.Closure, nil
}

// POST /t/{t}/networks/{name}/change/fence {opId, node} → fence-network-change
// of a draining change with the owner's closure (Expected: the change
// revision). 409 not-draining, in-use (containers still on it), unreachable.
func (s *Server) handleNetworkChangeFence(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Node string `json:"node"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.networkStep(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, n *mydc.Network, _ uint64) (string, any, uint64, error) {
		m, err := memberOn(n, req.Node)
		if err != nil {
			return "", nil, 0, err
		}
		if m.Change == nil || m.Change.Phase != string(tenancy.ChangeDraining) {
			return "", nil, 0, &httpErr{http.StatusConflict, "not-draining", "this server's change is not draining"}
		}
		closed, err := memberClosed(ctx, c, m)
		if err != nil {
			return "", nil, 0, err
		}
		q := control.NetworkChangeFence{Tenant: m.Source.Tenant, ID: m.ID, Generation: m.Change.Generation, Closed: closed}
		return mydc.ActionFenceNetworkChange, q, m.Change.Revision, nil
	})
}

// closureView is one drained member's closure report. A count mydcd has
// not measured is null (never guessed as 0); nativeGone likewise.
type closureView struct {
	Node             string  `json:"node"`
	State            string  `json:"state"` // pending / unreachable / closed
	Closed           bool    `json:"closed"`
	Unreachable      bool    `json:"unreachable"`
	NativeGone       *bool   `json:"nativeGone"`
	PendingEndpoints *uint64 `json:"pendingEndpoints"`
	PendingFlows     *uint64 `json:"pendingFlows"`
	PendingPins      *uint64 `json:"pendingPins"`
}

// closures reads the closure report of each drained member (nil when none).
func closures(ctx context.Context, c mydc.Conn, n *mydc.Network) ([]closureView, error) {
	var out []closureView
	for i := range n.Members {
		m := &n.Members[i]
		if !m.Draining {
			continue
		}
		v, err := readClosure(ctx, c, m.Source.Tenant, m.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, closureView{Node: m.Node, State: v.State, Closed: v.State == "closed" && v.Closure != nil, Unreachable: v.State == "unreachable",
			NativeGone: v.NativeGone, PendingEndpoints: v.PendingEndpoints, PendingFlows: v.PendingFlows, PendingPins: v.PendingPins})
	}
	return out, nil
}
