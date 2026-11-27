// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// SystemNetworkReport is a server's own step on the system network
// (sfc-system), signed with its node key. No user sends one: the network
// follows the servers that run cluster apps.
//
//   - use: the server starts (On) or stops running cluster apps. The first user
//     creates the network with itself as the only member.
//   - join: a work server that is not a member joins while any server uses
//     the network (and creates it when it has no members).
//   - drain, leave: while no server uses it, each member drains itself; a
//     drained member leaves on its own closure. The last leave deletes the
//     network.
//   - run: the server starts running cluster app App. Only one server runs
//     each cluster app: refused while another server that uses the network
//     runs it (Jay 2026-11-26). Stopping cluster apps (use off) ends its
//     runs. Its address is fixed (tenancy Networks.ClusterAppAddress).
//
// Expected is the networks revision (use, join, run) or the member's
// revision (drain, leave). RootRevision is the resources root it was read at.
type SystemNetworkReport struct {
	Schema            uint8
	Cluster, Reporter [32]byte
	Node, Action      string
	On                bool   `json:",omitempty"`
	App               string `json:",omitempty"`
	Expected, Epoch   uint64
	RootRevision      uint64
	Closure           *tenancy.NetworkClosure `json:",omitempty"`
	Signature         []byte
}

func SystemNetworkReportBytes(r SystemNetworkReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-system-network-report-1\x00"), raw...)
}

func (r SystemNetworkReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: ResourcesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func (p Policy) ResolveSystemNetworkReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r SystemNetworkReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.systemNetworkReport(s, cmd)
	return cmd, err
}

func (p Policy) systemNetworkReport(s state.State, cmd state.Command) (SystemNetworkReport, error) {
	var r SystemNetworkReport
	if cmd.Kind != state.ModuleReport || cmd.Key != ResourcesKey || !strings.HasPrefix(cmd.Actor, "node/") || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || !ed25519.Verify(r.Reporter[:], SystemNetworkReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ErrCatalog
	}
	if (r.Action == "run") != (r.App != "") {
		return r, ErrCatalog
	}
	switch r.Action {
	case "use", "join", "drain", "run":
		if r.Closure != nil {
			return r, ErrCatalog
		}
	case "leave":
		if r.On || r.Closure == nil || r.Closure.Node != r.Node || r.Closure.Owner != r.Reporter {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	if r.On && r.Action != "use" {
		return r, ErrCatalog
	}
	// Joining and starting to use need a current work server; stopping and
	// leaving only the server's own identity.
	owner := p.nodeOwner
	if r.Action == "join" || r.Action == "use" && r.On || r.Action == "run" {
		owner = p.workNodeOwner
	}
	key, err := owner(s, r.Node)
	if err != nil || key != r.Reporter {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) reduceSystemNetworkReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	current, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	p = current
	r, err := p.systemNetworkReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	res, err := p.Resources(s)
	if err != nil {
		return nil, state.Invalid
	}
	var native map[string][]byte
	members := res.Networks.SystemMembers()
	member := func() (tenancy.Network, bool) {
		for _, m := range members {
			if m.Node == r.Node {
				return m, true
			}
		}
		return tenancy.Network{}, false
	}
	switch r.Action {
	case "use":
		if r.Expected != res.Networks.Revision() {
			return nil, state.ConditionFailed
		}
		res.Networks, err = res.Networks.SetSystemUse(r.Node, r.On)
		if err == nil && r.On && len(members) == 0 {
			res.Networks, native, err = p.createSystemNetwork(s, res, r)
		} else if err == nil && !r.On {
			// its cluster apps' addresses stop routing to it
			native, err = systemTunnelWrites(s, res.Networks)
		}
	case "run":
		res.Networks, err = res.Networks.ClaimClusterApp(r.Expected, r.Node, r.App, p.SystemNetworkUsers(s, res.Networks))
		if errors.Is(err, access.ErrConflict) {
			return nil, state.ConditionFailed
		}
		if err == nil {
			// the other members' TUNs route the app's address to it
			native, err = systemTunnelWrites(s, res.Networks)
		}
	case "join":
		if _, found := member(); found || len(p.SystemNetworkUsers(s, res.Networks)) == 0 || r.Expected != res.Networks.Revision() {
			return nil, state.ConditionFailed
		}
		if len(members) == 0 {
			// used again while the last members were leaving
			res.Networks, native, err = p.createSystemNetwork(s, res, r)
			break
		}
		var next tenancy.TUNNode
		if next, err = res.Networks.NextSystemMember(r.Node, r.Reporter); err == nil {
			res.Networks, err = res.Networks.JoinSystemTUN(res.Quotas, r.Expected, next)
		}
		if err == nil {
			native, err = joinManagedNetworkSources(s, res.Networks, "", tenancy.SystemNetwork, r.Node)
		}
	case "drain":
		m, found := member()
		if !found || len(p.SystemNetworkUsers(s, res.Networks)) != 0 {
			return nil, state.ConditionFailed
		}
		res.Networks, err = res.Networks.DrainSystem(r.Node, r.Expected)
		if err == nil {
			native, err = drainManagedNetworkSources(s, res.Networks, "", m.ID, cmd)
		}
	case "leave":
		proof := *r.Closure
		// A drained member still leaves when a server uses the network
		// again meanwhile: its server joins anew afterwards.
		if m, found := member(); !found || proof.Tenant != "" || proof.Network != m.ID {
			return nil, state.ConditionFailed
		}
		res.Networks, native, err = p.leaveMember(s, res, proof, r.Expected, func(a services.Authority, sources []services.RetiredNativeSource) (services.Authority, tenancy.Networks, error) {
			return a.LeaveSystemTUN(res.Networks, proof, sources)
		})
	}
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	writes, code := p.resourceCheckpoint(s, res)
	if code != state.Applied {
		return nil, code
	}
	for key, raw := range native {
		writes[key] = raw
	}
	return writes, code
}

// systemTunnelWrites rewrites the members' TUN sources whose route set
// changed, in place: a cluster app's address follows the server that runs
// it (tenancy Networks.ClusterAppHosts). Nothing changes without members.
func systemTunnelWrites(s state.State, next tenancy.Networks) (map[string][]byte, error) {
	if len(next.SystemMembers()) == 0 {
		return nil, nil
	}
	rows, err := next.TUNSources("", tenancy.SystemNetwork)
	if err != nil {
		return nil, err
	}
	writes := map[string][]byte{}
	for _, row := range rows {
		o := s.Object(row.TunnelKey)
		if row.Tunnel == nil || !o.Present {
			return nil, ErrCatalog
		}
		raw, _ := json.Marshal(row.Tunnel)
		if string(raw) != o.Value {
			writes[row.TunnelKey] = raw
		}
	}
	return writes, nil
}

// createSystemNetwork creates the system network with the reporter as its
// only member, at the first free addresses of the range.
func (p Policy) createSystemNetwork(s state.State, res Resources, r SystemNetworkReport) (tenancy.Networks, map[string][]byte, error) {
	first, err := res.Networks.NextSystemMember(r.Node, r.Reporter)
	if err != nil {
		return res.Networks, nil, err
	}
	d := tenancy.TUNDefinition{Name: tenancy.SystemNetwork, System: true, GatewayMode: network.ManagedGatewayMode, Members: []tenancy.TUNNode{first}}
	next, err := res.Networks.CreateSystemTUN(res.Quotas, res.Networks.Revision(), d)
	if err != nil {
		return res.Networks, nil, err
	}
	native, err := newManagedNetworkSources(s, next, "", tenancy.SystemNetwork)
	return next, native, err
}

// SystemNetworkUsers are the servers recorded as using the system network
// that are still full cluster members. A server removed from the cluster
// cannot report that it stopped, so its record no longer holds the network.
func (p Policy) SystemNetworkUsers(s state.State, n tenancy.Networks) []string {
	var out []string
	for _, u := range n.SystemPolicy().Users {
		if _, err := p.nodeOwner(s, u); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// systemRangeRefusal: a refused workspace network create, join, plan or
// reconfigure whose addresses overlap the system range gets its own result
// reason (system-range-overlap) instead of a bare condition failure.
func systemRangeRefusal(n tenancy.Networks, change Change) bool {
	var prefixes []netip.Prefix
	members := func(m []tenancy.TUNNode) {
		for _, v := range m {
			for _, p := range v.Pools {
				prefixes = append(prefixes, p.Prefix)
			}
		}
	}
	switch change.Action {
	case "create-tun-network":
		var v tenancy.TUNDefinition
		if canonical(change.Payload, &v) != nil {
			return false
		}
		members(v.Members)
	case "join-tun-network":
		var v NetworkJoin
		if canonical(change.Payload, &v) != nil {
			return false
		}
		members([]tenancy.TUNNode{v.Member})
	case "reconfigure-tun-network":
		var v NetworkReconfigure
		if canonical(change.Payload, &v) != nil {
			return false
		}
		members(v.Target.Members)
	case "plan-network-change":
		var v NetworkChangePlan
		if canonical(change.Payload, &v) != nil {
			return false
		}
		for _, p := range v.Target.Pools {
			prefixes = append(prefixes, p.Prefix)
		}
	default:
		return false
	}
	return tenancy.OverlapsSystemRange(prefixes)
}

// SystemNetworkBlock is why node cannot add itself to the system network
// now (use that creates it, or join), as a fixed reason, or "" when nothing
// known blocks it. The reducer refuses such a report as a condition failure,
// which reads the same as a race, so sfcd asks this first and shows the
// reason instead of sending a report that cannot apply.
func (p Policy) SystemNetworkBlock(s state.State, node string, owner [32]byte) string {
	if key, err := p.workNodeOwner(s, node); err != nil || key != owner {
		return "not-work-server"
	}
	res, err := p.Resources(s)
	if err != nil {
		return ""
	}
	if _, ok := res.Networks.NodeAddress(node); !ok {
		return "no-server-address"
	}
	limit, ok := res.Quotas.Limit("", node)
	switch {
	case !ok:
		return "no-server-quota"
	case limit.Owner != owner:
		return "server-quota-owner"
	case res.Networks.ReservedCount("", node) >= limit.Networks:
		return "server-network-limit"
	}
	if _, err := res.Networks.NextSystemMember(node, owner); err != nil {
		return "no-free-system-pool"
	}
	return ""
}
