// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Uses the existing owned two-namespace/two-Engine fixture after app borrows
// have closed. All proofs come from the actual installed owners' observe RPC;
// this helper neither fabricates native facts nor substitutes cleanup for them.
func verifyManagedTUNReconfiguration(t *testing.T, p control.Policy, read func() cluster.View, submit func(string, string, uint64, any) state.Result, wait func(string, func() bool), observe func(string, string) (ModuleObservation, error), startEchoes, stopEchoes, probe, stopB, startB, restartB func(), replay func(string)) {
	t.Helper()
	apply := func(id, action string, expected uint64, payload any) {
		t.Helper()
		if result := submit(id, action, expected, payload); result.Code != state.Applied {
			t.Fatal(id, action, result)
		}
	}
	resources := func() control.Resources {
		t.Helper()
		r, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	rows := func(name string) []tenancy.TUNSource {
		t.Helper()
		v, err := resources().Networks.TUNSources("tenant", name)
		if err != nil {
			t.Fatal(name, err)
		}
		return v
	}
	versions := func(group []tenancy.TUNSource) []tenancy.NetworkChangeVersion {
		t.Helper()
		n := resources().Networks
		var out []tenancy.NetworkChangeVersion
		for _, row := range group {
			ch, found := n.Change("tenant", row.Network.ID)
			if !found {
				t.Fatal("lost original change", row.Network.ID)
			}
			out = append(out, tenancy.NetworkChangeVersion{Tenant: "tenant", ID: row.Network.ID, Generation: ch.Generation, Revision: ch.Revision})
		}
		return out
	}
	waitClosed := func(group []tenancy.TUNSource) {
		t.Helper()
		wait("every original Bridge/TUN terminal journal at its exact tombstone", func() bool {
			for _, row := range group {
				for _, key := range []string{row.BridgeKey, row.TunnelKey} {
					if key == "" {
						continue
					}
					object := read().State.Object(key)
					o, err := observe(row.Network.Node, key)
					if err != nil || o.Ready || o.Error != "" || len(o.Retirement) == 0 || object.Present || o.Journal.PendingID != 0 || o.Journal.Applied.Present || o.Journal.Desired.Present || o.Journal.Consumers != 0 || o.Journal.GenerationFloor != object.Generation || o.Journal.DesiredRevision < object.Revision {
						return false
					}
				}
			}
			return true
		})
	}
	drain := func(id, name string, changeGateway bool) []tenancy.NetworkChangeVersion {
		t.Helper()
		group := rows(name)
		for _, row := range group {
			n := row.Network
			target := n
			target.Generation, target.Revision, target.PendingChange = 0, 0, 0
			target.Owner = [32]byte{}
			target.Pools = append([]tenancy.Subnet(nil), n.Pools...)
			if changeGateway {
				target.Pools[0].Gateway = target.Pools[0].Gateway.Next()
			}
			apply(id+"/plan/"+n.Node, "plan-network-change", n.Revision, control.NetworkChangePlan{Tenant: "tenant", ID: n.ID, Change: id + "-" + n.Node, Target: target})
		}
		for _, row := range group {
			n := row.Network
			apply(id+"/drain/"+n.Node, "drain-network", n.Revision, control.NetworkSelection{Tenant: "tenant", ID: n.ID})
		}
		for i, row := range group {
			var proof tenancy.NetworkClosure
			wait("actual owner Bridge/TUN Gone before shared fence "+row.Network.Node, func() bool {
				o, err := observe(row.Network.Node, row.BridgeKey)
				return err == nil && !o.Ready && len(o.Retirement) != 0 && json.Unmarshal(o.Retirement, &proof) == nil
			})
			ch, _ := resources().Networks.Change("tenant", row.Network.ID)
			apply(id+"/fence/"+row.Network.Node, "fence-network-change", ch.Revision, control.NetworkChangeFence{Tenant: "tenant", ID: row.Network.ID, Generation: ch.Generation, Closed: proof})
			if i == 0 && len(group) > 1 {
				before := read().State.Object(control.ResourcesKey)
				result := submit(id+"/premature-commit", "commit-network-change", resources().Networks.Revision(), control.NetworkChangeCommit{Tenant: "tenant", Network: name, Members: versions(group)})
				if result.Code != state.ConditionFailed || read().State.Object(control.ResourcesKey) != before || !read().State.Object(group[1].BridgeKey).Present || !read().State.Object(group[1].TunnelKey).Present {
					t.Fatal("one owner's closure partially committed or withdrew its peer", result)
				}
			}
		}
		waitClosed(group)
		return versions(group)
	}
	waitActive := func(name string, previous map[string]state.Object) map[string]ModuleObservation {
		t.Helper()
		out := map[string]ModuleObservation{}
		wait("new management generation actually serves Bridge/TUN "+name, func() bool {
			for _, row := range rows(name) {
				for _, key := range []string{row.BridgeKey, row.TunnelKey} {
					if key == "" {
						continue
					}
					o, err := observe(row.Network.Node, key)
					object := read().State.Object(key)
					if err != nil || !o.Ready || !object.Present || o.Generation != object.Generation || object.Generation <= previous[key].Generation || o.NativeID == "" || len(o.Retirement) != 0 || row.TunnelKey == key && (o.Tunnel == nil || o.Tunnel.PacketUsers != 1) {
						return false
					}
					out[key] = o
				}
			}
			return true
		})
		return out
	}

	before := read().State.Objects(tenancy.ManagedNetworkSourcePrefix)
	old := rows("alpha")
	reservation := old[0].Network
	originalNative, err := observe(reservation.Node, old[0].BridgeKey)
	if err != nil || !originalNative.Ready {
		t.Fatal("original Bridge before metadata cancellation", err)
	}
	target := reservation
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	target.Owner = [32]byte{}
	apply("e3-cancel/plan", "plan-network-change", reservation.Revision, control.NetworkChangePlan{Tenant: "tenant", ID: reservation.ID, Change: "e3-cancel", Target: target})
	candidate, _ := resources().Networks.Change("tenant", reservation.ID)
	if !candidate.MetadataOnly || tenancy.CandidateNativeID(candidate) != "" {
		t.Fatal("product reservation invented a native candidate")
	}
	apply("e3-cancel/cancel", "cancel-network-change", candidate.Revision, control.NetworkChangeCancel{Tenant: "tenant", ID: reservation.ID, Generation: candidate.Generation})
	for key, source := range before {
		if read().State.Object(key) != source {
			t.Fatal("metadata cancellation changed native source", key)
		}
	}
	wait("metadata cancellation preserves original native Bridge", func() bool {
		o, err := observe(reservation.Node, old[0].BridgeKey)
		return err == nil && o.Ready && o.NativeID == originalNative.NativeID && o.Generation == originalNative.Generation && o.Journal.LastID == originalNative.Journal.LastID
	})
	selected := drain("e3-gateway", "alpha", true)
	// The original owners have both closed. Revocation is still checked at
	// target admission, and must not partially publish the reserved target.
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	apply("e3-gateway/revoke-target", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}})
	reserved := read().State.Object(control.ResourcesKey)
	blocked := submit("e3-gateway/blocked-commit", "commit-network-change", resources().Networks.Revision(), control.NetworkChangeCommit{Tenant: "tenant", Network: "alpha", Members: selected})
	if blocked.Code != state.Forbidden || read().State.Object(control.ResourcesKey) != reserved {
		t.Fatal("revoked target grant published or erased its original reservation", blocked)
	}
	for _, row := range old {
		candidate, exists := resources().Networks.Change("tenant", row.Network.ID)
		if !exists || candidate.Phase != tenancy.ChangeFenced || candidate.SourceClosed == nil || read().State.Object(row.BridgeKey).Present || read().State.Object(row.TunnelKey).Present {
			t.Fatal("denied target commit lost original fenced sources")
		}
	}
	catalog, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = catalog.Tenant("tenant")
	apply("e3-gateway/restore-target", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a", "node-b"}})
	// stopB joins the exact owned daemon handle. A management timeout is not
	// treated as evidence that the original process or its work has stopped.
	members, err := p.Members(read().State)
	if err != nil {
		t.Fatal(err)
	}
	member, exists := members.Entry("node-b")
	if !exists || member.Peer.Voter {
		t.Fatal("partial native fixture requires its original nonvoter owner")
	}
	stopB()
	apply("e3-gateway/commit", "commit-network-change", resources().Networks.Revision(), control.NetworkChangeCommit{Tenant: "tenant", Network: "alpha", Members: selected})
	var local tenancy.TUNSource
	for _, row := range rows("alpha") {
		if row.Network.Node == "node-a" {
			local = row
		}
	}
	if local.BridgeKey == "" || local.TunnelKey == "" {
		t.Fatal("partial native target lost its expected local member")
	}
	wait("partial new generation has a real local Bridge while peer is offline", func() bool {
		o, err := observe("node-a", local.BridgeKey)
		return err == nil && o.Ready && o.NativeID != "" && o.Generation > before[local.BridgeKey].Generation
	})
	partial, err := observe("node-a", local.TunnelKey)
	if err != nil || partial.Ready {
		t.Fatal("partial native target was reported as a ready bilateral TUN", partial, err)
	}
	for _, row := range rows("alpha") {
		if !read().State.Object(row.BridgeKey).Present || !read().State.Object(row.TunnelKey).Present {
			t.Fatal("offline owner erased the committed target source")
		}
	}
	startB()
	active := waitActive("alpha", before)
	for _, row := range rows("beta") {
		for _, key := range []string{row.BridgeKey, row.TunnelKey} {
			if read().State.Object(key) != before[key] {
				t.Fatal("alpha transition changed beta's committed native source", key)
			}
		}
	}
	for _, row := range rows("alpha") {
		for _, original := range old {
			if row.Network.Node == original.Network.Node && row.Network.Pools[0].Gateway != original.Network.Pools[0].Gateway.Next() {
				t.Fatal("atomic target did not publish the requested gateway")
			}
		}
	}
	startEchoes()
	probe()
	restartB()
	for _, row := range rows("alpha") {
		if row.Network.Node != "node-b" {
			continue
		}
		for _, key := range []string{row.BridgeKey, row.TunnelKey} {
			wait("same post-transition node DB/native generation after restart", func() bool {
				o, err := observe("node-b", key)
				return err == nil && o.Ready && o.NativeID == active[key].NativeID && o.Generation == active[key].Generation && o.Journal.LastID == active[key].Journal.LastID
			})
		}
	}
	probe()
	replay("e3-gateway/commit")
	replay("e3-gateway/blocked-commit")
	replay("e3-cancel/cancel")
	stopEchoes()

	full := tenancy.TUNDefinition{Tenant: "tenant", Name: "alpha", Members: []tenancy.TUNNode{}}
	var rebound tenancy.TUNNode
	for _, row := range rows("alpha") {
		member := tenancy.TUNNode{Node: row.Network.Node, Pools: row.Network.Pools, Addresses: row.Network.TunnelAddresses}
		full.Members = append(full.Members, member)
		if member.Node == "node-a" {
			rebound = member
			rebound.Node = "node-b"
		}
	}
	before = read().State.Objects(tenancy.ManagedNetworkSourcePrefix)
	shrinking := rows("alpha")
	selected = drain("e3-shrink", "alpha", false)
	apply("e3-shrink/commit", "reconfigure-tun-network", resources().Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: "alpha", Members: []tenancy.TUNNode{rebound}}, Members: selected})
	waitActive("alpha", before)
	if only := rows("alpha"); len(only) != 1 || only[0].Network.Node != "node-b" || only[0].Network.Pools[0].Prefix != rebound.Pools[0].Prefix || only[0].Tunnel != nil {
		t.Fatal("2→1 failed to rebind the original CIDR to its requested owner")
	}
	// Only removed keys are Closed; the retained node's Bridge is a new active
	// generation and must never be shadowed by its historical descriptor.
	for _, row := range shrinking {
		if row.Network.Node == "node-b" {
			row.BridgeKey = ""
		}
		waitClosed([]tenancy.TUNSource{row})
	}
	before = read().State.Objects(tenancy.ManagedNetworkSourcePrefix)
	selected = drain("e3-expand", "alpha", false)
	apply("e3-expand/commit", "reconfigure-tun-network", resources().Networks.Revision(), control.NetworkReconfigure{Target: full, Members: selected})
	waitActive("alpha", before)
	startEchoes()
	probe()
	stopEchoes()
	for _, name := range []string{"alpha", "beta"} {
		group := rows(name)
		selected = drain("e3-retire-"+name, name, false)
		apply("e3-retire-"+name+"/commit", "reconfigure-tun-network", resources().Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: name, Members: []tenancy.TUNNode{}}, Members: selected})
		waitClosed(group)
	}
	if len(resources().Networks.AllNetworks()) != 0 {
		t.Fatal("final explicit group retirement left active members")
	}
	t.Log("E3 real two-owner closure/fence, incomplete-peer commit rejection, atomic gateway generation, resumed kernel UDP/same-DB restart, CIDR owner rebind 2→1→2, final native/journal retirement; app stayed down during network changes")
}
