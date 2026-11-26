// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/bootstrap"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestRQ12ManagedTUNCurrentKeysKeepOriginalNativeTraffic(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{managedNetwork: true, identityTraffic: true})
}
func TestRQ12CrossTenantRouteCurrentKeysKeepOriginalNativeTraffic(t *testing.T) {
	testManagedTwoNodeFixture(t, false, managedTwoNodeOptions{crossTenantRoute: true, identityTraffic: true})
}

// Reuses the already installed second daemon, original operation submitter,
// native namespace/Engine, packet probes and rollback. No new app or runner.
func prepareTrafficIdentityRotations(t *testing.T, ctx context.Context, a *Runtime, root, nodeConfig, manifest string, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool)) func(func()) {
	t.Helper()
	return func(probe func()) {
		t.Helper()
		cfg, err := config.LoadNode(nodeConfig)
		if err != nil {
			t.Fatal(err)
		}
		p := a.controlPolicy
		selected := read().State.Objects(tenancy.ManagedNetworkSourcePrefix)
		originalGoals := read().State.Objects("network/tun/")
		projection, err := p.ProjectResources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		originalEndpoints := projection.Addresses.Checkpoint().Allocations
		originalAuthority := projection.NetworkAuthority != nil
		var originalRefs []services.ReferenceConsumer
		if originalAuthority {
			originalRefs = projection.NetworkAuthority.RouteReferences()
		}
		for i := 0; i < 2; i++ {
			effective, _, err := bootstrap.Effective(cfg)
			if err != nil {
				t.Fatal(err)
			}
			old, err := identity.Load(effective.Node.IdentityDir)
			if err != nil {
				t.Fatal(err)
			}
			d, err := p.Members(read().State)
			entry, found := d.Entry("node-b")
			if err != nil || !found {
				t.Fatal(err)
			}
			operation := fmt.Sprintf("rotate-traffic-b-%d", i)
			change(operation, "rotate-node-identity", entry.Revision, control.NodeIdentityChange{ID: "node-b", Operation: operation})
			var next [32]byte
			wait("original second daemon installs current key without native redeployment", func() bool {
				d, err := p.Members(read().State)
				row, found := d.IdentityRotation("node-b", operation)
				if err != nil || !found || row.Phase != "Installed" || row.Proof == nil {
					return false
				}
				next = row.Proof.New
				record, err := bootstrap.Read(cfg)
				return err == nil && record.Root.Self.Key == next && next != old.Public && !d.MemberKey(old.Public) && d.WorkKey(next)
			})
			remote, known := a.Mesh.Peer(mydcp.Identity(next))
			if !known || !remote.Member {
				t.Fatal("current peer directory missing installed replacement")
			}
			if _, known := a.Mesh.Peer(mydcp.Identity(old.Public)); known {
				t.Fatal("old node key remained a transport fallback")
			}
			wait("positive current-key authenticated RPC before old-key rejection", func() bool {
				reply, err := cluster.CallManagement(ctx, a.Mesh, a.commandIdentity(), p.Cluster, remote, cluster.ManagementRequest{Method: "status", Latest: false})
				return err == nil && reply.Node == "node-b"
			})
			source, known := a.Mesh.Peer(mydcp.Identity(a.Identity.Public))
			if !known {
				t.Fatal("current source peer required")
			}
			source.Endpoint = "192.0.2.1:44101"
			obsolete, err := mydcp.NewTransport(old, p.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) { return source, key == source.Key })
			if err != nil {
				t.Fatal(err)
			}
			denied, cancel := context.WithTimeout(ctx, 2*time.Second)
			_, oldErr := cluster.CallManagement(denied, obsolete, old, p.Cluster, source, cluster.ManagementRequest{Method: "status", Latest: false})
			cancel()
			_ = obsolete.Close()
			clear(old.Private)
			if oldErr == nil {
				t.Fatal("old authenticated node key obtained a current management response")
			}
			// Caller waits for existing bilateral paths, then exercises actual kernel
			// packets/containers with unchanged endpoint IDs and original flow tokens.
			probe()
			after, err := p.ProjectResources(read().State)
			var afterRefs []services.ReferenceConsumer
			if after.NetworkAuthority != nil {
				afterRefs = after.NetworkAuthority.RouteReferences()
			}
			if err != nil || originalAuthority != (after.NetworkAuthority != nil) || !reflect.DeepEqual(selected, read().State.Objects(tenancy.ManagedNetworkSourcePrefix)) || !reflect.DeepEqual(originalGoals, read().State.Objects("network/tun/")) || !reflect.DeepEqual(originalEndpoints, after.Addresses.Checkpoint().Allocations) || !reflect.DeepEqual(originalRefs, afterRefs) {
				t.Fatal("identity switch replaced original native sources, endpoint IDs or route lifetimes", err)
			}
			raw, err := os.ReadFile(manifest)
			var record map[string]any
			if err != nil || json.Unmarshal(raw, &record) != nil {
				t.Fatal("owned identity rollback manifest", err)
			}
			record[fmt.Sprintf("identity_traffic_rotation_%d", i)] = map[string]any{"operation": operation, "old": old.Public, "current": next, "root": filepath.Dir(nodeConfig), "old_rpc_error": fmt.Sprint(oldErr)}
			raw, _ = json.Marshal(record)
			if err = os.WriteFile(manifest, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}
		// The current identity may lose WORK eligibility; original native sources
		// still exist for explicit retirement. Reuse the policy fence in the core
		// isolation counterexample instead of accepting a second native redeploy.
		before, _ := json.Marshal(selected)
		after, _ := json.Marshal(read().State.Objects(tenancy.ManagedNetworkSourcePrefix))
		if !bytes.Equal(before, after) {
			t.Fatal("traffic verification changed original management sources")
		}
	}
}

// Retire just the original two named management networks. This identity root
// reuses E3's proven drain/fence/reconfigure API without repeating its gateway
// changes, rebinds or creating any replacement native owner generation.
func retireTrafficIdentityNetworks(t *testing.T, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), observe func(string, string) (ModuleObservation, error)) {
	t.Helper()
	resources := func() control.Resources {
		t.Helper()
		r, err := p.Resources(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	for _, name := range []string{"alpha", "beta"} {
		group, err := resources().Networks.TUNSources("tenant", name)
		if err != nil || len(group) != 2 {
			t.Fatal("original identity TUN group", name, err)
		}
		for _, row := range group {
			target := row.Network
			target.Generation, target.Revision, target.PendingChange = 0, 0, 0
			target.Owner = [32]byte{}
			id := "identity-retire-" + name + "-" + row.Network.Node
			change(id+"-plan", "plan-network-change", row.Network.Revision, control.NetworkChangePlan{Tenant: "tenant", ID: row.Network.ID, Change: id, Target: target})
		}
		for _, row := range group {
			change("identity-drain-"+name+"-"+row.Network.Node, "drain-network", row.Network.Revision, control.NetworkSelection{Tenant: "tenant", ID: row.Network.ID})
		}
		var versions []tenancy.NetworkChangeVersion
		for _, row := range group {
			var proof tenancy.NetworkClosure
			wait("original rotated native Bridge/TUN closure "+name+"/"+row.Network.Node, func() bool {
				o, err := observe(row.Network.Node, row.BridgeKey)
				return err == nil && !o.Ready && len(o.Retirement) > 0 && json.Unmarshal(o.Retirement, &proof) == nil
			})
			pending, _ := resources().Networks.Change("tenant", row.Network.ID)
			change("identity-fence-"+name+"-"+row.Network.Node, "fence-network-change", pending.Revision, control.NetworkChangeFence{Tenant: "tenant", ID: row.Network.ID, Generation: pending.Generation, Closed: proof})
			pending, _ = resources().Networks.Change("tenant", row.Network.ID)
			versions = append(versions, tenancy.NetworkChangeVersion{Tenant: "tenant", ID: row.Network.ID, Generation: pending.Generation, Revision: pending.Revision})
		}
		change("identity-retire-"+name, "reconfigure-tun-network", resources().Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: "tenant", Name: name, Members: []tenancy.TUNNode{}}, Members: versions})
		wait("original rotated native terminal journals "+name, func() bool {
			for _, row := range group {
				for _, key := range []string{row.BridgeKey, row.TunnelKey} {
					o, err := observe(row.Network.Node, key)
					object := read().State.Object(key)
					if err != nil || o.Ready || object.Present || o.Journal.PendingID != 0 || o.Journal.Applied.Present || o.Journal.Desired.Present || o.Journal.Consumers != 0 || o.Journal.GenerationFloor != object.Generation {
						return false
					}
				}
			}
			return true
		})
	}
}
