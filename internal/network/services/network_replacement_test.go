// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/tenancy"
)

func TestRetiredMembershipSourceMetadataUsesOriginalChangeValidation(t *testing.T) {
	f, _, _ := managedDNSFixture(t)
	n, found := f.n.NamedNetwork("first", "shared", "node-a")
	rows, err := f.n.TUNSources("first", "shared")
	if !found || err != nil {
		t.Fatal(err)
	}
	var descriptor []RetiredNativeSource
	for _, row := range rows {
		if row.Network.ID == n.ID {
			descriptor = []RetiredNativeSource{{Key: row.BridgeKey, Generation: 17, Revision: 31, Bridge: &row.Bridge}, {Key: row.TunnelKey, Generation: 18, Revision: 31, Tunnel: row.Tunnel}}
		}
	}
	target := n
	target.Generation, target.Revision = 0, 0
	f.n, err = f.n.PlanChange(f.c, "admin", n.Tenant, n.ID, "members", n.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	change, _ := f.n.Change(n.Tenant, n.ID)
	f.n, err = f.n.BeginChangeDrain(f.c, "admin", n.Tenant, n.ID, change.Generation, change.Revision)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := f.n.Network(n.Tenant, n.ID)
	change, _ = f.n.Change(n.Tenant, n.ID)
	close := tenancy.NetworkClosure{Cluster: f.n.Cluster(), Tenant: n.Tenant, Network: n.ID, Node: n.Node, Owner: n.Owner, Generation: n.Generation, Revision: current.Revision, NativeGone: true}
	close.Signature = ed25519.Sign(f.key, tenancy.NetworkClosureBytes(close))
	f.n, err = f.n.FenceChange(f.c, "admin", n.Tenant, n.ID, change.Generation, change.Revision, close)
	if err != nil {
		t.Fatal(err)
	}
	change, _ = f.n.Change(n.Tenant, n.ID)
	archive := RetiredNetwork{Network: current, ChangeGeneration: change.Generation, Closed: close, Change: &change, Sources: descriptor}
	if err := validateRetiredSources(f.n.Cluster(), archive); err != nil {
		t.Fatal("original exact metadata fixture", err)
	}
	for label, mutate := range map[string]func(*RetiredNetwork){
		"owner":     func(v *RetiredNetwork) { v.Sources[0].Bridge.Owner = "foreign" },
		"pool":      func(v *RetiredNetwork) { v.Sources[0].Bridge.Pools[0].MTU++ },
		"zero-gen":  func(v *RetiredNetwork) { v.Sources[0].Generation = 0 },
		"phase":     func(v *RetiredNetwork) { v.Change.Phase = tenancy.ChangeCommitted },
		"target":    func(v *RetiredNetwork) { v.Change.Target.ID = "other" },
		"signature": func(v *RetiredNetwork) { v.Change.SourceClosed.Signature = nil },
		"namespace": func(v *RetiredNetwork) { v.Sources[0].Key = "control/network-sources/bridge/other/shared/node-a" },
	} {
		raw, _ := json.Marshal(archive)
		var bad RetiredNetwork
		if err := json.Unmarshal(raw, &bad); err != nil {
			t.Fatal(err)
		}
		mutate(&bad)
		if validateRetiredSources(f.n.Cluster(), bad) == nil {
			t.Fatal("retired source accepted a changed original", label)
		}
	}
}
