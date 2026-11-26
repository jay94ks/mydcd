// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"maps"
	"testing"

	"github.com/jay94ks/mydcd/internal/tenancy"
)

// Product references and PlanChange, with a purely in-memory catalog/source
// fixture. Native lifetime/permission is not established by these tests.
func TestNetworkReferenceCandidatePreservesOnlyTheExactAcceptedSource(t *testing.T) {
	f, c, ctx, source := externalFixture(t)
	ref, err := resolveNetworkReference(ctx, "tenant", "node-a", "shared-lan", NetworkBinding{"shared-lan", source})
	if err != nil {
		t.Fatal(err)
	}
	original, _ := ctx.Networks.Network("tenant", ref.Network)
	target := original
	target.Generation, target.Revision = 0, 0
	target.Pools = append([]tenancy.Subnet(nil), target.Pools...)
	target.Pools[0].Gateway = mustAddr("10.240.10.2")
	ctx.Networks, err = ctx.Networks.PlanChange(f.c, "alice", "tenant", ref.Network, "change-gateway", original.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := ctx.Networks.Encode()
	if ref.CheckRetained(ctx) != nil || ref.Check(ctx) == nil {
		t.Fatal("retained identity and fresh admission were conflated")
	}
	if _, err := Compile(c, f.c, ctx); err == nil {
		t.Fatal("new app borrowed a changing network")
	}
	for label, mutate := range map[string]func(*NetworkReference){
		"generation": func(r *NetworkReference) { r.CatalogGeneration++ },
		"revision":   func(r *NetworkReference) { r.CatalogRevision++ },
		"owner":      func(r *NetworkReference) { r.Owner[0]++ },
		"pool":       func(r *NetworkReference) { r.Pools[0].Gateway = target.Pools[0].Gateway },
		"name":       func(r *NetworkReference) { r.ManagedName = "other" },
	} {
		raw, _ := json.Marshal(ref)
		var bad NetworkReference
		_ = json.Unmarshal(raw, &bad)
		mutate(&bad)
		if bad.CheckRetained(ctx) == nil {
			t.Fatal("candidate bypassed original", label)
		}
	}
	for _, field := range []string{"generation", "revision", "value", "missing"} {
		changed := ctx
		changed.Current = maps.Clone(ctx.Current)
		o := changed.Current[source]
		switch field {
		case "generation":
			o.Generation++
		case "revision":
			o.Revision++
		case "value":
			o.Value += " "
		case "missing":
			o.Present = false
		}
		changed.Current[source] = o
		if ref.CheckRetained(changed) == nil {
			t.Fatal("candidate adopted changed source", field)
		}
	}
	after, _ := ctx.Networks.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("read-only reference checks mutated the reservation")
	}
}

func TestManagedNetworkCandidateStopsGroupAdmissionAndRetainsAllOriginalPeers(t *testing.T) {
	f, c, ctx := managedNetworkFixture(t)
	b, err := CompileApp(c, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	var refs []NetworkReference
	for _, step := range b.Steps() {
		if step.Kind == "network-ref" {
			var ref NetworkReference
			if json.Unmarshal(step.Goal, &ref) != nil {
				t.Fatal("original reference")
			}
			refs = append(refs, ref)
		}
	}
	if len(refs) != 2 {
		t.Fatal("two-node fixture required")
	}
	original, _ := ctx.Networks.Network("tenant", refs[0].Network)
	target := original
	target.Generation, target.Revision = 0, 0
	ctx.Networks, err = ctx.Networks.PlanChange(f.c, "alice", "tenant", original.ID, "change-member", original.Revision, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if ref.CheckRetained(ctx) != nil || ref.Check(ctx) == nil {
			t.Fatal("local/remote candidate lost retained/fresh distinction", ref.Node)
		}
		for _, frozen := range ref.ManagedSources {
			changed := ctx
			changed.Current = maps.Clone(ctx.Current)
			o := changed.Current[frozen.Source.Key]
			o.Revision++
			changed.Current[frozen.Source.Key] = o
			if ref.CheckRetained(changed) == nil {
				t.Fatal("retained reference ignored changed peer", frozen.Source.Key)
			}
		}
	}
	if b.ValidateCurrent(f.c, ctx) == nil {
		t.Fatal("stored artifact granted a new operation during a candidate")
	}
	ctx.Networks, err = ctx.Networks.Drain(f.c, "alice", "tenant", original.ID, original.Revision)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if ref.CheckRetained(ctx) == nil {
			t.Fatal("retained validation bypassed group Drain", ref.Node)
		}
	}
}
