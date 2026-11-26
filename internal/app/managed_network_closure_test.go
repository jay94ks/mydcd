// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// Extends the existing owned single-node Engine/Bridge/CLI fixture at its final
// native boundary. It inherits that fixture's baseline, finite context and
// independent rollback. This is not a multiple-member/global closure test.
func verifyManagedNetworkClosureObservation(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), key string, user userauth.Client, peer mydcp.Peer, session access.Session, root string) {
	t.Helper()
	v := read()
	projection, err := p.ProjectResources(v.State)
	if err != nil {
		t.Fatal("closure preflight resource projection", err)
	}
	source := projection.ManagedSources[key]
	// The preceding app recovery test revoked node placement before down.
	// Original cleanup still succeeds, but this test now needs a NEW native
	// borrow and a NEW management candidate. Explicitly restore that owner's
	// placement through the same signed CAS instead of bypassing admission.
	catalog, err := p.Catalog(v.State)
	tenant, exists := catalog.Tenant(source.Network.Tenant)
	if err != nil || !exists || source.Network.Node == "" {
		t.Fatal("closure preflight current tenant/node", err)
	}
	if !slices.Contains(tenant.AllowedNodes, source.Network.Node) {
		change("restore-closure-node", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: tenant.ID, Nodes: append(slices.Clone(tenant.AllowedNodes), source.Network.Node)})
		v = read()
		projection, err = p.ProjectResources(v.State)
		if err != nil {
			t.Fatal("closure restored placement projection", err)
		}
		source = projection.ManagedSources[key]
		t.Log("restored original owner placement by explicit CAS before fresh closure-test borrow")
	}
	raw, err := r.observeManaged(ctx, key, v)
	var active ModuleObservation
	if err != nil || json.Unmarshal(raw, &active) != nil || !active.Ready || len(active.Retirement) != 0 {
		t.Fatal("active network manufactured a closure", string(raw), err)
	}
	// Keep one exact native borrow across Drain so the public pending counters
	// come from the owner's real journal, then return that original pin.
	if _, err := r.network.Acquire(ctx, key, "rq10-closure-read", active.Generation); err != nil {
		t.Fatal("closure fresh native borrow", err)
	}
	returned := false
	defer func() {
		if !returned {
			if err := r.network.ReturnConsumer(key, "rq10-closure-read", active.Generation); err != nil {
				t.Error(err)
			}
		}
	}()
	target := source.Network
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	target.Owner = [32]byte{}
	target.Pools = append([]tenancy.Subnet(nil), target.Pools...)
	target.Pools[0].Gateway = target.Pools[0].Gateway.Next()
	change("reserve-managed-network-change", "plan-network-change", source.Network.Revision, control.NetworkChangePlan{Tenant: source.Network.Tenant, ID: source.Network.ID, Change: "replace-managed-network", Target: target})
	change("drain-managed-network", "drain-network", source.Network.Revision, control.NetworkSelection{Tenant: source.Network.Tenant, ID: source.Network.ID})
	wait("user closure exposes original pending native borrow", func() bool {
		page := readNativePublicPage(t, ctx, user, peer, session, "network-closure", source.Network.Tenant, control.PublicReadQuery{Name: source.Network.ID})
		if len(page.Rows) != 1 || page.Rows[0].Closure == nil {
			return false
		}
		status := page.Rows[0].Closure
		return status.State == "pending" && status.Closure == nil && status.PendingPins != nil && *status.PendingPins > 0
	})
	if err := r.network.ReturnConsumer(key, "rq10-closure-read", active.Generation); err != nil {
		t.Fatal(err)
	}
	returned = true
	var observed ModuleObservation
	var proof tenancy.NetworkClosure
	wait("original managed Bridge Gone and signed owner closure", func() bool {
		v = read()
		raw, err = r.observeManaged(ctx, key, v)
		if err != nil || json.Unmarshal(raw, &observed) != nil || len(observed.Retirement) == 0 {
			return false
		}
		return json.Unmarshal(observed.Retirement, &proof) == nil
	})
	projection, err = p.ProjectResources(v.State)
	drained := projection.ManagedSources[key]
	n := drained.Network
	if err != nil || observed.Ready || !n.Draining || !v.State.Object(key).Present || proof.Cluster != p.Cluster || proof.Tenant != n.Tenant || proof.Network != n.ID || proof.Node != n.Node || proof.Owner != r.Identity.Public || proof.Generation != n.Generation || proof.Revision != n.Revision || !proof.NativeGone || proof.PendingEndpoints != 0 || proof.PendingFlows != 0 || proof.PendingPins != 0 || !ed25519.Verify(r.Identity.Public[:], tenancy.NetworkClosureBytes(proof), proof.Signature) {
		t.Fatal("owner closure does not match the exact original drained member", proof, err)
	}
	ownerTarget := control.NetworkReadTarget{Network: n, Source: deployment.ObjectRef{Key: key, Generation: observed.Generation, Revision: observed.Revision}}
	ownerRead, readErr := r.networkClosureRead(ctx, ownerTarget)
	if readErr != nil || ownerRead.State != "closed" || ownerRead.Closure == nil || !ownerTarget.VerifyClosure(p.Cluster, *ownerRead.Closure) {
		t.Fatal("public owner read lost original signed closure", ownerRead, readErr)
	}
	page := readNativePublicPage(t, ctx, user, peer, session, "network-closure", n.Tenant, control.PublicReadQuery{Name: n.ID})
	if len(page.Rows) != 1 || page.Rows[0].Closure == nil || page.Rows[0].Closure.State != "closed" || page.Rows[0].Closure.Closure == nil || !ownerTarget.VerifyClosure(p.Cluster, *page.Rows[0].Closure.Closure) {
		t.Fatal("real user session did not receive exact owner closure", page)
	}
	// 'mydc network update' reads the same User closure; the old raw CLI
	// read is gone.
	proof = *page.Rows[0].Closure.Closure // Existing real fence consumes the exact User result.
	if proof.Generation == observed.Generation && proof.Revision == observed.Revision {
		t.Fatal("fixture must distinguish logical network and native source ordinals")
	}
	if native, err := r.network.Inspect(ctx, key); err == nil || native != "" {
		t.Fatal("closure coexists with an Applied native Bridge", native, err)
	}
	stale := n
	stale.Revision++
	if wrong, err := r.managedNetworkClosure(ctx, v, projection, stale); err == nil || wrong != nil {
		t.Fatal("owner signed a different management revision", wrong, err)
	}
	resources, err := p.Resources(v.State)
	candidate, found := resources.Networks.Change(n.Tenant, n.ID)
	if err != nil || !found || candidate.Phase != tenancy.ChangeDraining {
		t.Fatal("original reserved candidate did not enter Drain", err)
	}
	change("fence-managed-network-change", "fence-network-change", candidate.Revision, control.NetworkChangeFence{Tenant: n.Tenant, ID: n.ID, Generation: candidate.Generation, Closed: proof})
	resources, err = p.Resources(read().State)
	closed, found := resources.Networks.Change(n.Tenant, n.ID)
	if err != nil || !found || closed.Phase != tenancy.ChangeFenced || closed.SourceClosed == nil || !ed25519.Verify(r.Identity.Public[:], tenancy.NetworkClosureBytes(*closed.SourceClosed), closed.SourceClosed.Signature) || closed.SourceClosed.Revision != proof.Revision {
		t.Fatal("actual owner closure was not retained by the shared fence", err)
	}
	tombstone := read().State.Object(key)
	if tombstone.Present || tombstone.Generation != active.Generation {
		t.Fatal("closed source did not preserve its native generation floor")
	}
	change("commit-managed-network-change", "commit-network-change", resources.Networks.Revision(), control.NetworkChangeCommit{Tenant: n.Tenant, Network: n.Logical, Members: []tenancy.NetworkChangeVersion{{Tenant: n.Tenant, ID: n.ID, Generation: closed.Generation, Revision: closed.Revision}}})
	var targetObservation ModuleObservation
	wait("new committed managed Bridge generation actually Ready", func() bool {
		v = read()
		raw, err = r.observeManaged(ctx, key, v)
		return err == nil && json.Unmarshal(raw, &targetObservation) == nil && targetObservation.Ready
	})
	object := v.State.Object(key)
	if !object.Present || object.Generation <= active.Generation || targetObservation.NativeID == "" || targetObservation.NativeID == active.NativeID || targetObservation.Generation != object.Generation || len(targetObservation.Retirement) != 0 {
		t.Fatal("new target reused the original native instance", targetObservation)
	}
	apps, err := p.Apps(v.State)
	authority, _, known := apps.NetworkDNS(r.Identity.Public)
	archived, retained := authority.RetiredNetwork(n.Tenant, n.ID, n.Generation)
	if err != nil || !known || !retained || archived.Closed.Revision != proof.Revision {
		t.Fatal("native recreation lost the original closure/archive", err)
	}
	t.Log("E3 reserved candidate -> original Bridge Gone -> signed observe/shared fence+tombstone -> atomic target/archive commit -> actual new native generation Ready; app remains down, group member add/remove not claimed")
	verifyManagedNetworkFinalRetirement(t, ctx, r, p, read, change, wait, key)
}

func verifyManagedNetworkFinalRetirement(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), key string, retainedNetworks ...int) {
	t.Helper()
	expectedNetworks := 0
	if len(retainedNetworks) > 1 || len(retainedNetworks) == 1 && retainedNetworks[0] < 0 {
		t.Fatal("explicit retained network baseline required")
	}
	if len(retainedNetworks) == 1 {
		expectedNetworks = retainedNetworks[0]
	}
	v := read()
	projection, err := p.ProjectResources(v.State)
	if err != nil {
		t.Fatal(err)
	}
	original := projection.ManagedSources[key].Network
	target := original
	target.Generation, target.Revision, target.PendingChange = 0, 0, 0
	change("plan-final-network-retirement", "plan-network-change", original.Revision, control.NetworkChangePlan{Tenant: original.Tenant, ID: original.ID, Change: "final-network-retirement", Target: target})
	verifyPlannedManagedNetworkRetirement(t, ctx, r, p, read, change, wait, key, original, expectedNetworks)
}

// The plan is accepted while the owner admits new work. An isolating/removing
// owner then consumes only its already-accepted drain/fence/empty-member work.
func verifyPlannedManagedNetworkRetirement(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), key string, original tenancy.Network, expectedNetworks int) {
	t.Helper()
	v := read()
	projection, err := p.ProjectResources(v.State)
	if err != nil {
		t.Fatal(err)
	}
	change("drain-final-network-retirement", "drain-network", original.Revision, control.NetworkSelection{Tenant: original.Tenant, ID: original.ID})
	var closure tenancy.NetworkClosure
	wait("final original Bridge native closure", func() bool {
		v = read()
		raw, err := r.observeManaged(ctx, key, v)
		var o ModuleObservation
		return err == nil && json.Unmarshal(raw, &o) == nil && len(o.Retirement) > 0 && json.Unmarshal(o.Retirement, &closure) == nil
	})
	resources, _ := p.Resources(v.State)
	selection, _ := resources.Networks.Change(original.Tenant, original.ID)
	change("fence-final-network-retirement", "fence-network-change", selection.Revision, control.NetworkChangeFence{Tenant: original.Tenant, ID: original.ID, Generation: selection.Generation, Closed: closure})
	resources, _ = p.Resources(read().State)
	selection, _ = resources.Networks.Change(original.Tenant, original.ID)
	change("retire-complete-network", "reconfigure-tun-network", resources.Networks.Revision(), control.NetworkReconfigure{Target: tenancy.TUNDefinition{Tenant: original.Tenant, Name: original.Logical, Members: []tenancy.TUNNode{}}, Members: []tenancy.NetworkChangeVersion{{Tenant: original.Tenant, ID: original.ID, Generation: selection.Generation, Revision: selection.Revision}}})
	wait("retired source remains bound to its terminal local journal", func() bool {
		v = read()
		projection, err = p.ProjectResources(v.State)
		row, localErr := r.network.View(key)
		return err == nil && localErr == nil && len(projection.Resources.Networks.AllNetworks()) == expectedNetworks && projection.ManagedSources[key].Closed != nil && !v.State.Object(key).Present && row.State.Desired.Revision >= v.State.Object(key).Revision && row.State.Pending == nil && !row.State.Applied.Present && !row.State.Desired.Present && len(row.Consumers) == 0
	})
	raw, err := r.observeManaged(ctx, key, v)
	var retired ModuleObservation
	if err != nil || json.Unmarshal(raw, &retired) != nil || retired.Ready || len(retired.Retirement) == 0 {
		t.Fatal("retired network lost its original closed observation", string(raw), err)
	}
	t.Log("E3 explicit empty membership -> same shared archive -> terminal original local journal/closed observe; no active group/native recreated")
}
