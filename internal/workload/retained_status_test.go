// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

type retainedStatusNative struct{}

func (retainedStatusNative) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}
func (retainedStatusNative) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}

func retainedStatusJournal(t *testing.T, path, key, spec string) {
	t.Helper()
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Desired(key, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Generation: 1, Present: true, Spec: spec}}, 4); err != nil {
		t.Fatal(err)
	}
	if err = j.Step(context.Background(), key, retainedStatusNative{}); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
}

// Only native outcomes/HTTP Inspect bytes are model inputs. Actual workload
// and network managers, the installed lineage selector, journals and consumer
// inspection are reused. The missing retained pin stops before Netlink I/O;
// this fixture does not claim a kernel Bridge or container is actually ready.
func retainedStatusFixture(t *testing.T) (*Manager, *network.Manager, *network.Manager, *startFixture, containerops.Target) {
	t.Helper()
	f := makeStartFixture(t)
	cluster := [32]byte{91}
	oldKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
	newKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	old, current := [32]byte(oldKey.Public().(ed25519.PublicKey)), [32]byte(newKey.Public().(ed25519.PublicKey))
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: cluster, Node: "node-a", Operation: "rotate", Old: old, New: current, Prepared: [32]byte{94}}
	proof.OldSignature = ed25519.Sign(oldKey, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(newKey, lifecycle.IdentityProofBytes(proof))
	f.spec.Node = engine.Owner(cluster, current)
	f.spec.BridgeOwner = engine.Owner(cluster, old)
	f.spec.ResourceKeys = []lifecycle.IdentityTransition{{Proof: proof, Index: 2, Revision: 2}}
	f.engine.Owner = f.spec.Node
	raw, err := json.Marshal(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	resource := reconcile.Resource{Generation: 1, Present: true, Spec: string(raw)}
	id, err := f.engine.Identity("container", "task", resource)
	if err != nil {
		t.Fatal(err)
	}
	f.native.Name = "/" + id.Name
	f.native.Config.Labels = id.Labels
	f.native.HostConfig.LogConfig.Type = "local"
	root := t.TempDir()
	currentPath, oldPath := filepath.Join(root, "current-network.db"), filepath.Join(root, "old-network.db")
	bridge := network.BridgeSpec{Schema: 1, Network: "original-net", Owner: f.spec.BridgeOwner, MTU: 1500, Pools: []network.Pool{{ID: "pool", Network: "original-net", Owner: f.spec.BridgeOwner, MTU: 1500, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Gateway: netip.MustParseAddr("192.0.2.1")}}}
	bridgeRaw, _ := json.Marshal(bridge)
	if _, err = network.DecodeBridge(string(bridgeRaw)); err != nil {
		t.Fatal(err)
	}
	retainedStatusJournal(t, oldPath, f.spec.Bridge, string(bridgeRaw))
	oldEngine := &engine.Client{Owner: f.spec.BridgeOwner, API: f.engine.API}
	oldManager, err := network.OpenManager(oldPath, oldEngine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = oldManager.Close() })
	currentManager, err := network.OpenManager(currentPath, f.engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = currentManager.Close() })
	if err = currentManager.AttachRetained(oldManager); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "workload.db")
	retainedStatusJournal(t, path, "task", string(raw))
	m, err := OpenManager(path, f.engine, currentManager)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	target := containerops.Target{Cluster: cluster, Owner: current, Binding: [32]byte{95}, Tenant: "tenant", App: "app", Service: "web", Node: "node-a", Instance: "task", Generation: 1, Revision: 1}
	return m, currentManager, oldManager, f, target
}

func TestRetainedBridgeStatusUsesOriginalConsumerJournal(t *testing.T) {
	m, current, old, f, _ := retainedStatusFixture(t)
	if selected := m.driver.taskNetworkManager(f.spec); selected != old {
		t.Fatal("selector lost exact retained manager")
	}
	if _, err := current.InspectConsumer(context.Background(), f.spec.Bridge, "missing", 1); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("current namespace unexpectedly contains original bridge", err)
	}
	before, err := m.View("task")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Status(context.Background(), "task"); !errors.Is(err, reconcile.ErrLease) || errors.Is(err, storage.ErrMissing) {
		t.Fatal("Status bypassed retained original consumer journal", err)
	}
	after, err := m.View("task")
	beforeRaw, _ := json.Marshal(before)
	afterRaw, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(beforeRaw, afterRaw) || f.starts != 0 || f.stops != 0 || f.removes != 0 {
		t.Fatal("readback recreated/replaced original workload", err)
	}
}

func TestRetainedBridgeDetailKeepsOriginalNetworkDriftBoundary(t *testing.T) {
	m, _, _, _, target := retainedStatusFixture(t)
	query := containerops.Query{Schema: 1, Kind: "inspect", Selection: containerops.Selection{App: "app", Service: "web"}, MaxBytes: 4096}
	// Before the fix both wrong/current missing and original missing-pin looked
	// like network drift. Distinguish the actual read target by supplying a
	// provider that counts forbidden fallback reads while returning the same
	// concrete original Manager from its installed Retained selector.
	current := m.driver.Network.(*network.Manager)
	provider := &retainedStatusProvider{current: current}
	m.driver.Network = provider
	result, err := m.ObserveContainerDetail(context.Background(), target, query, containerops.DetailDeclaration{})
	if err != nil || result.Detail == nil || !slices.Contains(result.Detail.Drift, "network") || provider.currentReads != 0 {
		t.Fatal("detail read wrong network namespace or hid actual drift", err, provider.currentReads)
	}
}

type retainedStatusProvider struct {
	current      *network.Manager
	currentReads int
}

func (p *retainedStatusProvider) Acquire(ctx context.Context, key, consumer string, g uint64) (network.BridgeLease, error) {
	return p.current.Acquire(ctx, key, consumer, g)
}
func (p *retainedStatusProvider) InspectConsumer(ctx context.Context, key, consumer string, g uint64) (network.BridgeLease, error) {
	p.currentReads++
	return p.current.InspectConsumer(ctx, key, consumer, g)
}
func (p *retainedStatusProvider) ReturnConsumer(key, consumer string, g uint64) error {
	return p.current.ReturnConsumer(key, consumer, g)
}
func (p *retainedStatusProvider) Retained(owner string) *network.Manager {
	if p.current != nil {
		return p.current.Retained(owner)
	}
	return nil
}

func TestRetainedBridgeTypedNilAndUnregisteredOwnerRejectSafely(t *testing.T) {
	m, _, _, f, target := retainedStatusFixture(t)
	// A resolver's typed nil must become a nil BridgeProvider. The same
	// parameters guard protects create/recovery, Status and native detail.
	m.driver.Network = &retainedStatusProvider{}
	if m.driver.taskNetworkManager(f.spec) != nil {
		t.Fatal("typed nil retained manager escaped as nonnil interface")
	}
	if _, _, err := m.driver.parameters("task", reconcile.Operation{Kind: reconcile.Apply, Target: reconcile.Resource{Generation: 1, Present: true, Spec: mustRetainedSpec(t, m)}}); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("foreign/missing retained owner admitted", err)
	}
	if _, err := m.Status(context.Background(), "task"); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("Status did not reject missing original manager", err)
	}
	query := containerops.Query{Schema: 1, Kind: "inspect", Selection: containerops.Selection{App: "app", Service: "web"}, MaxBytes: 4096}
	if _, err := m.ObserveContainerDetail(context.Background(), target, query, containerops.DetailDeclaration{}); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("detail did not reject missing original manager", err)
	}
}
func mustRetainedSpec(t *testing.T, m *Manager) string {
	t.Helper()
	r, err := m.View("task")
	if err != nil {
		t.Fatal(err)
	}
	return r.State.Applied.Spec
}
