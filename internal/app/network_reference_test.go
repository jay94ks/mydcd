// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// A2/A3 are real product cores; Applied/source rows below are explicit model
// inputs. This fixture performs no native inspect, DB, socket or quorum RPC.
func heldReferenceFixture(t *testing.T, withTunnel bool) ([32]byte, deployment.NetworkReference, map[string]state.Object, reconcile.Record, *reconcile.Record) {
	t.Helper()
	cluster, owner := [32]byte{61}, [32]byte{62}
	physical := hex.EncodeToString(cluster[:]) + "/" + hex.EncodeToString(owner[:])
	pool := tenancy.Subnet{ID: "pool", Prefix: netip.MustParsePrefix("10.201.0.0/24"), Gateway: netip.MustParseAddr("10.201.0.1"), MTU: 1280}
	b := network.BridgeSpec{Schema: 1, Network: "member-a", Owner: physical, MTU: 1280, Pools: []network.Pool{{ID: "pool", Network: "member-a", Owner: physical, Prefix: pool.Prefix, Gateway: pool.Gateway, MTU: pool.MTU}}}
	key := (tenancy.SourceIdentity{Kind: "bridge", Tenant: "tenant", Network: "services", Node: "node-a"}).Key()
	raw, _ := json.Marshal(b)
	ref := deployment.NetworkReference{Schema: 1, Tenant: "tenant", Network: "member-a", Node: "node-a", Owner: owner, Source: deployment.ObjectRef{Key: key, Generation: 17, Revision: 31}, CatalogGeneration: 1, CatalogRevision: 1, Spec: sha256.Sum256(raw), Pools: []tenancy.Subnet{pool}, RetainSource: true}
	objects := map[string]state.Object{key: {Present: true, Generation: 17, Revision: 31, Value: string(raw)}}
	record := func(source deployment.ObjectRef, raw []byte) reconcile.Record {
		t.Helper()
		s, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: source.Revision, Resource: reconcile.Resource{Present: true, Generation: source.Generation, Spec: string(raw)}})
		if err != nil {
			t.Fatal(err)
		}
		s, operation, err := reconcile.Plan(s)
		if err != nil || operation == nil {
			t.Fatal(err)
		}
		s, err = reconcile.Dispatch(s, operation.ID)
		if err == nil {
			s, err = reconcile.Settle(s, operation.ID, reconcile.EffectApplied)
		}
		if err != nil {
			t.Fatal(err)
		}
		leases, _ := reconcile.NewLeases(source.Generation, 2)
		pin, err := leases.Acquire()
		if err != nil {
			t.Fatal(err)
		}
		checkpoint := leases.Checkpoint()
		return reconcile.Record{Schema: 1, State: s, Pins: &checkpoint, Consumers: map[string]reconcile.Lease{"original": pin}, Capacity: 2}
	}
	bridge := record(ref.Source, raw)
	if !withTunnel {
		return cluster, ref, objects, bridge, nil
	}
	ref.ManagedName, ref.PacketNetwork = "services", tenancy.PacketNamespace("tenant", "services")
	ref.ManagedSources = append(ref.ManagedSources, deployment.NetworkSourceRef{Source: ref.Source, Spec: ref.Spec})
	spec := network.TunnelSpec{Schema: 1, Owner: physical, Network: ref.PacketNetwork, MTU: 1280, RouteMetric: 100, Addresses: []netip.Prefix{netip.MustParsePrefix("10.202.0.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("10.203.0.0/24")}}
	key = (tenancy.SourceIdentity{Kind: "tun", Tenant: "tenant", Network: "services", Node: "node-a"}).Key()
	raw, _ = json.Marshal(spec)
	source := deployment.ObjectRef{Key: key, Generation: 18, Revision: 32}
	objects[key] = state.Object{Present: true, Generation: source.Generation, Revision: source.Revision, Value: string(raw)}
	ref.ManagedSources = append(ref.ManagedSources, deployment.NetworkSourceRef{Source: source, Spec: sha256.Sum256(raw)})
	tunnel := record(source, raw)
	return cluster, ref, objects, bridge, &tunnel
}

func TestHeldNetworkReferenceUsesAllOriginalPinsWithoutMutatingThem(t *testing.T) {
	for _, withTunnel := range []bool{false, true} {
		cluster, ref, objects, bridge, tunnel := heldReferenceFixture(t, withTunnel)
		before, _ := json.Marshal([]any{bridge, tunnel, objects})
		held, err := heldAppNetworkReference(cluster, ref, "original", objects, bridge, tunnel)
		if err != nil || !held {
			t.Fatal("complete original pins were not retained", withTunnel, err)
		}
		if held, err = heldAppNetworkReference(cluster, ref, "new-consumer", objects, bridge, tunnel); err != nil || held {
			t.Fatal("inspection created a different consumer", err)
		}
		after, _ := json.Marshal([]any{bridge, tunnel, objects})
		if !bytes.Equal(before, after) {
			t.Fatal("inspection changed the original token/spec/source")
		}
	}
}

func TestHeldNetworkReferenceRejectsPendingDrainStoppedAndChangedIdentity(t *testing.T) {
	for label, mutate := range map[string]func(*reconcile.Record){
		"generation": func(r *reconcile.Record) { p := r.Consumers["original"]; p.Generation++; r.Consumers["original"] = p },
		"zero-token": func(r *reconcile.Record) { p := r.Consumers["original"]; p.Token = 0; r.Consumers["original"] = p },
		"revision":   func(r *reconcile.Record) { r.State.Desired.Revision++ },
		"spec":       func(r *reconcile.Record) { r.State.Applied.Spec += " " },
		"Drain":      func(r *reconcile.Record) { r.State.Desired.Resource = reconcile.Resource{} },
		"Stopped":    func(r *reconcile.Record) { r.State.Stopped = true },
		"Unknown": func(r *reconcile.Record) {
			r.State.Pending = &reconcile.Operation{ID: 2, Kind: reconcile.Remove, Phase: reconcile.RecoveryRequired, Target: r.State.Applied}
		},
	} {
		cluster, ref, objects, bridge, tunnel := heldReferenceFixture(t, true)
		mutate(&bridge)
		if held, err := heldAppNetworkReference(cluster, ref, "original", objects, bridge, tunnel); err == nil || held {
			t.Fatal("held inspection accepted a different/pending source", label, err)
		}
	}
}

func TestHeldNetworkReferenceNeedsMissingDependencyAdmissionAndExactPeerRows(t *testing.T) {
	cluster, ref, objects, bridge, tunnel := heldReferenceFixture(t, true)
	if held, err := heldAppNetworkReference(cluster, ref, "original", objects, bridge, nil); err != nil || held {
		t.Fatal("partial Bridge pin manufactured a TUN borrow", err)
	}
	tunnel.Consumers = map[string]reconcile.Lease{}
	if held, err := heldAppNetworkReference(cluster, ref, "original", objects, bridge, tunnel); err != nil || held {
		t.Fatal("lost TUN pin was treated as held", err)
	}
	for key := range objects {
		changed := maps.Clone(objects)
		o := changed[key]
		o.Revision++
		changed[key] = o
		if held, err := heldAppNetworkReference(cluster, ref, "original", changed, bridge, tunnel); err == nil || held {
			t.Fatal("inspection adopted another original/peer source", key, err)
		}
	}
}

func TestReportedNetworkReferenceCannotReborrowAfterOriginalPinLoss(t *testing.T) {
	for _, applied := range []bool{false, true} {
		clusterID, ref, objects, _, _ := heldReferenceFixture(t, false)
		s, err := state.New("fixture")
		if err != nil {
			t.Fatal(err)
		}
		value := objects[ref.Source.Key].Value
		command := state.Command{Kind: state.Module, Actor: "fixture", Epoch: 1, RequestID: "original-source", Key: ref.Source.Key, Value: "injected source"}
		var result state.Result
		s, result, err = state.ApplyReduced(s, 1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
			return map[string][]byte{ref.Source.Key: []byte(value)}, state.Applied
		})
		if err != nil || result.Code != state.Applied {
			t.Fatal("original source fixture", result, err)
		}
		o := s.Object(ref.Source.Key)
		ref.Source.Generation, ref.Source.Revision = o.Generation, o.Revision
		manager, err := network.OpenManager(filepath.Join(t.TempDir(), "network.db"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = manager.Close() })
		r := &Runtime{network: manager, Identity: &identity.Identity{Public: ref.Owner}, controlPolicy: control.Policy{Cluster: clusterID}}
		raw, _ := json.Marshal(ref)
		goal := deployment.GoalCommand{Schema: 1, Cluster: clusterID, Tenant: ref.Tenant, App: "app", Deployment: "deploy", Kind: "network-ref", Node: ref.Node, Owner: ref.Owner, Config: raw}
		raw, _ = json.Marshal(goal)
		stage := deployment.StageRecord{Command: &state.Command{Value: string(raw)}, Result: &state.Result{Code: state.Applied, Revision: 2, Generation: 2}, Observation: &deployment.Observation{Applied: applied, Native: "borrow/original"}}
		if native, err := r.acquireAppNetworkReference(t.Context(), cluster.View{State: s}, stage, false); !errors.Is(err, reconcile.ErrLease) || native != "" || len(manager.Keys()) != 0 {
			t.Fatal("reported borrow was recreated or reached fresh RPC/native use", native, err)
		}
		stage.Observation, stage.Noop = nil, true
		if native, err := r.acquireAppNetworkReference(t.Context(), cluster.View{State: s}, stage, true); !errors.Is(err, reconcile.ErrLease) || native != "" || len(manager.Keys()) != 0 {
			t.Fatal("retiring noop recreated a lost borrow before first target observation", native, err)
		}
	}
}
