// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

type closedTUNModelDriver struct{ outcome reconcile.Outcome }

func (d closedTUNModelDriver) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return d.outcome, nil
}
func (d closedTUNModelDriver) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return d.outcome, nil
}

// Shared closure is an explicit model fact. Real temporary bbolt journals
// below contain missing/open/Unknown lifetimes; every case must reject before
// any TunnelDriver kernel inspection, native effect, fresh permit or pin return.
func TestClosedManagedTUNCannotEraseMissingOpenUnknownOrDifferentJournal(t *testing.T) {
	for _, mode := range []string{"missing", "desired", "applied", "pin", "unknown-remove", "different-floor", "present-source"} {
		t.Run(mode, func(t *testing.T) {
			_, ref, objects, _, _ := heldReferenceFixture(t, true)
			key := ref.ManagedSources[1].Source.Key
			spec, err := network.DecodeTunnel(objects[key].Value)
			if err != nil {
				t.Fatal(err)
			}
			s, err := state.New("fixture")
			if err != nil {
				t.Fatal(err)
			}
			for index := uint64(1); index <= 2; index++ {
				var value []byte
				if index == 1 || mode == "present-source" {
					value = []byte(objects[key].Value)
				}
				var result state.Result
				s, result, err = state.ApplyTransactional(s, index, state.Command{Kind: state.Module, Actor: "fixture", Epoch: 1, RequestID: string(rune('a' + index)), Key: "control/model-source", Expected: s.Object("control/model-source").Revision, Value: "model source"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
					return map[string][]byte{"control/model-source": []byte("fixed model root"), key: value}, state.Applied
				}, nil, nil, func(_ state.State, _ state.Command, keys []string) bool { return len(keys) == 1 && keys[0] == key })
				if err != nil || result.Code != state.Applied {
					t.Fatal("source model", result, err)
				}
			}
			path := filepath.Join(t.TempDir(), "tunnel.db")
			journal, err := reconcile.OpenJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode != "missing" {
				if err = journal.Desired(key, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: objects[key].Value}}, 2); err != nil {
					t.Fatal(err)
				}
				if mode == "applied" || mode == "pin" || mode == "unknown-remove" {
					if err = journal.Step(t.Context(), key, closedTUNModelDriver{reconcile.EffectApplied}); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "pin" {
					if _, err = journal.Borrow(key, "original", 1); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "different-floor" || mode == "unknown-remove" {
					floor := uint64(1)
					if mode == "different-floor" {
						floor = 2
					}
					if err = journal.Desired(key, reconcile.Desired{Revision: 2, Retiring: floor}, 2); err != nil {
						t.Fatal(err)
					}
					if mode == "unknown-remove" {
						_ = journal.Step(t.Context(), key, closedTUNModelDriver{reconcile.EffectUnknown})
						row, err := journal.Read(key)
						if err != nil || row.State.Pending == nil || row.State.Pending.Phase != reconcile.RecoveryRequired {
							t.Fatal("Unknown model did not retain original remove", err)
						}
					}
				}
			}
			if err = journal.Close(); err != nil {
				t.Fatal(err)
			}
			manager, err := network.OpenTunnelManager(path, spec.Owner)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = manager.Close() })
			before, beforeErr := manager.View(key)
			beforeBytes, _ := json.Marshal(before)
			r := &Runtime{Identity: &identity.Identity{Public: ref.Owner}, tunnel: &tunnelRuntime{manager: manager}}
			projection := control.ResourceProjection{ManagedSources: map[string]control.ManagedNetworkSource{key: {Network: tenancy.Network{Owner: ref.Owner}, Tunnel: &spec, Closed: &tenancy.NetworkClosure{NativeGone: true}}}}
			if err = r.reconcileClosedManagedTunnels(t.Context(), cluster.View{State: s}, projection); err == nil {
				t.Fatal("shared closure erased or adopted a different original journal")
			}
			after, afterErr := manager.View(key)
			afterBytes, _ := json.Marshal(after)
			if (beforeErr == nil) != (afterErr == nil) || !bytes.Equal(beforeBytes, afterBytes) {
				t.Fatal("failed closure changed original Desired/operation/floor/pins")
			}
		})
	}
}
