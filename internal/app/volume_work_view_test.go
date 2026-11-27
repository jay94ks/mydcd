// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func TestVolumeWorkUsesEachCurrentViewBeforeNativeDispatch(t *testing.T) {
	shared, err := state.New("anchor")
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{controlPolicy: control.Policy{Cluster: [32]byte{1}, TrustRoot: [32]byte{2}}}
	view := cluster.View{State: shared, Local: true}
	// A blank cluster has no work. Disabled native adapters are not permission
	// to skip the next view's registry validation or reuse this empty result.
	if err := r.reconcileVolumeWork(context.Background(), view); err != nil {
		t.Fatal("blank cluster", err)
	}
	command := state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "invalid-volume-root", Key: control.VolumesKey, Value: "counterexample"}
	damaged, result, err := state.ApplyReduced(shared, shared.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{control.VolumesKey: []byte("{}")}, state.Applied
	})
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if err := r.reconcileVolumeWork(context.Background(), cluster.View{State: damaged, Local: true}); !errors.Is(err, control.ErrCatalog) {
		t.Fatal("damaged current registry accepted before native dispatch", err)
	}
	if err := r.reconcileVolumeWork(context.Background(), view); err != nil {
		t.Fatal("a later view contaminated the original immutable view", err)
	}
}
