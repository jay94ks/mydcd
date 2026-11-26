// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestBindingPermitRechecksSharedCurrentResources(t *testing.T) {
	f, owner, request := permitDecodeFixture(t)
	want, err := f.p.AppBindingPermit(f.s, owner, request)
	if err != nil {
		t.Fatal(err)
	}
	var goal deployment.GoalCommand
	if canonical([]byte(f.s.Object(request.Task.Key).Value), &goal) != nil {
		t.Fatal("original task")
	}
	var reference string
	for _, dep := range goal.Dependencies {
		if strings.HasPrefix(dep.Key, "network/reference/") {
			reference = dep.Key
			break
		}
	}
	if reference == "" {
		t.Fatal("fixture must exercise a borrowed management network")
	}
	for _, test := range []struct{ name, key string }{
		{"volume-catalog", VolumesKey},
		{"resources-and-quota", ResourcesKey},
		{"network-reference", reference},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Explicitly invalid committed input, not a mutation adapter. Apps,
			// Task and Binding remain identical to the previously granted call.
			var changed state.State
			if test.key == reference {
				var result state.Result
				changed, result, err = state.Apply(f.s, f.s.Index()+1, state.Command{Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: "invalid-reference-counterexample", Key: reference, Expected: f.s.Object(reference).Revision, Value: "invalid-current-resource"})
				if err != nil || result.Code != state.Applied {
					t.Fatal("construct explicit invalid reference input", result, err)
				}
			} else {
				changed = permitDecodeWrites(t, f.s, test.key, map[string][]byte{test.key: []byte("invalid-current-resource")})
			}
			if changed.Object(AppsKey) != f.s.Object(AppsKey) || changed.Object(request.Task.Key) != f.s.Object(request.Task.Key) {
				t.Fatal("counterexample changed the original task or Apps")
			}
			if _, err := f.p.AppBindingPermit(changed, owner, request); err == nil {
				t.Fatal("reused a previous resource/quota/reference grant")
			}
			got, err := f.p.AppBindingPermit(f.s, owner, request)
			if err != nil || got.Task != want.Task || got.ReadSet != want.ReadSet || got.MaxConsumers != want.MaxConsumers || !bytes.Equal(got.Binding, want.Binding) {
				t.Fatal("another current view contaminated the original read", err)
			}
		})
	}
}
