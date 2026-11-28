// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// Deliberately invalid checkpoint payloads isolate whoami's root metadata from
// page loading. This is an immutable FSM fixture, not a DB/quorum/native proof.
func TestQueryReplyWhoamiUsesOriginalViewWithoutLoadingPages(t *testing.T) {
	current, err := state.New("fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{control.RegistriesKey, control.LifecycleKey, control.NodeStorageKey, control.ResourcesKey, control.VolumesKey, control.VaultKey, control.AppsKey, control.ExternalRegistriesKey}
	for i, key := range keys {
		for j := 0; j <= i; j++ {
			command := state.Command{Kind: state.Module, Actor: "fixture-admin", Epoch: 1, RequestID: fmt.Sprintf("%d-%d", i, j), Key: key, Expected: current.Object(key).Revision, Value: "fixture"}
			var result state.Result
			current, result, err = state.ApplyReduced(current, current.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
				return map[string][]byte{key: []byte(fmt.Sprintf("invalid-checkpoint-%d-%d", i, j))}, state.Applied
			})
			if err != nil || result.Code != state.Applied {
				t.Fatal(result, err)
			}
		}
	}
	original := cluster.View{State: current}
	svc := Service{Policy: control.Policy{Cluster: [32]byte{1}}}
	roots := rootsOf(original)
	for _, key := range keys {
		if roots[key] != original.State.Object(key).Revision || roots[key] == 0 {
			t.Fatal("whoami root mismatch", key, roots[key])
		}
	}
	command := state.Command{Kind: state.Module, Actor: "fixture-admin", Epoch: 1, RequestID: "later", Key: control.RegistriesKey, Expected: current.Object(control.RegistriesKey).Revision, Value: "fixture"}
	later, result, err := state.ApplyReduced(current, current.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{control.RegistriesKey: []byte("later-checkpoint")}, state.Applied
	})
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if rootsOf(original)[control.RegistriesKey] != roots[control.RegistriesKey] || rootsOf(cluster.View{State: later})[control.RegistriesKey] == roots[control.RegistriesKey] {
		t.Fatal("query assembly mixed committed views")
	}
	for _, tc := range []struct {
		name string
		call func(Request) Reply
	}{
		{"registries", func(r Request) Reply {
			_, code := methodRules["registries"].run(context.Background(), svc, original, access.Session{}, TenantPageQuery{Tenant: r.Tenant})
			return Reply{Schema: 1, Code: code}
		}},
		{"apps", func(r Request) Reply {
			return svc.appsQueryReply(original, access.Catalog{}, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.call(Request{Method: tc.name, Tenant: "tenant"}); got.Code != "unavailable" {
				t.Fatal("bad checkpoint became denied or successful", got.Code)
			}
		})
	}
}
