// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
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
	assemble := func(view cluster.View) Reply {
		reply := Reply{Schema: 1, Code: "ok"}
		request := Request{Method: "whoami"}
		session := access.Session{}
		catalog := access.Catalog{}
		reply = svc.registryQueryReply(view, session, request, reply)
		reply = svc.lifecycleQueryReply(view, session, request, reply)
		reply = svc.storageQueryReply(view, catalog, session, request, reply)
		reply = svc.resourcesQueryReply(view, catalog, session, request, reply)
		reply = svc.volumesQueryReply(view, catalog, session, request, reply)
		reply = svc.vaultQueryReply(view, catalog, session, request, reply)
		return svc.appsQueryReply(view, catalog, session, request, reply)
	}
	reply := assemble(original)
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"Schema": float64(1), "Code": "ok", "RootRevision": float64(0)}
	names := []string{"RegistriesRootRevision", "LifecycleRootRevision", "NodeStorageRootRevision", "ResourcesRootRevision", "VolumesRootRevision", "VaultRootRevision", "AppsRootRevision", "ExternalRegistriesRootRevision"}
	for i, name := range names {
		want[name] = float64(original.State.Object(keys[i]).Revision)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("whoami JSON shape/root mismatch: got %s want %v", raw, want)
	}
	command := state.Command{Kind: state.Module, Actor: "fixture-admin", Epoch: 1, RequestID: "later", Key: control.RegistriesKey, Expected: current.Object(control.RegistriesKey).Revision, Value: "fixture"}
	later, result, err := state.ApplyReduced(current, current.Index()+1, command, nil, func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{control.RegistriesKey: []byte("later-checkpoint")}, state.Applied
	})
	if err != nil || result.Code != state.Applied {
		t.Fatal(result, err)
	}
	if assemble(original).RegistriesRootRevision != reply.RegistriesRootRevision || assemble(cluster.View{State: later}).RegistriesRootRevision == reply.RegistriesRootRevision {
		t.Fatal("query assembly mixed committed views")
	}
	for _, tc := range []struct {
		name string
		call func(Request) Reply
	}{
		{"registries", func(r Request) Reply {
			return svc.registryQueryReply(original, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
		{"lifecycles", func(r Request) Reply {
			return svc.lifecycleQueryReply(original, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
		{"node-storage", func(r Request) Reply {
			return svc.storageQueryReply(original, access.Catalog{}, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
		{"resources", func(r Request) Reply {
			return svc.resourcesQueryReply(original, access.Catalog{}, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
		{"volumes", func(r Request) Reply {
			return svc.volumesQueryReply(original, access.Catalog{}, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
		}},
		{"vault", func(r Request) Reply {
			return svc.vaultQueryReply(original, access.Catalog{}, access.Session{}, r, Reply{Schema: 1, Code: "ok"})
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
