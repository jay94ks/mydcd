// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func volumeConflictDocument(app string, readOnly bool) []byte {
	return []byte(fmt.Sprintf("name: %s\nservices:\n  debug:\n    image: docker.io/library/php@sha256:%s\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.80.1.40}}\n    volumes: [{type: volume, source: data, target: /data, read_only: %t}]\n    x-sfc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\nvolumes:\n  data:\n    external: true\n    x-sfc: {node: node-a, uid: 10001, gid: 10001, mode: '0750'}\n", app, string(bytes.Repeat([]byte{'a'}, 64)), readOnly))
}

func TestStandaloneVolumePreflightRejectsCurrentForeignWriterWithoutReservation(t *testing.T) {
	for _, existingWriter := range []bool{false, true} {
		for _, wantedWriter := range []bool{false, true} {
			f := managedDNSTaskCoreFixture(t)
			scope := volumes.Scope{Cluster: f.p.Cluster, Tenant: "tenant", App: deployment.StandaloneScopeName("tenant", "debug"), ID: "data", Generation: 1}
			f.apply("standalone-data", "create-volume", 0, volumeFact(t, scope, "node-a", f.node), state.Applied)
			registry, err := f.p.Volumes(f.s)
			core, found := registry.Volume(scope)
			if err != nil || !found {
				t.Fatal("registered original Volume", err)
			}
			f.apply("unclosed-pin", "acquire-volume", core.Revision(), VolumeAcquire{Scope: scope, Consumer: "unclosed-original", Generation: 7, Writable: existingWriter}, state.Applied)
			before, _ := state.Encode(f.s)
			r := AppPlanRequest{Document: volumeConflictDocument("debug", !wantedWriter), Deployment: "deploy", Standalone: &StandaloneDefinition{Name: "debug", Mode: "entrypoint", Lifetime: "fixed"}}
			_, err = f.p.AppPlanArtifact(f.s, f.session, 10, "tenant", r)
			wantConflict := existingWriter || wantedWriter
			var input *deployment.InputError
			if wantConflict {
				if !errors.As(err, &input) || input.Code != "VOLUME_WRITER_CONFLICT" || input.Path != scope.Key() {
					t.Fatal("missing specific non-secret Volume diagnostic", existingWriter, wantedWriter, err)
				}
			} else if err != nil {
				t.Fatal("readers cannot coexist in preview", err)
			}
			after, _ := state.Encode(f.s)
			if !bytes.Equal(before, after) {
				t.Fatal("read-only plan acquired or released original resources")
			}
			denied := f.session
			denied.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
			denied.Signature = ed25519.Sign(f.node, access.SessionBytes(denied))
			if _, err := f.p.AppPlanArtifact(f.s, denied, 10, "tenant", r); !errors.Is(err, access.ErrDenied) {
				t.Fatal("Volume diagnostic bypassed current Deploy permission", err)
			}
		}
	}
}

func TestOrdinaryAppPlanRetainsExistingCoordinatedReplacementAdmission(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	f.apply("unknown-old-app-writer", "acquire-volume", f.core().Revision(), VolumeAcquire{Scope: f.scope, Consumer: "previous-task", Generation: 7, Writable: true}, state.Applied)
	before, _ := state.Encode(f.s)
	if _, err := f.p.AppPlanArtifact(f.s, f.session, 10, "tenant", AppPlanRequest{Document: volumeConflictDocument("app", false), Project: "app", Deployment: "deploy"}); err != nil {
		t.Fatal("standalone preview guard changed ordinary app replacement planning", err)
	}
	after, _ := state.Encode(f.s)
	if !bytes.Equal(before, after) {
		t.Fatal("ordinary app plan changed original consumer")
	}
}
