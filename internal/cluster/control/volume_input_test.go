// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

func TestVolumeManagementInputPreservesSignedFactAndRejectsPrivateFields(t *testing.T) {
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
	fact := volumeFact(t, volumes.Scope{Cluster: [32]byte{78}, Tenant: "tenant", App: "app", ID: "data", Generation: 1}, "node-a", node)
	for _, input := range []struct {
		action  string
		payload any
	}{{"create-volume", fact}, {"acquire-volume", VolumeAcquire{Scope: fact.Spec.Scope, Consumer: "database", Generation: 1, Writable: true}}, {"release-volume", volumes.Gone{Scope: fact.Spec.Scope}}} {
		payload, _ := json.Marshal(input.payload)
		raw, _ := json.Marshal(ChangeDocument{Schema: 1, Action: input.action, Expected: 3, Payload: payload})
		change, err := InputChange(raw, "current-manager")
		if err != nil || change.Principal != "current-manager" || change.Expected != 3 || !bytes.Equal(change.Payload, payload) || CommandKey(change.Action) != VolumesKey {
			t.Fatal("typed volume intent", input.action, err)
		}
		if input.action == "create-volume" {
			for _, field := range []string{`"Mountpoint":"/host/private",`, `"PrivateKey":"secret",`, `"Password":"secret",`} {
				bad := strings.Replace(string(raw), `"Spec":{`, `"Spec":{`+field, 1)
				if _, err = InputChange([]byte(bad), "current-manager"); err == nil {
					t.Fatal("private/host field accepted", field)
				}
			}
		}
	}
}
