// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Use the actual operation signing and raw payload representation, including
// the typed put-user payload decode used by the management reducer.
func TestVolumeFileCeilingOriginalOperationJSONAndSignature(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{23}, ed25519.SeedSize))
	var public [32]byte
	copy(public[:], private.Public().(ed25519.PublicKey))
	cluster := [32]byte{1}
	wide := []access.VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/", Operations: []string{"volume-file-put"}}}
	for _, test := range []struct {
		name   string
		grants []access.VolumeFileGrant
	}{{"nil", nil}, {"empty", []access.VolumeFileGrant{}}, {"nonempty", wide}} {
		t.Run(test.name, func(t *testing.T) {
			user := access.User{ID: "operator", Username: "operator", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public, Enabled: true, Operations: []string{"volume-file-put"}, VolumeFiles: test.grants}}}
			payload, err := json.Marshal(user)
			if err != nil {
				t.Fatal(err)
			}
			session := access.Session{Schema: 1, ID: "original-session", Cluster: cluster, User: "admin", Credential: "key", AccountRevision: 1, Key: public, Issuer: public, IssuerEpoch: 1, IssuedAt: 100, ExpiresAt: 200, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.ManageCredentials}}}}
			session.Signature = ed25519.Sign(private, access.SessionBytes(session))
			operation := control.UserOperation{Schema: 1, Session: session, At: 101, Epoch: 1, RequestID: "original-user-ceiling", RootRevision: 1, Change: control.Change{Schema: 1, Action: "put-user", Principal: session.User, Payload: payload}}
			original := control.OperationBytes(operation)
			operation.Signature = ed25519.Sign(private, original)
			if operation.VerifyOriginal(cluster) != nil {
				t.Fatal("original signed operation invalid")
			}
			raw, err := json.Marshal(operation)
			if err != nil {
				t.Fatal(err)
			}
			var restored control.UserOperation
			if json.Unmarshal(raw, &restored) != nil || restored.VerifyOriginal(cluster) != nil || !bytes.Equal(original, control.OperationBytes(restored)) {
				t.Fatal("operation JSON changed original signature bytes")
			}
			var received access.User
			if json.Unmarshal(restored.Change.Payload, &received) != nil || !received.Credentials[0].Equal(user.Credentials[0]) || (received.Credentials[0].VolumeFiles == nil) != (test.grants == nil) {
				t.Fatal("signed typed payload widened ceiling")
			}
			canonical, err := json.Marshal(received)
			if err != nil || !bytes.Equal(canonical, restored.Change.Payload) {
				t.Fatal("typed payload lost canonical original bytes", err)
			}
			if test.name == "empty" {
				if !bytes.Contains(restored.Change.Payload, []byte(`"VolumeFiles":[]`)) {
					t.Fatal("original payload omitted empty ceiling")
				}
				received.Credentials[0].VolumeFiles = nil
				restored.Change.Payload, _ = json.Marshal(received)
				if restored.VerifyOriginal(cluster) == nil {
					t.Fatal("empty ceiling removed without invalidating original signature")
				}
			}
		})
	}
}
