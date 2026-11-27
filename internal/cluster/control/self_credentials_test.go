// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func TestSelfCredentialInputPreservesOwnFieldsAndRejectsAccountReplacement(t *testing.T) {
	for _, tc := range []struct {
		action  string
		payload any
	}{
		{"add-credential", access.CredentialAddition{User: "alice", Credential: access.CredentialKey{ID: "browser", Method: access.PrivateKey, PublicKey: [32]byte{1}}, Label: "browser", Challenge: [32]byte{2}, Proof: []byte{3}}},
		{"disable-credential", access.CredentialDisable{User: "alice", Credential: "browser"}},
	} {
		t.Run(tc.action, func(t *testing.T) {
			payload, _ := json.Marshal(tc.payload)
			raw, _ := json.Marshal(ChangeDocument{Schema: 1, Action: tc.action, Expected: 7, Payload: payload})
			got, err := InputChange(raw, "alice")
			if err != nil || got.Action != tc.action || got.Principal != "alice" || got.Expected != 7 || string(got.Payload) != string(payload) || CommandKey(got.Action) != CatalogKey {
				t.Fatal("self input changed", err)
			}
			var fields map[string]any
			_ = json.Unmarshal(payload, &fields)
			fields["SystemAdmin"] = true
			bad, _ := json.Marshal(fields)
			raw, _ = json.Marshal(ChangeDocument{Schema: 1, Action: tc.action, Expected: 7, Payload: bad})
			if _, err = InputChange(raw, "alice"); err == nil {
				t.Fatal("self action accepted account replacement fields")
			}
		})
	}
}
