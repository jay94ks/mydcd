// SPDX-License-Identifier: Apache-2.0

package access

import (
	"reflect"
	"testing"
)

func TestCredentialConvenienceCandidatesPreserveOtherCredentialsAndAccountFields(t *testing.T) {
	u := user("admin", true)
	u.Revision = 42
	u.Credentials = append(u.Credentials, Credential{ID: "password", Method: Password, VerifierRef: "original-backend", Enabled: true})
	before := u
	before.Credentials = append([]Credential(nil), u.Credentials...)
	added, err := u.WithPrivateKey("laptop", key(9))
	if err != nil || added.Revision != 0 || added.ID != u.ID || added.Username != u.Username || !added.SystemAdmin || !added.Enabled || len(added.Credentials) != 3 || !reflect.DeepEqual(added.Credentials[:2], u.Credentials) {
		t.Fatal("key add replaced other account data", err)
	}
	disabled, err := added.WithPrivateKeyDisabled("laptop")
	if err != nil || disabled.Credentials[2].Enabled || !reflect.DeepEqual(disabled.Credentials[:2], u.Credentials) || !reflect.DeepEqual(before, u) || !added.Credentials[2].Enabled {
		t.Fatal("key disable changed another credential/candidate", err)
	}
	for _, change := range []struct {
		id string
		pk [32]byte
	}{{"laptop", key(10)}, {"other", key(9)}, {"", key(11)}, {"zero", [32]byte{}}} {
		if _, err := added.WithPrivateKey(change.id, change.pk); err == nil {
			t.Fatal("duplicate/invalid credential accepted", change.id)
		}
	}
	for _, id := range []string{"missing", "password", "laptop"} {
		if _, err := disabled.WithPrivateKeyDisabled(id); err == nil {
			t.Fatal("non-key/missing/already disabled credential accepted", id)
		}
	}
	if _, err := user("admin", true).WithPrivateKeyDisabled("key"); err == nil {
		t.Fatal("last authentication credential removed")
	}
}
