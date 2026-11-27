// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

// access.Credential's MarshalJSON only keeps sfcd's stored bytes; the view
// is camelCase, keys hex, and an empty VolumeFiles (deny all) stays [] while
// nil (no ceiling) is left out.
func TestCamelCredentialRows(t *testing.T) {
	k := [32]byte{1}
	for _, tc := range []struct {
		v    any
		want []string
		not  []string
	}{
		{access.Credential{ID: "key-1", Method: access.PrivateKey, PublicKey: k, Enabled: true},
			[]string{`"id":"key-1"`, `"method":"private-key"`, `"publicKey":"01000000`}, []string{`"ID"`, `volumeFiles`}},
		{access.Credential{ID: "key-1", VolumeFiles: []access.VolumeFileGrant{}}, []string{`"volumeFiles":[]`}, nil},
		{access.PublicCredential{ID: "pw", Method: access.Password, VolumeFiles: []access.VolumeFileGrant{}}, []string{`"id":"pw"`, `"volumeFiles":[]`}, nil},
		{access.PublicCredential{ID: "pw"}, []string{`"id":"pw"`}, []string{`volumeFiles`}},
	} {
		b, err := camelJSON(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range tc.want {
			if !strings.Contains(string(b), w) {
				t.Fatalf("%s: want %s", b, w)
			}
		}
		for _, w := range tc.not {
			if strings.Contains(string(b), w) {
				t.Fatalf("%s: unexpected %s", b, w)
			}
		}
	}
}
