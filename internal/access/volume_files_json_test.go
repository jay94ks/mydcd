// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestVolumeFileCeilingJSONPreservesLegacyAndExplicitEmpty(t *testing.T) {
	wide := []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/", Operations: []string{"volume-file-put"}}}
	for _, test := range []struct {
		name   string
		grants []VolumeFileGrant
	}{{"nil", nil}, {"empty", []VolumeFileGrant{}}, {"nonempty", wide}} {
		t.Run(test.name, func(t *testing.T) {
			credential := Credential{ID: "key", Method: PrivateKey, PublicKey: key(7), Enabled: true, Operations: []string{"volume-file-put"}, VolumeFiles: test.grants}
			public := PublicUserOf(User{Credentials: []Credential{credential}}).Credentials[0]
			// Defined types retain the prior struct tags/order and have no custom
			// marshal method. Nil/nonempty must keep those exact schema1 bytes.
			type legacyCredential Credential
			type legacyPublicCredential PublicCredential
			raw, err := json.Marshal(credential)
			if err != nil {
				t.Fatal(err)
			}
			publicRaw, err := json.Marshal(public)
			if err != nil {
				t.Fatal(err)
			}
			if test.name != "empty" {
				old, _ := json.Marshal(legacyCredential(credential))
				oldPublic, _ := json.Marshal(legacyPublicCredential(public))
				if !bytes.Equal(raw, old) || !bytes.Equal(publicRaw, oldPublic) {
					t.Fatal("existing credential JSON bytes changed")
				}
			} else if !bytes.Contains(raw, []byte(`"VolumeFiles":[]`)) || !bytes.Contains(publicRaw, []byte(`"VolumeFiles":[]`)) {
				t.Fatal("explicit empty ceiling omitted")
			}
			if test.name == "nil" && (bytes.Contains(raw, []byte(`"VolumeFiles"`)) || bytes.Contains(publicRaw, []byte(`"VolumeFiles"`))) {
				t.Fatal("legacy nil gained a field")
			}
			var stored Credential
			var projected PublicCredential
			if json.Unmarshal(raw, &stored) != nil || json.Unmarshal(publicRaw, &projected) != nil || (stored.VolumeFiles == nil) != (test.grants == nil) || (projected.VolumeFiles == nil) != (test.grants == nil) || !stored.Equal(credential) {
				t.Fatal("JSON roundtrip widened ceiling")
			}
		})
	}
}

func TestEmptyVolumeFileSourceAndApprovalCeilingsSurviveCatalogRoundtrip(t *testing.T) {
	operations := []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}
	wide := []VolumeFileGrant{{Tenant: "tenant", Volume: "backup", Prefix: "exports/", Operations: operations}}
	for _, role := range []Role{Manager, Viewer} {
		for _, limited := range []string{"source", "approval"} {
			t.Run(string(role)+"/"+limited, func(t *testing.T) {
				makeCatalog := func(empty bool) (Catalog, Session, Issuer) {
					c := tenant(t, enrolled(t), "tenant")
					public, private := signingKey(7)
					operator := user("operator", false)
					operator.Credentials[0].PublicKey = public
					operator.Credentials[0].Operations = operations
					operator.Credentials[0].VolumeFiles = wide
					source := Credential{ID: "token", Method: Token, VerifierRef: "protected-token", Enabled: true, Operations: operations, VolumeFiles: wide}
					if empty {
						if limited == "source" {
							source.VolumeFiles = []VolumeFileGrant{}
						} else {
							operator.Credentials[0].VolumeFiles = []VolumeFileGrant{}
						}
					}
					operator.Credentials = append(operator.Credentials, source)
					c = put(t, c, "admin", operator)
					c = member(t, c, "tenant", "operator", role, true)
					if role == Viewer {
						var err error
						c, err = c.SetVolumeFileGrant("admin", c.Revision(), VolumeFileFolderGrant{Tenant: "tenant", Volume: "backup", Prefix: "exports/", User: "operator"}, false)
						if err != nil {
							t.Fatal(err)
						}
					}
					session, issuer, _ := signedSession(c, "operator", "token", []Scope{{Tenant: "tenant", Actions: []Action{Read, ManageVolumes}}})
					approved, err := ApproveSession(session, private)
					if err != nil || c.VerifySession(approved, key(1), issuer, 100) != nil {
						t.Fatal("current approved session fixture", err)
					}
					return c, approved, issuer
				}
				baseline, allowed, issuer := makeCatalog(false)
				if baseline.AuthorizeVolumeFile(allowed, key(1), issuer, 100, "tenant", "", "backup", "exports/a", "volume-file-put", "") != nil {
					t.Fatal("positive authority/approval control denied")
				}
				c, session, issuer := makeCatalog(true)
				assertDenied := func(stage string, current Catalog) {
					t.Helper()
					if current.VerifySession(session, key(1), issuer, 100) != nil {
						t.Fatal("empty ceiling denial came from an invalid session", stage)
					}
					operator, _ := current.User("operator")
					id := "token"
					if limited == "approval" {
						id = "key"
					}
					found := false
					for _, credential := range operator.Credentials {
						if credential.ID == id {
							found = credential.VolumeFiles != nil && len(credential.VolumeFiles) == 0
						}
					}
					if !found {
						t.Fatal("empty ceiling became unrestricted nil", stage)
					}
					for _, operation := range operations {
						path := "exports/a"
						if operation == "volume-file-list" {
							path = "exports/"
						}
						if current.AuthorizeVolumeFile(session, key(1), issuer, 100, "tenant", "", "backup", path, operation, "") == nil {
							t.Fatal("empty source/approval ceiling bypassed", stage, operation)
						}
					}
					public := PublicUserOf(operator)
					raw, err := json.Marshal(public)
					if err != nil {
						t.Fatal(err)
					}
					var restored PublicUser
					if json.Unmarshal(raw, &restored) != nil {
						t.Fatal("public credential decode")
					}
					for _, credential := range restored.Credentials {
						if credential.ID == id && credential.VolumeFiles == nil {
							t.Fatal("public projection erased empty ceiling", stage)
						}
					}
				}
				assertDenied("put-user", c)
				cloned, err := c.clone()
				if err != nil {
					t.Fatal(err)
				}
				assertDenied("clone", cloned)
				raw, err := cloned.Encode()
				if err != nil {
					t.Fatal(err)
				}
				restored, err := Decode(raw)
				if err != nil {
					t.Fatal(err)
				}
				assertDenied("export-import", restored)
				again, err := restored.Encode()
				if err != nil || !bytes.Equal(raw, again) {
					t.Fatal("snapshot JSON not stable", err)
				}
			})
		}
	}
}
