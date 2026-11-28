// SPDX-License-Identifier: Apache-2.0

package vps

import "testing"

// Managed and Owned vendors never mix: each lookup returns only its kind,
// and every shipped vendor sets exactly the constructor of its kind.
func TestVendorOwnership(t *testing.T) {
	for _, v := range Vendors() {
		switch v.Ownership {
		case Managed:
			if v.New == nil || v.NewOwned != nil {
				t.Fatalf("%s: managed vendor constructors", v.ID)
			}
			if _, ok := LookupManaged(v.ID); !ok {
				t.Fatalf("%s: not found as managed", v.ID)
			}
			if _, ok := LookupOwned(v.ID); ok {
				t.Fatalf("%s: found as owned", v.ID)
			}
		case Owned:
			if v.NewOwned == nil || v.New != nil {
				t.Fatalf("%s: owned vendor constructors", v.ID)
			}
			if _, ok := LookupManaged(v.ID); ok {
				t.Fatalf("%s: found as managed", v.ID)
			}
		default:
			t.Fatalf("%s: ownership %q", v.ID, v.Ownership)
		}
	}
	if _, ok := LookupManaged("iwinv"); !ok {
		t.Fatal("iwinv is managed")
	}
}

func TestVendorAcceptsCredential(t *testing.T) {
	signing := Vendor{ID: "s"}
	token := Vendor{ID: "t", TokenOnly: true}
	pair := Credential{AccessKey: "A", SecretKey: "S"}
	one := Credential{AccessKey: "TOKEN"}
	if !signing.Accepts(pair) || signing.Accepts(one) {
		t.Fatal("signing vendor needs both keys")
	}
	if !token.Accepts(one) || token.Accepts(pair) {
		t.Fatal("token vendor takes one token")
	}
	if signing.Accepts(Credential{}) || token.Accepts(Credential{}) {
		t.Fatal("empty credential")
	}
}
