// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestCheckerPublicationReceiptIsImmutableAndLegacyCatalogEncodingUnchanged(t *testing.T) {
	store, _, _, key := cacheRetentionFixture(t)
	fact := stageRetentionSource(t, store, []byte("package checker\n"), sourcePolicy(), [32]byte{79})
	book := cacheRetentionCatalog(t, sourcePolicy(), fact, false)
	before, err := book.Encode()
	if err != nil {
		t.Fatal(err)
	}
	copy := book.clone()
	if err := copy.rememberPublication(fact); err != nil {
		t.Fatal(err)
	}
	replay, _ := copy.Encode()
	if !bytes.Equal(before, replay) {
		t.Fatal("same original allocated another receipt")
	}
	changed := fact.Clone()
	changed.Digest[0]++
	changed.Signature = ed25519.Sign(key, SourceFactBytes(changed))
	if changed.Verify() != nil {
		t.Fatal("invalid mutation fixture")
	}
	if err := copy.rememberPublication(changed); err == nil {
		t.Fatal("same upload ID changed content")
	}
	after, _ := book.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("receipt changed original catalog")
	}
	copy.d.Publications[publicationKey(fact.Tenant, fact.Owner, *fact.Upload)] = [32]byte{3}
	if copy.Validate() == nil {
		t.Fatal("snapshot accepted a different publication content")
	}
	if book.Validate() != nil {
		t.Fatal("clone aliases original receipt map")
	}
	legacy, err := NewCatalog([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(legacy.d)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"Publications"`)) {
		t.Fatal("legacy schema1 acquired optional metadata")
	}
	if _, err := DecodeCatalog(encoded); err != nil {
		t.Fatal(err)
	}
}
