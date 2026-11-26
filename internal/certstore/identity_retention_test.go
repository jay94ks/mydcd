// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/storage"
)

// Actual bbolt/wallet envelopes and reopen: the master key and the upload
// receipt open only with the installation identity that stored them.
func TestMasterAndReceiptRequireOriginalIdentityAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	old := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{26}, 32))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	native := Native{DB: db, Cluster: [32]byte{1}, Identity: old}
	if err = native.GenerateMaster(); err != nil {
		t.Fatal(err)
	}
	master, err := native.Master()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	material := certificateMaterial(t, []string{"app.test"}, 10, 500)
	defer material.Clear()
	in, _ := Inspect(material.Chain, 20)
	key, _ := Derive(master, in.Metadata.ID)
	defer clear(key)
	v, err := native.Prepare("admin", "original", 20, material, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	native.DB = db
	replacement := native
	replacement.Identity = next
	if _, err = replacement.Master(); err == nil {
		t.Fatal("new identity decrypted the old master envelope")
	}
	if _, err = replacement.Recover("admin", "original"); err == nil {
		t.Fatal("new identity reinterpreted old receipt owner")
	}
	recovered, err := native.Recover("admin", "original")
	if err != nil || recovered.Digest() != v.Digest() || !bytes.Equal(recovered.SealedKey, v.SealedKey) {
		t.Fatal("original recovery replaced immutable receipt", err)
	}
	again, err := native.Master()
	if err != nil || !bytes.Equal(again, master) {
		t.Fatal("master changed across reopen", err)
	}
	clear(again)
	if _, err = Open(v, key); err != nil {
		t.Fatal(err)
	}
}
