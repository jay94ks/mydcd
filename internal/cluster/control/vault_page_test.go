// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/secrets"
)

// This is the actual public response formatter, reused by the SFCP service.
// Large ACL rows exceed a count-only page budget before reaching eight rows.
func TestVaultMetadataPagesUseWireByteBudgetAndStableCursor(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	defer clear(key)
	c, err := access.New([32]byte(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll([32]byte(key.Public().(ed25519.PublicKey)), access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(key.Public().(ed25519.PublicKey)), Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "tenant", 0)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := secrets.NewTree([32]byte{72}, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	acl := secrets.ACL{}
	for i := 0; i < 256; i++ {
		acl.Users = append(acl.Users, fmt.Sprintf("u%062d", i))
	}
	for i := 0; i < 12; i++ {
		tree, err = tree.Create(c, "admin", tree.Revision(), secrets.Object{ID: fmt.Sprintf("g%02d", i), Parent: "root", Kind: secrets.Group, ACL: acl})
		if err != nil {
			t.Fatal(err)
		}
	}
	v := Vault{Trees: map[string]secrets.Tree{"tenant": tree}}
	after := ""
	seen := map[string]bool{}
	pages := 0
	for {
		rows, next, err := v.Page(c, "admin", "tenant", after)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(rows)
		if len(raw) > 112<<10 || len(rows) > 8 {
			t.Fatal("wire budget exceeded", len(raw), len(rows))
		}
		if pages == 0 && (len(rows) >= 8 || next == "") {
			t.Fatal("count-only paging failed to exercise byte boundary")
		}
		for _, row := range rows {
			if row.Object == nil || seen[row.Object.ID] {
				t.Fatal("lost/duplicated row")
			}
			seen[row.Object.ID] = true
		}
		pages++
		if next == "" {
			break
		}
		if next <= after {
			t.Fatal("cursor did not advance")
		}
		after = next
	}
	if len(seen) != 13 || pages < 2 {
		t.Fatal("incomplete realm pages", len(seen), pages)
	}
}
