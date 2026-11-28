// SPDX-License-Identifier: Apache-2.0

package server

import (
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

func TestVaultScreenPaths(t *testing.T) {
	got := vaultViews("shop", []secrets.Object{
		{ID: "app", Parent: "shop", Kind: secrets.Group, Revision: 2, ACL: secrets.ACL{Users: []string{"u2", "u1"}}},
		{ID: "db", Parent: "app", Kind: secrets.Secret, Revision: 3, Reference: secrets.Reference{Profile: "main", Keys: []string{"pw", "user"}}},
		{ID: "shop", Kind: secrets.Group, Revision: 1},
	})
	paths := map[string]sfc.VaultView{}
	for _, v := range got {
		paths[v.Path] = v
	}
	if r, ok := paths["shop"]; !ok || r.Parent != "shop" || r.Kind != "group" {
		t.Fatalf("root %+v", got)
	}
	if g := paths["app"]; g.Parent != "shop" || !slices.Equal(g.ACL.Users, []string{"u1", "u2"}) {
		t.Fatalf("group %+v", g)
	}
	if o := paths["app/db"]; o.Kind != "object" || o.Profile != "main" || len(o.Keys) != 2 || o.Revision != 3 {
		t.Fatalf("object %+v", got)
	}
}
