// SPDX-License-Identifier: Apache-2.0

package access

import (
	"bytes"
	"testing"
)

// The row form decodes to the same catalog as the whole-catalog form, and
// applying only the changed rows to the previous catalog gives the same
// catalog as decoding every row.
func TestCatalogRows(t *testing.T) {
	steps := []func(Catalog) Catalog{
		func(c Catalog) Catalog { return tenant(t, c, "first") },
		func(c Catalog) Catalog { return put(t, c, "admin", user("alice", false)) },
		func(c Catalog) Catalog { return member(t, c, "first", "alice", Manager, true) },
		func(c Catalog) Catalog {
			v, _ := c.Tenant("first")
			n, err := c.ChangeTrust("admin", "first", v.Revision, []TrustRule{{"private.example", "team/php"}}, nil)
			return must(t, n, err)
		},
		func(c Catalog) Catalog {
			u, _ := c.User("alice")
			n, err := c.RevokeSession("admin", "alice", "s1", u.Revision)
			return must(t, n, err)
		},
		func(c Catalog) Catalog { return member(t, c, "first", "alice", Viewer, false) },
	}
	c := enrolled(t)
	check := func(c Catalog) {
		t.Helper()
		meta, rows, err := c.Rows()
		if err != nil {
			t.Fatal(err)
		}
		d, err := DecodeRows(meta, rows)
		if err != nil {
			t.Fatal("decode rows", err)
		}
		a, _ := c.Encode()
		b, _ := d.Encode()
		if !bytes.Equal(a, b) {
			t.Fatal("rows changed the catalog")
		}
	}
	check(c)
	for i, step := range steps {
		next := step(c)
		meta, changed, err := next.ChangedRows(c)
		if err != nil {
			t.Fatal(err)
		}
		_, all, _ := next.Rows()
		if len(changed) == 0 || len(changed) >= len(all) && len(all) > 3 {
			t.Fatal(i, "changed rows", len(changed), "of", len(all))
		}
		applied, err := c.ApplyRows(meta, changed)
		if err != nil {
			t.Fatal(i, "apply rows", err)
		}
		a, _ := next.Encode()
		b, _ := applied.Encode()
		if !bytes.Equal(a, b) {
			t.Fatal(i, "applied rows differ from the catalog")
		}
		check(next)
		c = next
	}
	meta, rows, _ := c.Rows()
	for key := range rows {
		bad := map[string][]byte{}
		for k, v := range rows {
			bad[k] = v
		}
		bad[key+"x"] = bad[key]
		delete(bad, key)
		if _, err := DecodeRows(meta, bad); err == nil {
			t.Fatal("row under the wrong key", key)
		}
		bad = map[string][]byte{}
		for k, v := range rows {
			bad[k] = v
		}
		bad[key] = append([]byte(" "), rows[key]...)
		if _, err := DecodeRows(meta, bad); err == nil {
			t.Fatal("non-canonical row", key)
		}
	}
	if _, err := c.ApplyRows(meta, map[string][]byte{"u/nobody": nil}); err == nil {
		t.Fatal("removed a missing row")
	}
}
