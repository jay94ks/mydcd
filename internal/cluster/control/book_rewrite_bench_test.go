// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// BenchmarkCatalogSmallChange measures one small user change (a trust rule
// added or removed) against a catalog of growing size (R17 B0). Today the
// whole control/access book is decoded, re-encoded and rewritten, and every
// book is validated again, so the cost follows the catalog, not the change.
func BenchmarkCatalogSmallChange(b *testing.B) {
	for _, users := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("users=%d", users), func(b *testing.B) {
			f, raw := catalogWithUsers(b, users)
			rule := access.TrustRule{Registry: "registry.example.test", Repository: "team/app"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := range b.N {
				catalog, err := f.p.Catalog(f.s)
				if err != nil {
					b.Fatal(err)
				}
				t, _ := catalog.Tenant("tenant")
				change := TrustChange{Tenant: "tenant", Add: []access.TrustRule{rule}}
				if i%2 == 1 {
					change = TrustChange{Tenant: "tenant", Remove: []access.TrustRule{rule}}
				}
				f.apply("manager", "set-trust", t.Revision, change, state.Applied)
			}
			b.ReportMetric(float64(len(raw)), "catalog-bytes")
		})
	}
}

// BenchmarkValidateUnrelated is the validation every command pays, whatever
// it touched: all books are decoded and checked again.
func BenchmarkValidateUnrelated(b *testing.B) {
	for _, users := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("users=%d", users), func(b *testing.B) {
			f, _ := catalogWithUsers(b, users)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if err := f.p.Validate(f.s, f.s, state.Command{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func catalogWithUsers(b *testing.B, users int) (*nodeStorageFixture, []byte) {
	f := newNodeStorageFixture(b)
	c := f.users
	for i := range users {
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i), byte(i >> 8), 7}, 32)[:32])
		id := fmt.Sprintf("user-%04d", i)
		var err error
		c, err = c.PutUser("admin", 0, access.User{ID: id, Username: id, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(key.Public().(ed25519.PublicKey)), Enabled: true}}})
		if err != nil {
			b.Fatal(err)
		}
		if c, err = c.SetMembership("admin", 0, access.Membership{Tenant: "tenant", User: id, Role: access.Viewer, Enabled: true}); err != nil {
			b.Fatal(err)
		}
	}
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		b.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
	f.users = c
	s := f.sessions["manager"]
	s.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.ManageTrust}}}
	s.Signature = ed25519.Sign(f.node, access.SessionBytes(s))
	f.sessions["manager"] = s
	raw, _ := c.Encode()
	return f, raw
}
