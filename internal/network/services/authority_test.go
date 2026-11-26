// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"net/netip"
	"testing"
)

type networkFixture struct {
	a    Authority
	c    access.Catalog
	n    tenancy.Networks
	key  ed25519.PrivateKey
	boot [32]byte
}

func private(seed byte) ed25519.PrivateKey {
	b := make([]byte, 32)
	b[0] = seed
	return ed25519.NewKeyFromSeed(b)
}
func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }
func addr(s string) netip.Addr          { return netip.MustParseAddr(s) }
func fixture(t *testing.T) networkFixture {
	t.Helper()
	key := private(31)
	c, err := access.New(pub(key))
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Enroll(pub(key), access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: pub(key), Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.CreateTenant("admin", "first", 0)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("first")
	c, err = c.SetNodes("admin", "first", tenant.Revision, []string{"node-a"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := tenancy.New([32]byte{4})
	if err != nil {
		t.Fatal(err)
	}
	n, err = n.Create(c, "admin", n.Revision(), tenancy.Network{Tenant: "first", ID: "lan", Node: "node-a", Owner: pub(key), Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.42.0.0/24"), Gateway: addr("10.42.0.1"), MTU: 1500}}})
	if err != nil {
		t.Fatal(err)
	}
	book, err := n.AddressPlan(16)
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewAuthority(n.Cluster(), book)
	if err != nil {
		t.Fatal(err)
	}
	return networkFixture{a: a, c: c, n: n, key: key, boot: [32]byte{8}}
}
func encode(t *testing.T, a Authority) []byte {
	t.Helper()
	b, err := a.Encode()
	if err != nil {
		t.Fatal("invalid candidate", err)
	}
	return b
}
func TestAuthorityStaticBookPreservesOwnerAddressAndGeneration(t *testing.T) {
	f := fixture(t)
	before := encode(t, f.a)
	a, alloc, err := f.a.ReserveStatic("task", poolOwner(Source{Owner: pub(f.key)}), "first/lan", "first/lan/pool", 1, addr("10.42.0.128"))
	if err != nil || !bytes.Equal(before, encode(t, f.a)) {
		t.Fatal("static candidate", err)
	}
	if _, _, err = a.ReserveStatic("another", alloc.Owner, "first/lan", alloc.Pool, 1, alloc.Address); err == nil {
		t.Fatal("duplicate address")
	}
	restored, err := DecodeAuthority(encode(t, a))
	if err != nil || restored.book.Count() != 1 {
		t.Fatal("static recovery", err)
	}
	if _, _, err = restored.ReserveStatic("foreign", "other", "first/lan", alloc.Pool, 2, addr("10.42.0.129")); err == nil {
		t.Fatal("foreign pool owner")
	}
}
func TestAuthorityRejectsLegacyDHCPStateWithoutErasingIt(t *testing.T) {
	f := fixture(t)
	original := encode(t, f.a)
	for _, field := range []string{"Services", "Clients", "Leases"} {
		var obj map[string]json.RawMessage
		json.Unmarshal(original, &obj)
		obj[field] = json.RawMessage(`[{"legacy":"retained"}]`)
		raw, _ := json.Marshal(obj)
		if _, err := DecodeAuthority(raw); err == nil {
			t.Fatal("DHCP state silently adopted", field)
		}
	}
	if !bytes.Equal(original, encode(t, f.a)) {
		t.Fatal("rejected legacy state mutated live Authority")
	}
}
