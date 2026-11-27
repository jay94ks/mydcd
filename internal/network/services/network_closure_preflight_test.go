// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestNetworkClosurePreflightReusesTheSameAddressAndReferenceFence(t *testing.T) {
	f := fixture(t)
	n, _ := f.n.Network("first", "lan")
	if !f.a.NetworkReferencesSettled(n) {
		t.Fatal("empty original network")
	}
	cfg := DNSConfig{Tenant: "first", ID: "dns", Network: "lan", Pool: "pool", Source: 1, Serial: 1, Enabled: true, Zone: "app.sfc.test.", TTL: 1, NegativeTTL: 1, QuerySeconds: 2, MaxQueries: 4, MaxCacheEntries: 2, MaxResponseBytes: 4096}
	a, ref, err := f.a.GrantDNSInstance(f.c, f.n, "admin", 0, cfg)
	if err != nil || a.NetworkReferencesSettled(n) {
		t.Fatal("empty names hid an original live DNS instance", err)
	}
	before := encode(t, a)
	if a.NetworkReferencesSettled(n) || !bytes.Equal(before, encode(t, a)) {
		t.Fatal("read-only preflight erased a live reference")
	}
	// Explicit model closure; this is not a native/socket/TTL observation.
	close := ReferenceClose{Cluster: a.Cluster(), Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: ref.Local.Owner, Boot: f.boot, At: 10, Native: "model-original", Fenced: true, Settled: true, TTLExpired: true}
	close.Signature = ed25519.Sign(f.key, ReferenceCloseBytes(close))
	a, err = a.ObserveReferenceClose(close, 10)
	if err != nil || !a.NetworkReferencesSettled(n) {
		t.Fatal("positive original closure did not settle its reference", err)
	}
	local, _ := source(f.n, f.n.Cluster(), "first", "lan", "pool")
	a, _, err = a.ReserveStatic("static-original", poolOwner(local), "first/lan", "first/lan/pool", 1, addr("10.42.0.10"))
	if err != nil || a.NetworkReferencesSettled(n) {
		t.Fatal("closed DNS hid an original static address", err)
	}
	empty := n
	empty.ID = ""
	if a.NetworkReferencesSettled(empty) {
		t.Fatal("preflight accepted an empty selection")
	}
}
