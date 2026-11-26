// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/containerops"
)

func TestContainerObservationTargetsCurrentUserAndExactOwner(t *testing.T) {
	f, _, _, consumer, provider := checkerProbePermitFixture(t)
	q := containerops.Query{Schema: 1, Selection: containerops.Selection{App: "first", Service: "beta"}, Kind: "top", MaxBytes: 16384}
	target, err := f.p.ContainerTarget(f.s, f.session, 10, "tenant", q)
	if err != nil || target.Owner != provider || target.Service != "beta" || target.NativeID == "" {
		t.Fatal("valid target", target, err)
	}
	read := ContainerRead{Session: f.session, Query: q, Target: target}
	if _, err = f.p.ContainerReadPermit(f.s, provider, read, 10); err != nil {
		t.Fatal("exact owner denied", err)
	}
	if _, err = f.p.ContainerReadPermit(f.s, consumer, read, 10); err == nil {
		t.Fatal("another member became provider")
	}
	for _, change := range []func(*ContainerRead){func(r *ContainerRead) { r.Target.Generation++ }, func(r *ContainerRead) { r.Target.NativeID = "different" }, func(r *ContainerRead) { r.Target.Tenant = "other" }, func(r *ContainerRead) { r.Target.Binding = [32]byte{99} }, func(r *ContainerRead) { r.Query.Selection.Instance = "native-id" }} {
		copy := read
		change(&copy)
		if _, err = f.p.ContainerReadPermit(f.s, provider, copy, 10); err == nil {
			t.Fatal("altered target admitted")
		}
	}
	for _, tenant := range []string{"", "other"} {
		if _, err = f.p.ContainerTarget(f.s, f.session, 10, tenant, q); err == nil {
			t.Fatal("foreign/missing tenant admitted")
		}
	}
	limited := f.session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
	// Fixture's session issuer is the original node-a key, restored by helper.
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	if _, err = f.p.ContainerTarget(f.s, limited, 10, "tenant", q); err == nil {
		t.Fatal("system admin bypassed missing Read ceiling")
	}
	expired := f.session
	expired.ExpiresAt = 9
	expired.Signature = ed25519.Sign(f.node, access.SessionBytes(expired))
	if _, err = f.p.ContainerTarget(f.s, expired, 10, "tenant", q); err == nil {
		t.Fatal("expired user read admitted")
	}
}
