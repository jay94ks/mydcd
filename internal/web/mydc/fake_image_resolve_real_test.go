// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// REQ-31 in mydcd's real shape: every result passes
// control.ImageResolveResult.ValidQuery, untrusted refs are never "asked".
func TestResolveImageReal(t *testing.T) {
	f, _ := newTestFake(t)
	f.SetIdleTimeout(0)
	alice := passwordLogin(t, f, "alice", "alice")
	resolve := func(ref string) control.ImageResolveResult {
		t.Helper()
		q := control.ImageResolveQuery{Ref: ref}
		r, err := alice.ResolveImage(ctx, "shop", q)
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if !r.ValidQuery(q) {
			t.Fatalf("%s: not a valid result %+v", ref, r)
		}
		return r
	}
	for _, tc := range []struct{ ref, kind, source, code string }{
		{"registry.mydc.local/shop/php-shop:1.4.2", "managed", "builtin", "OK"},
		{"registry.mydc.local/shop/php-shop:9.9.9", "managed", "builtin", "NOT_FOUND"},
		{"mysql:8.4", "unknown", "", "OK"},
		{"docker.io/library/mysql:missing", "unknown", "", "NOT_FOUND"},
		{"nginx", "unknown", "", "UNTRUSTED"},
		{"registry.example.com/shop/cron:1", "external", "example", "OK"},
		{"registry.example.com/shop/other:1", "external", "example", "UNTRUSTED"},
		// Untrusted: the failing host is not asked, so no UNAUTHORIZED.
		{"private.example.com/team/app:1", "unknown", "", "UNTRUSTED"},
		{"Not A Ref", "unknown", "", "INVALID_IMAGE"},
	} {
		r := resolve(tc.ref)
		if r.Kind != tc.kind || r.Source != tc.source || r.Code != tc.code {
			t.Fatalf("%s: %s/%s %s", tc.ref, r.Kind, r.Source, r.Code)
		}
		if tc.code == "OK" && (r.Image == nil || r.Image.Digest == "") || tc.code != "OK" && r.Image != nil {
			t.Fatalf("%s: image %+v", tc.ref, r.Image)
		}
		if tc.code == "UNTRUSTED" && (r.Trust.Trusted || len(r.Trust.Rules) == 0) {
			t.Fatalf("%s: trust %+v", tc.ref, r.Trust)
		}
	}
	if r := resolve("registry.mydc.local/shop/php-shop:stable"); r.Image.Pinned != "registry.mydc.local/shop/php-shop@"+r.Image.Digest {
		t.Fatalf("pinned %+v", r.Image)
	}
	if r := resolve("mysql:8.4"); r.Normalized != "docker.io/library/mysql:8.4" || len(r.Image.Platforms) != 2 || r.Image.Platforms[0].Platform == nil {
		t.Fatalf("index %+v", r.Image)
	}
	if r := resolve("registry.example.com/shop/cron:1"); len(r.Image.Platforms) != 0 || r.Image.MediaType != fakeImageManifestType {
		t.Fatalf("manifest %+v", r.Image)
	}

	// Trusted hosts that fail.
	tv, _ := alice.SelectTenant(ctx, "shop")
	rules := append(slices.Clone(f.w.trust["shop"]), TrustRule{Registry: "private.example.com", Repository: "**"}, TrustRule{Registry: "unreachable.example.com", Repository: "**"})
	if _, res := submit(t, alice, ActionSetTrust, tv.Revision, control.TrustAssignment{Tenant: "shop", Rules: rules}, rootFor(t, alice, ActionSetTrust)); res.Code != ResultApplied {
		t.Fatalf("set-trust %+v", res)
	}
	if r := resolve("private.example.com/team/app:1"); r.Code != "UNAUTHORIZED" || !r.Trust.Trusted {
		t.Fatalf("auth %+v", r)
	}
	if r := resolve("unreachable.example.com/x:1"); r.Code != "UNAVAILABLE" {
		t.Fatalf("unreachable %+v", r)
	}

	// The external source's reader and record.
	f.SetRegistryLoginResult("registry.example.com", "unauthorized")
	if r := resolve("registry.example.com/shop/cron:1"); r.Code != "UNAUTHORIZED" {
		t.Fatalf("login result %+v", r)
	}
	f.SetRegistryLoginResult("registry.example.com", "")
	x := f.w.extReal().rows["shop/example"]
	reader := x.reader
	x.reader = nil
	if r := resolve("registry.example.com/shop/cron:1"); r.Code != "SOURCE_NOT_READY" {
		t.Fatalf("no reader %+v", r)
	}
	x.reader, x.deleted = reader, true
	if r := resolve("registry.example.com/shop/cron:1"); r.Code != "SOURCE_REVOKED" {
		t.Fatalf("deleted %+v", r)
	}

	// Permissions: bob reads shop but not payments.
	bob, _ := keyLogin(t, f, "bob", FixtureKey("bob"))
	_, err := bob.ResolveImage(ctx, "payments", control.ImageResolveQuery{Ref: "redis:7.4"})
	wantCode(t, err, CodeDenied)
	_, err = alice.ResolveImage(ctx, "shop", control.ImageResolveQuery{})
	wantCode(t, err, CodeInvalid)
}
