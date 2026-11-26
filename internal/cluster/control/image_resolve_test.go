// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagesource"
)

func resolveTrust(t *testing.T, f *nodeStorageFixture, rules []access.TrustRule) {
	t.Helper()
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	c, err = c.SetTrust("manager", "tenant", tenant.Revision, rules)
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.checkpoint(f.s, c)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
}

func TestImageResolveReadUsesDeploymentTrustAndRetainsSourceRevocation(t *testing.T) {
	f, _ := registryFixture(t)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	readOnly := session
	readOnly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readOnly.Signature = ed25519.Sign(f.node, access.SessionBytes(readOnly))
	q := ImageResolveQuery{Ref: "ghcr.io/team/app:release"}
	read, err := f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", q, owner)
	if err != nil || read.Target.Code != "UNTRUSTED" || read.Target.Kind != "unknown" {
		t.Fatal("untrusted host would perform IO", read.Target, err)
	}
	if _, err = f.p.PlanImageResolve(f.s, readOnly, 2, "foreign", q, owner); err == nil {
		t.Fatal("foreign tenant read permitted")
	}
	resolveTrust(t, f, []access.TrustRule{{Registry: "ghcr.io", Repository: "team/app"}})
	read, err = f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", q, owner)
	if err != nil || read.Target.Code != "" || read.Target.Kind != "unknown" || read.Target.Owner != owner || !read.Target.Trust.Trusted {
		t.Fatal("trusted anonymous source", read.Target, err)
	}
	spec := imagesource.Source{Tenant: "tenant", ID: "private", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	read, err = f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", q, owner)
	if err != nil || read.Target.Code != "SOURCE_NOT_READY" || read.Target.Kind != "external" || read.Target.Source != "private" {
		t.Fatal("missing source grant became anonymous", read.Target, err)
	}
	plan, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", "private", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", plan.Expected, plan.Selection, state.Applied)
	read, err = f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", q, owner)
	if err != nil || read.Target.Code != "" || read.Target.External == nil || read.Target.ExternalReadSet == ([32]byte{}) {
		t.Fatal("Read did not use original approved source", read.Target, err)
	}
	if _, err = f.p.CurrentImageResolve(f.s, read, 2); err != nil {
		t.Fatal("unchanged source rejected", err)
	}
	f.apply("manager", "unbind-external-registry", 2, RegistrySelection{"tenant", "private"}, state.Applied)
	if _, err = f.p.CurrentImageResolve(f.s, read, 2); err == nil {
		t.Fatal("old source permit survived drain")
	}
	f.apply("manager", "delete-external-registry", 3, RegistrySelection{"tenant", "private"}, state.Applied)
	revoked, err := f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", q, owner)
	if err != nil || revoked.Target.Code != "SOURCE_REVOKED" || revoked.Target.Kind != "external" {
		t.Fatal("deleted source became anonymous", revoked.Target, err)
	}
	if !revoked.Target.Result("SOURCE_REVOKED", nil).ValidQuery(q) {
		t.Fatal("public source revocation shape")
	}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{q.Ref, "ghcr.io/team/other:release"} {
		r, err := f.p.PlanImageResolve(f.s, readOnly, 2, "tenant", ImageResolveQuery{Ref: ref}, owner)
		if err != nil {
			t.Fatal(err)
		}
		_, imageErr := c.CheckImageTrust("tenant", strings.Split(ref, ":release")[0]+"@sha256:"+strings.Repeat("a", 64))
		if r.Target.Trust.Trusted != (imageErr == nil) {
			t.Fatal("preview differs from actual deployment trust")
		}
	}
}

func TestImageResolveManagedClassificationAndMalformedInputAreNotRemoteFailures(t *testing.T) {
	f, spec := registryFixture(t)
	f.apply("manager", "put-registry", 0, RegistryPut{spec}, state.Applied)
	resolveTrust(t, f, []access.TrustRule{{Registry: spec.Authority, Repository: "**"}})
	session := f.sessions["manager"]
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	for _, test := range []struct{ ref, code, kind string }{
		{spec.Authority + "/team/app:latest", "UNAVAILABLE", "managed"},
		{"sha256:" + strings.Repeat("a", 64), "INVALID_IMAGE", "unknown"},
		{"https://registry.example/app", "INVALID_IMAGE", "unknown"},
	} {
		q := ImageResolveQuery{Ref: test.ref}
		read, err := f.p.PlanImageResolve(f.s, session, 2, "tenant", q, owner)
		if err != nil || read.Target.Code != test.code || read.Target.Kind != test.kind || !read.Target.Result(test.code, nil).ValidQuery(q) {
			t.Fatal(test, read.Target, err)
		}
	}
}
