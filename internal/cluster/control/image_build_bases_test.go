// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/imagesource"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func buildBaseQuery(plan ImageBuildJobPlan, ref string) ImageBuildBaseQuery {
	return ImageBuildBaseQuery{Tenant: plan.Spec.Tenant, Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Source: imagebuild.Source{Reference: ref, Platform: plan.Spec.Context.Platforms[0], Stage: 0, Kind: "from", Line: 1}, At: 3}
}

// The actual policy/reducer/signature boundary is used. Manifest metadata is
// explicitly injected, not evidence of registry I/O, layer pulls or BuildKit.
func TestBuildBaseResolutionUsesAcceptedJobAndRunningSourceKeepsItsOriginalPin(t *testing.T) {
	f, plan := buildJobFixture(t)
	session := f.sessions["manager"]
	session.ExpiresAt = 3
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := buildBaseQuery(plan, "docker.io/library/alpine:latest")
	q.At = 4 // the accepted origin is retained after login expiry
	read, err := f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil || read.Target.Code != "" || read.Target.Owner != plan.Spec.Scope.Root.Key {
		t.Fatal(read, err)
	}
	image := registryclient.Resolution{Normalized: q.Source.Reference, Registry: "docker.io", Repository: "library/alpine", Digest: "sha256:" + strings.Repeat("a", 64), MediaType: "application/vnd.oci.image.manifest.v1+json", ManifestBytes: 100}
	image.Pinned = "docker.io/library/alpine@" + image.Digest
	result := read.Result(read.Target.Result("OK", &image))
	if err := f.p.ValidateImageBuildBaseResult(f.s, read, result, 4); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*ImageBuildBaseResult){
		func(r *ImageBuildBaseResult) { r.Builder[0] ^= 1 }, func(r *ImageBuildBaseResult) { r.Cluster[0] ^= 1 },
		func(r *ImageBuildBaseResult) { r.Source.Stage++ }, func(r *ImageBuildBaseResult) { r.Snapshot[0] ^= 1 },
		func(r *ImageBuildBaseResult) { r.Result.Image = nil },
	} {
		bad := result
		edit(&bad)
		if bad.Valid(read) {
			t.Fatal("changed owner result accepted")
		}
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: q.Job, Action: "begin", Inputs: []imagebuild.FrozenSource{{Source: q.Source, Image: image.Pinned}}}, state.Applied)
	current, err := f.p.ImageBuildBaseRead(f.s, read.Builder, q)
	if err != nil || current.Target.Normalized != image.Pinned {
		t.Fatal("running job resolved mutable tag again", current, err)
	}
	if _, err := f.p.CurrentImageBuildBaseRead(f.s, read, 4); err == nil {
		t.Fatal("old queued target survived begin pinning")
	}
	for _, edit := range []func(*ImageBuildBaseQuery){
		func(q *ImageBuildBaseQuery) { q.Source.Reference = "docker.io/library/busybox:latest" },
		func(q *ImageBuildBaseQuery) { q.Source.Stage++ }, func(q *ImageBuildBaseQuery) { q.Source.Platform = "linux/arm64" },
		func(q *ImageBuildBaseQuery) { q.Snapshot[0] ^= 1 }, func(q *ImageBuildBaseQuery) { q.Tenant = "other" },
	} {
		bad := q
		edit(&bad)
		if _, err := f.p.ImageBuildBaseRead(f.s, read.Builder, bad); err == nil {
			t.Fatal("query broadened accepted input")
		}
	}
	if _, err := f.p.ImageBuildBaseRead(f.s, [32]byte{9}, q); err == nil {
		t.Fatal("another node used job authority")
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: q.Tenant, ID: q.Job}, state.Applied)
	if _, err := f.p.ImageBuildBaseRead(f.s, read.Builder, q); err == nil {
		t.Fatal("cancelled job acquired fresh source I/O")
	}
}

func TestBuildBaseSelectionKeepsSourceReaderApprovalAndNeverFallsBackAfterRevocation(t *testing.T) {
	f, plan := buildJobFixture(t)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	q := buildBaseQuery(plan, "ghcr.io/team/base:latest")
	owner := plan.Spec.Scope.Root.Key
	untrusted, err := f.p.ImageBuildBaseRead(f.s, owner, q)
	if err != nil || untrusted.Target.Code != "UNTRUSTED" {
		t.Fatal("untrusted source could reach native I/O", untrusted, err)
	}
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	rules := append(slices.Clone(tenant.ImageSources), access.TrustRule{Registry: "ghcr.io", Repository: "**"})
	resolveTrust(t, f, rules)
	spec := imagesource.Source{Tenant: "tenant", ID: "private", Authority: "ghcr.io", Repository: "team/**", Enabled: true, Auth: "none"}
	f.apply("manager", "put-external-registry", 0, ExternalRegistryPut{Spec: spec}, state.Applied)
	unready, err := f.p.ImageBuildBaseRead(f.s, owner, q)
	if err != nil || unready.Target.Code != "SOURCE_NOT_READY" || unready.Target.Kind != "external" {
		t.Fatal(unready, err)
	}
	session := f.sessions["manager"]
	session.Scopes[0].Actions = append(session.Scopes[0].Actions, access.Deploy)
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["manager"] = session
	bind, err := f.p.PlanExternalRegistryBind(f.s, session, 2, "tenant", "private", "node-a")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "bind-external-registry", bind.Expected, bind.Selection, state.Applied)
	read, err := f.p.ImageBuildBaseRead(f.s, owner, q)
	if err != nil || read.Target.External == nil || read.Target.ExternalReadSet == ([32]byte{}) || read.Target.Code != "" {
		t.Fatal("original source reader not selected", read, err)
	}
	if _, err := f.p.CurrentImageBuildBaseRead(f.s, read, 3); err != nil {
		t.Fatal(err)
	}
	f.apply("manager", "unbind-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: "private"}, state.Applied)
	if _, err := f.p.CurrentImageBuildBaseRead(f.s, read, 3); err == nil {
		t.Fatal("old reader authority survived drain")
	}
	f.apply("manager", "delete-external-registry", 3, RegistrySelection{Tenant: "tenant", ID: "private"}, state.Applied)
	revoked, err := f.p.ImageBuildBaseRead(f.s, owner, q)
	if err != nil || revoked.Target.Code != "SOURCE_REVOKED" || revoked.Target.Kind != "external" || revoked.Target.External != nil {
		t.Fatal("revoked source fell back to anonymous", revoked, err)
	}
}
