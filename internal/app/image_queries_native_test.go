// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

// This consumes the same live CLI/User/Raft and owned registry fixtures. A
// public resolution is metadata, never evidence that a new native app ran.
func imageQueryResolveNative(t *testing.T, cli *managedRegistryNative, tenant, ref, kind, source, code, pinned string, publicBytes func(*testing.T, string, []byte)) control.ImageResolveResult {
	t.Helper()
	args := []string{"registry", "resolve", ref, "--tenant", tenant}
	if code == "UNTRUSTED" {
		// The owner-lock counterexample below must also terminate if a
		// regression wrongly attempts native I/O instead of refusing early.
		args = append([]string{"--timeout", "5s"}, args...)
	}
	output, diagnostic, err := cli.runCLI(nil, args...)
	if publicBytes != nil {
		publicBytes(t, "image resolve response", output)
		publicBytes(t, "image resolve diagnostic", diagnostic)
	}
	var result control.ImageResolveResult
	if json.Unmarshal(output, &result) != nil || !result.ValidQuery(control.ImageResolveQuery{Ref: ref}) || result.Code != code || result.Kind != kind || result.Source != source {
		t.Fatal("actual image resolve selector/outcome mismatch", tenant, kind, source, code, result.Code, err)
	}
	if code == "OK" {
		_, authority, repository, normalizeErr := registryclient.Normalize(ref)
		_, digest, found := strings.Cut(pinned, "@")
		if err != nil || normalizeErr != nil || !found || result.Image == nil || result.Image.Pinned != pinned || result.Image.Digest != digest || result.Image.Registry != authority || result.Image.Repository != repository || !result.Trust.Trusted {
			t.Fatal("actual image resolve lost original immutable coordinates", result, err)
		}
	} else {
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || result.Image != nil {
			t.Fatal("image resolve refusal did not preserve its exact public code", code, err)
		}
	}
	return result
}

// Trust changes use the fixture's existing immutable user operations and exact
// current tenant CAS. Restoration runs on a failed assertion as well.
func imageQueryWithdrawTrustNative(t *testing.T, authority, prefix string, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), check func()) {
	t.Helper()
	tenant := func() access.Tenant {
		t.Helper()
		catalog, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		value, ok := catalog.Tenant("tenant")
		if !ok {
			t.Fatal("original image query tenant missing")
		}
		return value
	}
	original := tenant()
	rules := slices.DeleteFunc(slices.Clone(original.ImageSources), func(rule access.TrustRule) bool { return rule.Registry == authority })
	if len(rules) == len(original.ImageSources) {
		t.Fatal("image query trust withdrawal has no current matching rule")
	}
	change(prefix+"-withdraw", "set-trust", original.Revision, control.TrustAssignment{Tenant: "tenant", Rules: rules})
	defer func() {
		current := tenant()
		change(prefix+"-restore", "set-trust", current.Revision, control.TrustAssignment{Tenant: "tenant", Rules: slices.Clone(original.ImageSources)})
		if !reflect.DeepEqual(tenant().ImageSources, original.ImageSources) {
			t.Error("image query did not restore original trust")
		}
	}()
	check()
}

func (f *managedRegistryNative) verifyManagedImageQueriesNative(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	publicBytes := func(t *testing.T, label string, raw []byte) {
		t.Helper()
		for _, value := range []string{"private-db-value", "private-native-group-password"} {
			if bytes.Contains(raw, []byte(value)) {
				t.Fatal(label, "contains protected fixture input")
			}
		}
	}
	tag := f.address + "/fixture:owned"
	resolved := imageQueryResolveNative(t, f, "tenant", tag, "managed", "private", "OK", f.reference, publicBytes)
	manifest, err := r.readRegistryManifest(ctx, f.original, "fixture", "owned", true)
	digest := sha256.Sum256(manifest.Body)
	if err != nil || resolved.Image.ManifestBytes != int64(len(manifest.Body)) || resolved.Image.MediaType != manifest.ContentType || resolved.Image.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		t.Fatal("managed CLI resolve differs from original owner metadata", err)
	}
	imageQueryResolveNative(t, f, "tenant", f.address+"/fixture:rq6-query-missing", "managed", "private", "NOT_FOUND", "", publicBytes)
	imageQueryWithdrawTrustNative(t, f.address, "rq6-managed-query-trust", p, read, change, func() {
		// Every managed manifest read needs this existing owner lock. The
		// untrusted result must complete without entering native metadata I/O.
		r.registryMu.Lock()
		defer r.registryMu.Unlock()
		result := imageQueryResolveNative(t, f, "tenant", tag, "managed", "private", "UNTRUSTED", "", publicBytes)
		if result.Trust.Trusted {
			t.Fatal("withdrawn managed trust remained authorized")
		}
	})
	imageQueryResolveNative(t, f, "tenant", tag, "managed", "private", "OK", f.reference, publicBytes)

	var repositories control.RegistryCatalogueResult
	output := f.cli(nil, "registry", "repositories", "private", "--tenant", "tenant")
	publicBytes(t, "managed repository page", output)
	if json.Unmarshal(output, &repositories) != nil || repositories.Kind != "managed" || repositories.ID != "private" || repositories.Page.Code != "OK" || repositories.Page.Authority != f.address || repositories.Page.Repository != "" || repositories.Page.Root == ([32]byte{}) || repositories.Page.Live || !repositories.Page.UntaggedComplete || repositories.Page.Next != "" || !slices.Contains(repositories.Page.Repositories, "fixture") {
		t.Fatal("actual managed repository CLI catalogue missing original repository")
	}
	var images control.RegistryCatalogueResult
	output = f.cli(nil, "registry", "images", "private", "--repository", "fixture", "--tenant", "tenant")
	publicBytes(t, "managed image page", output)
	if json.Unmarshal(output, &images) != nil || images.Kind != "managed" || images.ID != "private" || images.Page.Code != "OK" || images.Page.Authority != f.address || images.Page.Repository != "fixture" || images.Page.Root == ([32]byte{}) || images.Page.Live || !images.Page.UntaggedComplete || images.Page.Next != "" {
		t.Fatal("actual managed image CLI catalogue missing")
	}
	owned, immutable := false, false
	for _, image := range images.Page.Images {
		if !image.Valid() || image.Repository != "fixture" {
			t.Fatal("invalid actual managed image metadata")
		}
		if image.Reference == "owned" || image.Reference == resolved.Image.Digest {
			if image.Digest != resolved.Image.Digest || image.ManifestBytes != resolved.Image.ManifestBytes || image.MediaType != resolved.Image.MediaType || image.ImageBytes <= 0 || !image.UploadedAtKnown || image.UploadedAt == 0 {
				t.Fatal("managed catalogue lost original manifest/size/publication metadata")
			}
			owned = owned || image.Reference == "owned"
			immutable = immutable || image.Reference == resolved.Image.Digest
		}
	}
	if !owned || !immutable {
		t.Fatal("managed catalogue omitted original tag or immutable digest")
	}
	var usage struct {
		Schema uint8
		Tenant string
		Root   [32]byte
		Usages []control.ImageUsage
	}
	output = f.cli(nil, "registry", "usages", f.reference, "--tenant", "tenant")
	publicBytes(t, "managed image usages", output)
	if json.Unmarshal(output, &usage) != nil || usage.Schema != 1 || usage.Tenant != "tenant" || usage.Root == ([32]byte{}) {
		t.Fatal("actual managed image usage CLI receipt missing")
	}
	references, err := p.ImageReferences(read().State, "tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	query := control.ImageUsageQuery{Refs: []string{f.reference}}
	expected := map[string]control.ImageUsage{}
	for _, reference := range references {
		if reference.Tenant == "tenant" && query.Match(reference) != "" {
			expected[reference.ID] = control.ImageUsage{ImageReference: reference, Match: query.Match(reference)}
		}
	}
	for _, row := range usage.Usages {
		if !reflect.DeepEqual(row, expected[row.ID]) {
			t.Fatal("actual image usage differs from current original shared reference")
		}
		delete(expected, row.ID)
	}
	if len(expected) != 0 {
		t.Fatal("actual image usages omitted original shared references")
	}
	f.public["ManagedImageQueryDigest"], f.public["ManagedImageQueryMetadataAndUsages"] = resolved.Image.Digest, true
	f.save()
}

func (f *externalRegistryAppNative) verifyPrivateImageQueriesNative(t *testing.T, ctx context.Context, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	if err := ctx.Err(); err != nil {
		t.Fatal(err)
	}
	tag := f.remote.Registry + "/fixture:owned"
	before := f.remote.Manifests.Load()
	resolved := imageQueryResolveNative(t, f.cli, "tenant", tag, "external", "external-app", "OK", f.reference, f.publicBytes)
	if f.remote.Manifests.Load() <= before {
		t.Fatal("private CLI resolve did not read the original authenticated remote manifest")
	}
	imageQueryResolveNative(t, f.cli, "tenant", f.reference, "external", "external-app", "OK", f.reference, f.publicBytes)
	imageQueryResolveNative(t, f.cli, "tenant", f.remote.Registry+"/fixture:rq6-query-missing", "external", "external-app", "NOT_FOUND", "", f.publicBytes)
	// These are the existing CLI/User/owner catalogue adapters, backed by the
	// same approved Vault reader and exact Basic-authenticated HTTPS fixture.
	catalogue := func(method, source, repository, code string) control.RegistryCatalogueResult {
		t.Helper()
		args := []string{"registry", method, source, "--external", "--tenant", "tenant"}
		if repository != "" {
			args = append(args, "--repository", repository)
		}
		output, diagnostic, err := f.cli.runCLI(nil, args...)
		f.publicBytes(t, "private catalogue response", output)
		f.publicBytes(t, "private catalogue diagnostic", diagnostic)
		q := control.RegistryCatalogueQuery{Kind: "external", ID: source, Repository: repository}
		var result control.RegistryCatalogueResult
		if json.Unmarshal(output, &result) != nil || !result.ValidQuery(q, "") || result.Page.Code != code || result.Page.Authority != f.remote.Registry || result.Page.Repository != repository || result.Page.Next != "" {
			t.Fatal("actual private catalogue selector/outcome mismatch", method, source, repository, code, result.Page.Code, err)
		}
		if code != "OK" {
			var exit interface{ ExitCode() int }
			if !errors.As(err, &exit) || exit.ExitCode() != 3 || result.Page.Root != ([32]byte{}) || len(result.Page.Repositories) != 0 || len(result.Page.Images) != 0 {
				t.Fatal("private catalogue refusal returned a partial or successful view", code, err)
			}
			return result
		}
		if err != nil || !result.Page.Live || result.Page.UntaggedComplete || result.Page.Root == ([32]byte{}) {
			t.Fatal("private catalogue lost its live, tag-only remote contract", err)
		}
		owned := "fixture"
		if source == "external-second" {
			owned = "second"
		}
		if repository == "" {
			if !slices.Equal(result.Page.Repositories, []string{owned}) || len(result.Page.Images) != 0 {
				t.Fatal("private catalogue exposed a repository outside its exact source/credential")
			}
		} else {
			if len(result.Page.Images) != 1 || len(result.Page.Repositories) != 0 {
				t.Fatal("private catalogue omitted the owned tag or invented an untagged row")
			}
			image := result.Page.Images[0]
			_, digest, found := strings.Cut(f.remote.PrivateReference(owned), "@")
			if !found || !image.Valid() || image.Repository != owned || image.Reference != "owned" || image.Digest != digest || image.MediaType != resolved.Image.MediaType || image.ManifestBytes <= 0 || image.ImageBytes <= 0 || image.UploadedAtKnown || image.UploadedAt != 0 {
				t.Fatal("private catalogue lost immutable manifest metadata or invented publication time")
			}
			if owned == "fixture" && image.ManifestBytes != resolved.Image.ManifestBytes {
				t.Fatal("private catalogue and resolve disagree on original manifest bytes")
			}
		}
		return result
	}
	for _, source := range []struct{ id, repository string }{{"external-app", "fixture"}, {"external-second", "second"}} {
		authorized, _ := f.remote.PrivateStats(source.repository)
		catalogue("repositories", source.id, "", "OK")
		catalogue("images", source.id, source.repository, "OK")
		after, _ := f.remote.PrivateStats(source.repository)
		if after <= authorized {
			t.Fatal("private catalogue did not reach its original authenticated remote")
		}
	}
	remoteReads := func() [6]int64 {
		a, b := f.remote.PrivateStats("fixture")
		c, d := f.remote.PrivateStats("second")
		return [6]int64{a, b, c, d, f.remote.Manifests.Load(), f.remote.Blobs.Load()}
	}
	for _, denied := range []struct{ tenant, method, source, repository string }{
		{"foreign", "repositories", "external-app", ""},
		{"foreign", "images", "external-app", "fixture"},
		{"tenant", "images", "external-app", "second"},
		{"tenant", "images", "external-second", "fixture"},
	} {
		before := remoteReads()
		args := []string{"registry", denied.method, denied.source, "--external", "--tenant", denied.tenant}
		if denied.repository != "" {
			args = append(args, "--repository", denied.repository)
		}
		output, diagnostic, err := f.cli.runCLI(nil, args...)
		f.publicBytes(t, "private catalogue denied response", output)
		f.publicBytes(t, "private catalogue denied diagnostic", diagnostic)
		var exit interface{ ExitCode() int }
		if !errors.As(err, &exit) || exit.ExitCode() != 3 || len(bytes.TrimSpace(output)) != 0 || !bytes.Contains(diagnostic, []byte("denied")) || remoteReads() != before {
			t.Fatal("private catalogue borrowed another tenant/source reader or reached unauthorized remote I/O", denied, err)
		}
	}
	f.remote.DenyPrivate("fixture", true)
	func() {
		defer f.remote.DenyPrivate("fixture", false)
		_, rejected := f.remote.PrivateStats("fixture")
		imageQueryResolveNative(t, f.cli, "tenant", tag, "external", "external-app", "UNAUTHORIZED", "", f.publicBytes)
		catalogue("repositories", "external-app", "", "UNAUTHORIZED")
		catalogue("images", "external-app", "fixture", "UNAUTHORIZED")
		_, after := f.remote.PrivateStats("fixture")
		if after <= rejected {
			t.Fatal("private resolve authentication refusal did not reach current remote authorization")
		}
	}()
	imageQueryWithdrawTrustNative(t, f.remote.Registry, "rq6-private-query-trust", p, read, change, func() {
		authorized, rejected := f.remote.PrivateStats("fixture")
		manifests, blobs := f.remote.Manifests.Load(), f.remote.Blobs.Load()
		imageQueryResolveNative(t, f.cli, "tenant", tag, "external", "external-app", "UNTRUSTED", "", f.publicBytes)
		afterAuthorized, afterRejected := f.remote.PrivateStats("fixture")
		if afterAuthorized != authorized || afterRejected != rejected || f.remote.Manifests.Load() != manifests || f.remote.Blobs.Load() != blobs {
			t.Fatal("untrusted private resolution performed original remote I/O")
		}
		// Image trust authorizes resolution/deployment; it does not revoke
		// the current approved reader's permission to inspect metadata.
		catalogue("repositories", "external-app", "", "OK")
		catalogue("images", "external-app", "fixture", "OK")
	})
	imageQueryResolveNative(t, f.cli, "tenant", tag, "external", "external-app", "OK", f.reference, f.publicBytes)
	authorized, rejected := f.remote.PrivateStats("fixture")
	// The existing foreign tenant has no source or matching trust. Even the
	// system admin cannot borrow tenant's approved Vault reader into that scope.
	imageQueryResolveNative(t, f.cli, "foreign", tag, "unknown", "", "UNTRUSTED", "", f.publicBytes)
	afterAuthorized, afterRejected := f.remote.PrivateStats("fixture")
	if afterAuthorized != authorized || afterRejected != rejected {
		t.Fatal("foreign tenant resolution borrowed original private credentials")
	}
	f.public["ExternalImageQueryDigest"], f.public["ExternalImageQueryCurrentAuthTrustAndTenant"] = resolved.Image.Digest, true
	f.public["ExternalImageCatalogueLiveMetadataAndCurrentReader"] = true
	f.save()
}
