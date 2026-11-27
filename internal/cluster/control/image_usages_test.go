// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/imagesource"
)

// Real shared planner/reducer/signatures; lifecycle/native success is simulated
// by the existing core fixture, not evidence of Docker or a registry listener.
func TestImageUsesAndCacheShareAcceptedClaimsAndPreviousVersionReferences(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	image := "docker.io/library/php@sha256:" + strings.Repeat("a", 64)
	raw := []byte("name: source-view\nservices:\n  web:\n    image: " + image + "\n    cpus: '0.1'\n    mem_limit: 16m\n    networks: {lan: {ipv4_address: 10.80.1.9}}\n    x-sfc: {node: node-a}\nnetworks:\n  lan: {external: true, name: services}\n")
	acceptSourceVersion(t, f, "uses-first", raw)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	execution, ok := apps.Execution("tenant", "source-view")
	if !ok {
		t.Fatal("missing accepted execution")
	}
	for _, step := range execution.Steps() {
		managedDNSTaskCoreSubmit(t, f, "source-view", step.Key, true, state.Applied)
	}
	managedDNSTaskCoreProgress(t, f, "source-view", "finish", "", nil)
	acceptSourceVersion(t, f, "uses-second", append(slices.Clone(raw), []byte("\n# second accepted document\n")...))
	page, err := f.p.ImageUsages(f.s, f.session, 10, "tenant", ImageUsageQuery{Refs: []string{image}}, "")
	if err != nil {
		t.Fatal(err)
	}
	previous, accepted := false, false
	for _, row := range page.Rows {
		if !row.ImageReference.Valid() || row.Tenant != "tenant" || row.App != "source-view" || row.Image != image {
			t.Fatal("wrong public use", row)
		}
		previous = previous || row.Kind == "app-previous" && row.Version == 1
		accepted = accepted || row.Kind == "app-execution" && row.Operation == "uses-second"
	}
	if !previous || !accepted {
		t.Fatal("accepted or previous app source omitted", page)
	}
	refs, err := f.p.imageCacheReferences(f.s, "node-a")
	if err != nil || !slices.Contains(refs, image) {
		t.Fatal("cache and usage core diverged", refs, err)
	}
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageRegistry)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	spec := imagesource.Source{Tenant: "tenant", ID: "docker", Authority: "docker.io", Repository: "library/**", Enabled: true, Auth: "none"}
	f.apply("uses-source", "put-external-registry", 0, ExternalRegistryPut{spec}, state.Applied)
	source, err := f.p.ImageUsages(f.s, f.session, 10, "tenant", ImageUsageQuery{ExternalSource: "docker"}, "")
	if err != nil || len(source.Rows) == 0 {
		t.Fatal("external source app users", err)
	}
	f.apply("uses-source-delete", "delete-external-registry", 1, RegistrySelection{"tenant", "docker"}, state.Applied)
	retained, err := f.p.ImageUsages(f.s, f.session, 10, "tenant", ImageUsageQuery{ExternalSource: "docker"}, "")
	if err != nil || retained.Root != source.Root {
		t.Fatal("revocation erased app reference metadata", err)
	}
	if _, err = f.p.ImageUsages(f.s, f.session, 10, "foreign", ImageUsageQuery{}, ""); err == nil {
		t.Fatal("foreign tenant uses exposed")
	}
}

func TestImageUsageCursorPinsVisibleRowsAndRejectsChangedViews(t *testing.T) {
	q := ImageUsageQuery{}
	session := access.Session{User: "alice", Scopes: []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}}
	var rows []ImageUsage
	for i := 0; i < 19; i++ {
		service := fmt.Sprintf("web-%02d", i)
		ref := ImageReference{Tenant: "tenant", App: "demo", Deployment: "deploy", Service: service, Instance: service, Node: "node-a", Task: deployment.ResourceKey("task", "tenant", "demo", service), Operation: "run", Kind: "app-execution", Image: "docker.io/library/php@sha256:" + strings.Repeat("a", 64)}
		ref.ID = imageReferenceID(ref)
		rows = append(rows, ImageUsage{ImageReference: ref, Match: "scope"})
	}
	slices.SortFunc(rows, func(a, b ImageUsage) int { return strings.Compare(a.ID, b.ID) })
	first, err := pageImageUsages([32]byte{1}, 10, session, "tenant", q, "", rows)
	if err != nil || len(first.Rows) != 16 || first.Next == "" {
		t.Fatal("first page", err)
	}
	second, err := pageImageUsages([32]byte{1}, 999, session, "tenant", q, first.Next, rows)
	if err != nil || len(second.Rows) != 3 || second.Root != first.Root || second.Next != "" {
		t.Fatal("unrelated index change invalidated visible view", err)
	}
	changed := slices.Clone(rows)
	changed[0].Image = "docker.io/library/php@sha256:" + strings.Repeat("b", 64)
	changed[0].ID = imageReferenceID(changed[0].ImageReference)
	slices.SortFunc(changed, func(a, b ImageUsage) int { return strings.Compare(a.ID, b.ID) })
	if _, err = pageImageUsages([32]byte{1}, 1000, session, "tenant", q, first.Next, changed); !errors.Is(err, access.ErrConflict) {
		t.Fatal("changed view spliced into cursor", err)
	}
	if _, _, err = ImageUsagesCursor("not-a-cursor"); err == nil {
		t.Fatal("invalid cursor accepted")
	}
	foreign := slices.Clone(rows)
	foreign[0].Tenant = "foreign"
	foreign[0].ID = imageReferenceID(foreign[0].ImageReference)
	if _, err = pageImageUsages([32]byte{1}, 11, session, "tenant", q, "", foreign); err == nil {
		t.Fatal("unfiltered row leaked from projection")
	}
}

func TestImageReferenceMatchesDoNotInventLegacyTagOrMissingVersionDigests(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	pinned := ImageReference{Image: "ghcr.io/team/app@" + a}
	for _, tc := range []struct{ ref, match string }{{a, "digest"}, {"ghcr.io/team/app@" + a, "exact"}, {"ghcr.io/team/app@" + b, ""}, {"foreign.example/team/app@" + a, ""}, {"ghcr.io/team/app:latest", "repository-unknown"}} {
		if got := pinned.MatchImage(tc.ref); got != tc.match {
			t.Fatal(tc, got)
		}
	}
	legacy := ImageReference{Image: "ghcr.io/team/app:old"}
	if legacy.MatchImage("ghcr.io/team/app@"+a) != "repository-unknown" {
		t.Fatal("mutable legacy tag declared unused")
	}
	unknown := ImageReference{Tenant: "tenant", App: "demo", Deployment: "deploy", Kind: "app-previous-unknown", Version: 1, Unknown: true}
	unknown.ID = imageReferenceID(unknown)
	if !unknown.Valid() || unknown.MatchImage("ghcr.io/team/app@"+b) != "unknown" {
		t.Fatal("missing history treated as zero references")
	}
}
