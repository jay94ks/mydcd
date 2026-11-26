// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

func pruneTestDigest(n int) string { return fmt.Sprintf("sha256:%064x", n) }

func TestPruneOrdinalPagesBindSectionAndOriginalProgress(t *testing.T) {
	root := [32]byte{1}
	start, end, next, err := PrunePageRange("retained", root, 17, "")
	if err != nil || start != 0 || end != 8 || next == "" {
		t.Fatal(start, end, next, err)
	}
	start, end, last, err := PrunePageRange("retained", root, 17, next)
	if err != nil || start != 8 || end != 16 || last == "" {
		t.Fatal(start, end, last, err)
	}
	if _, _, _, err = PrunePageRange("items", root, 17, next); err == nil {
		t.Fatal("cursor switched sections")
	}
	if _, _, _, err = PrunePageRange("retained", [32]byte{2}, 17, next); err != ErrCatalogueChanged {
		t.Fatal("cursor adopted new original progress", err)
	}
	start, end, next, err = PrunePageRange("retained", root, 17, last)
	if err != nil || start != 16 || end != 17 || next != "" {
		t.Fatal(start, end, next, err)
	}
	start, end, next, err = PruneResultRange(root, 0, "")
	if err != nil || start != 0 || end != 0 || next != "" {
		t.Fatal("empty original result", err)
	}
}
func pruneTestImage(repo, ref, digest string, at uint64) ImageMetadata {
	return ImageMetadata{Repository: repo, Reference: ref, Digest: digest, MediaType: string(types.OCIManifestSchema1), ManifestBytes: 128, ImageBytes: 10, UploadedAt: at, UploadedAtKnown: at > 0}
}
func pruneTestInventory() PruneInventory {
	in := PruneInventory{Schema: 1, Authority: "registry.example", UntaggedComplete: true, PhysicalComplete: true}
	for n, repo := range []string{"team/app", "team/app", "other/app"} {
		digest := pruneTestDigest(n + 1)
		in.Images = append(in.Images, pruneTestImage(repo, digest, digest, 100))
		in.Blobs = append(in.Blobs, PruneBlob{repo, digest, pruneTestDigest(n + 11), 2}, PruneBlob{repo, digest, pruneTestDigest(99), 8})
	}
	in.Images = append(in.Images,
		pruneTestImage("team/app", "old-a", pruneTestDigest(1), 100),
		pruneTestImage("team/app", "stable", pruneTestDigest(1), 500),
		pruneTestImage("team/app", "old-b", pruneTestDigest(2), 200),
		pruneTestImage("other/app", "old-c", pruneTestDigest(3), 50))
	return in
}

func TestPruneSelectionKeepsRecentPerRepositoryAndCountsOnlyExclusivePhysicalBytes(t *testing.T) {
	in := pruneTestInventory()
	originalOrder := slices.Clone(in.Images)
	c := PruneConditions{KeepRecentPerRepository: 1, Before: 400, GC: true}
	p, err := BuildPrunePreview(in, c)
	if !slices.Equal(in.Images, originalOrder) {
		t.Fatal("preview sorting rewrote the caller's inventory")
	}
	if err != nil || !p.Valid() || len(p.Items) != 2 || !p.EstimateKnown || p.ImageBytes != 20 || p.EstimatedReclaimedBytes != 2 {
		t.Fatal("preview selection/shared blob estimate", p, err)
	}
	if p.Items[0].Image.Reference != "old-a" || len(p.Items[0].Tags) != 0 || p.Items[1].Image.Digest != pruneTestDigest(2) || !slices.Equal(p.Items[1].Tags, []string{"old-b"}) {
		t.Fatal("tag-only vs all-alias digest deletion", p.Items)
	}
	if len(p.Retained) != 2 || p.Retained[0].Image.Repository != "other/app" || p.Retained[0].Code != "RECENT" || p.Retained[1].Image.Reference != "stable" {
		t.Fatal("recent tags not grouped by repository", p.Retained)
	}
	root := p.Digest()
	slices.Reverse(in.Images)
	slices.Reverse(in.Blobs)
	other, err := BuildPrunePreview(in, c)
	if err != nil || root != other.Digest() {
		t.Fatal("arrival/map order changed the frozen selection", err)
	}
	c.ProtectedDigests = []string{pruneTestDigest(2)}
	protected, err := BuildPrunePreview(in, c)
	if err != nil || len(protected.Items) != 1 || protected.EstimatedReclaimedBytes != 0 {
		t.Fatal("saved-app digest did not protect all aliases", protected, err)
	}
	c.ProtectedDigests[0] = pruneTestDigest(3)
	if protected.Conditions.ProtectedDigests[0] != pruneTestDigest(2) {
		t.Fatal("preview aliases caller-owned conditions")
	}
	in.Protected = []PruneProtection{{Repository: "team/app", Digest: pruneTestDigest(2), Code: "IMAGE_IN_USE"}}
	c.ProtectedDigests = nil
	used, err := BuildPrunePreview(in, c)
	if err != nil || len(used.Items) != 1 || used.EstimatedReclaimedBytes != 0 {
		t.Fatal("current shared protection omitted", used, err)
	}
}

func TestPruneUnknownTimePatternsAndUntaggedAreExplicit(t *testing.T) {
	in := pruneTestInventory()
	in.Images = append(in.Images, pruneTestImage("team/app", pruneTestDigest(4), pruneTestDigest(4), 0))
	in.Blobs = append(in.Blobs, PruneBlob{"team/app", pruneTestDigest(4), pruneTestDigest(14), 10})
	c := PruneConditions{Before: 400, ExcludeTags: []string{"old-*"}, IncludeUntagged: true}
	p, err := BuildPrunePreview(in, c)
	if err != nil || len(p.Items) != 0 {
		t.Fatal("excluded or unknown-time image selected", p, err)
	}
	unknown := false
	for _, row := range p.Retained {
		unknown = unknown || row.Image.Digest == pruneTestDigest(4) && row.Code == "UPLOAD_TIME_UNKNOWN"
	}
	if !unknown {
		t.Fatal("legacy/unknown publication time was invented")
	}
	all, err := BuildPrunePreview(in, PruneConditions{IncludeUntagged: true})
	if err != nil || len(all.Items) != 4 || all.EstimatedReclaimedBytes != 24 {
		t.Fatal("explicit all-time cleanup or shared digest deduplication", all, err)
	}
	// An unreferenced association with no current manifest witness is not
	// silently adopted as exclusive reclaimed bytes of the selected image.
	in.Blobs = append(in.Blobs, PruneBlob{"pending/app", "", pruneTestDigest(99), 8})
	conservative, err := BuildPrunePreview(in, PruneConditions{IncludeUntagged: true})
	if err != nil || conservative.EstimatedReclaimedBytes != 16 {
		t.Fatal("unknown physical association erased from estimate", conservative, err)
	}
	for _, c := range []PruneConditions{
		{ExcludeTags: []string{"["}}, {ExcludeTags: []string{"../*"}}, {Repositories: []string{"z/app", "a/app"}}, {ProtectedDigests: []string{pruneTestDigest(1), pruneTestDigest(1)}},
	} {
		if _, err := BuildPrunePreview(in, c); err == nil {
			t.Fatal("invalid/ambiguous selection accepted", c)
		}
	}
}

func TestPruneKeptIndexAndSubjectKeepChildrenAndSelectedParentsPrecedeChildren(t *testing.T) {
	in := PruneInventory{Schema: 1, Authority: "registry.example", UntaggedComplete: true, PhysicalComplete: true}
	for n := 1; n <= 3; n++ {
		digest := pruneTestDigest(n)
		row := pruneTestImage("team/app", digest, digest, 100)
		if n < 3 {
			row.MediaType = string(types.OCIImageIndex)
		}
		in.Images = append(in.Images, row)
	}
	parent := in.Images[0]
	parent.Reference = "keep"
	in.Images = append(in.Images, parent)
	in.Blobs = []PruneBlob{{"team/app", pruneTestDigest(3), pruneTestDigest(30), 10}}
	in.Edges = []PruneEdge{{"team/app", pruneTestDigest(1), pruneTestDigest(2)}, {"team/app", pruneTestDigest(2), pruneTestDigest(3)}}
	kept, err := BuildPrunePreview(in, PruneConditions{IncludeUntagged: true, ExcludeTags: []string{"keep"}})
	if err != nil || len(kept.Items) != 0 || len(kept.Retained) != 3 || kept.EstimatedReclaimedBytes != 0 {
		t.Fatal("kept ancestor did not protect transitive child", kept, err)
	}
	remove, err := BuildPrunePreview(in, PruneConditions{IncludeUntagged: true})
	if err != nil || len(remove.Items) != 3 || remove.EstimatedReclaimedBytes != 10 {
		t.Fatal(remove, err)
	}
	for index, item := range remove.Items {
		if item.Image.Digest != pruneTestDigest(index+1) {
			t.Fatal("child precedes its parent", remove.Items)
		}
	}
	in.Edges = append(in.Edges, PruneEdge{"team/app", pruneTestDigest(3), pruneTestDigest(1)})
	if _, err = BuildPrunePreview(in, PruneConditions{IncludeUntagged: true}); err == nil {
		t.Fatal("cyclic dependency selected for deletion")
	}
}

func TestPrunePagesCommitConditionsAliasesAndInventoryWithOwnedData(t *testing.T) {
	in := PruneInventory{Schema: 1, Authority: "registry.example", UntaggedComplete: true}
	for i := 0; i < 18; i++ {
		digest := pruneTestDigest(i + 1)
		in.Images = append(in.Images, pruneTestImage("team/app", digest, digest, 100))
	}
	p, err := BuildPrunePreview(in, PruneConditions{IncludeUntagged: true})
	if err != nil || p.EstimateKnown {
		t.Fatal("missing physical evidence claimed known estimate", p, err)
	}
	first, err := p.Page("items", "")
	if err != nil || len(first.Items) != 8 || first.Next == "" || first.Root != p.Digest() || first.Total != 18 {
		t.Fatal(first, err)
	}
	if _, err = p.Page("retained", first.Next); !errors.Is(err, ErrCatalogueChanged) {
		t.Fatal("cursor crossed preview sections", err)
	}
	changed := p
	changed.Conditions.GC = true
	if _, err = changed.Page("items", first.Next); !errors.Is(err, ErrCatalogueChanged) {
		t.Fatal("cursor accepted changed cleanup conditions", err)
	}
	count, pages := 0, 0
	if err = p.RangePages("items", func(page PrunePage) error { pages++; count += len(page.Items); return nil }); err != nil || count != 18 || pages != 3 {
		t.Fatal("bounded page iteration", count, pages, err)
	}
	for _, page := range []PrunePage{first} {
		for _, item := range page.Items {
			if !item.Valid() || len(item.ItemID()) != 64 || strings.Contains(item.ItemID(), "/") {
				t.Fatal("invalid stable item identity", item)
			}
		}
	}
	first.Items[0].Image.Digest = pruneTestDigest(999)
	if !p.Valid() || p.Items[0].Image.Digest == pruneTestDigest(999) {
		t.Fatal("page mutation changed the original preview")
	}
	in.Live, in.UntaggedComplete = true, false
	if _, err = BuildPrunePreview(in, PruneConditions{IncludeUntagged: true}); ResultCode(err) != "UNSUPPORTED" {
		t.Fatal("incomplete external untagged enumeration pretended complete", err)
	}
}
