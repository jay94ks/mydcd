// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/v1/types"
)

const MaxPrunePreviewBytes = 8 << 20

// Before is an absolute Unix millisecond cutoff, fixed before preview. No
// clock, native effects or user/session authority enters this selection core.
type PruneConditions struct {
	Repositories            []string
	KeepRecentPerRepository uint32
	Before                  uint64
	ExcludeTags             []string
	IncludeUntagged         bool
	ProtectedDigests        []string
	GC                      bool
}

func pruneDigest(digest string) bool {
	if len(digest) != len("sha256:")+64 || strings.ToLower(digest) != digest {
		return false
	}
	_, _, _, err := Normalize("registry.example/image@" + digest)
	return err == nil && strings.HasPrefix(digest, "sha256:")
}

func (c PruneConditions) Valid() bool {
	if len(c.Repositories) > 256 || len(c.ExcludeTags) > 32 || len(c.ProtectedDigests) > 256 || c.KeepRecentPerRepository > MaxCatalogueNames {
		return false
	}
	for i, repo := range c.Repositories {
		if !ValidRepository(repo) || i > 0 && repo <= c.Repositories[i-1] {
			return false
		}
	}
	for i, pattern := range c.ExcludeTags {
		if len(pattern) == 0 || len(pattern) > 128 || strings.ContainsAny(pattern, "/\\\x00\r\n") || i > 0 && pattern <= c.ExcludeTags[i-1] {
			return false
		}
		if _, err := path.Match(pattern, "tag"); err != nil {
			return false
		}
	}
	for i, digest := range c.ProtectedDigests {
		if !pruneDigest(digest) || i > 0 && digest <= c.ProtectedDigests[i-1] {
			return false
		}
	}
	return true
}

type PruneEdge struct{ Repository, Parent, Child string }
type PruneBlob struct {
	Repository, Manifest, Digest string
	Size                         int64
}
type PruneProtection struct{ Repository, Digest, Code string }

// Blob rows describe direct manifest/config/layer ownership, not graph sums.
// Manifest="" is a physical association without a current manifest witness;
// it is excluded from the conservative estimate, not adopted as free bytes.
type PruneInventory struct {
	Schema           uint8
	Authority        string
	Live             bool
	UntaggedComplete bool
	PhysicalComplete bool
	Images           []ImageMetadata
	Edges            []PruneEdge
	Blobs            []PruneBlob
	Protected        []PruneProtection
}

func pruneImageKey(repo, digest string) string { return repo + "@" + digest }
func pruneRefKey(repo, ref string) string      { return repo + "/" + ref }

func (in PruneInventory) canonical() (PruneInventory, error) {
	if len(in.Images) > MaxCatalogueNames || len(in.Edges) > MaxCatalogueNames || len(in.Blobs) > 65536 || len(in.Protected) > MaxCatalogueNames {
		return in, &Error{Code: "METADATA_BUDGET"}
	}
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > MaxPrunePreviewBytes {
		return in, &Error{Code: "METADATA_BUDGET"}
	}
	// Own nested slices; callers may reuse/mutate their HTTP/DB result buffers.
	var owned PruneInventory
	if json.Unmarshal(raw, &owned) != nil {
		return in, &Error{Code: "INVALID_IMAGE"}
	}
	in = owned
	if in.Schema != 1 || len(in.Images) > MaxCatalogueNames || len(in.Edges) > MaxCatalogueNames || len(in.Blobs) > 65536 || len(in.Protected) > MaxCatalogueNames {
		return in, &Error{Code: "INVALID_IMAGE"}
	}
	_, host, _, err := Normalize(in.Authority + "/mydc-prune:check")
	if err != nil || host != in.Authority {
		return in, &Error{Code: "INVALID_SOURCE"}
	}
	slices.SortFunc(in.Images, func(a, b ImageMetadata) int {
		return strings.Compare(pruneRefKey(a.Repository, a.Reference), pruneRefKey(b.Repository, b.Reference))
	})
	images := map[string]bool{}
	contents := map[string]ImageMetadata{}
	for i, image := range in.Images {
		if !image.Valid() || i > 0 && pruneRefKey(image.Repository, image.Reference) == pruneRefKey(in.Images[i-1].Repository, in.Images[i-1].Reference) {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
		images[pruneImageKey(image.Repository, image.Digest)] = true
		key := pruneImageKey(image.Repository, image.Digest)
		if prior, ok := contents[key]; ok && (prior.MediaType != image.MediaType || prior.ManifestBytes != image.ManifestBytes || prior.ImageBytes != image.ImageBytes) {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
		contents[key] = image
	}
	if in.UntaggedComplete {
		for _, image := range in.Images {
			index, ok := slices.BinarySearchFunc(in.Images, pruneRefKey(image.Repository, image.Digest), func(image ImageMetadata, key string) int {
				return strings.Compare(pruneRefKey(image.Repository, image.Reference), key)
			})
			if !ok || in.Images[index].Digest != image.Digest {
				return in, &Error{Code: "INVALID_IMAGE"}
			}
		}
	}
	slices.SortFunc(in.Edges, func(a, b PruneEdge) int {
		return strings.Compare(a.Repository+"@"+a.Parent+"@"+a.Child, b.Repository+"@"+b.Parent+"@"+b.Child)
	})
	for i, edge := range in.Edges {
		if !pruneDigest(edge.Parent) || !pruneDigest(edge.Child) || edge.Parent == edge.Child || !images[pruneImageKey(edge.Repository, edge.Parent)] || !images[pruneImageKey(edge.Repository, edge.Child)] || i > 0 && edge == in.Edges[i-1] {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
	}
	slices.SortFunc(in.Blobs, func(a, b PruneBlob) int {
		return strings.Compare(a.Repository+"@"+a.Manifest+"@"+a.Digest, b.Repository+"@"+b.Manifest+"@"+b.Digest)
	})
	sizes := map[string]int64{}
	manifestBytes := map[string]int64{}
	for i, blob := range in.Blobs {
		if !ValidRepository(blob.Repository) || !pruneDigest(blob.Digest) || blob.Size < 0 || blob.Size > MaxImageBytes || blob.Manifest != "" && !images[pruneImageKey(blob.Repository, blob.Manifest)] || i > 0 && blob.Repository == in.Blobs[i-1].Repository && blob.Manifest == in.Blobs[i-1].Manifest && blob.Digest == in.Blobs[i-1].Digest {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
		if previous, ok := sizes[blob.Digest]; ok && previous != blob.Size {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
		sizes[blob.Digest] = blob.Size
		if blob.Manifest != "" {
			key := pruneImageKey(blob.Repository, blob.Manifest)
			if blob.Size > (1<<63-1)-manifestBytes[key] {
				return in, &Error{Code: "IMAGE_BUDGET"}
			}
			manifestBytes[key] += blob.Size
		}
	}
	if in.PhysicalComplete {
		for key, image := range contents {
			if types.MediaType(image.MediaType).IsImage() && manifestBytes[key] != image.ImageBytes {
				return in, &Error{Code: "INVALID_IMAGE"}
			}
		}
	}
	slices.SortFunc(in.Protected, func(a, b PruneProtection) int {
		return strings.Compare(pruneImageKey(a.Repository, a.Digest), pruneImageKey(b.Repository, b.Digest))
	})
	for i, row := range in.Protected {
		if !images[pruneImageKey(row.Repository, row.Digest)] || row.Code != "IMAGE_IN_USE" && row.Code != "PROTECTED" || i > 0 && row.Repository == in.Protected[i-1].Repository && row.Digest == in.Protected[i-1].Digest {
			return in, &Error{Code: "INVALID_IMAGE"}
		}
	}
	return in, nil
}

type PruneItem struct {
	Image ImageMetadata
	// Digest deletion is fixed to this complete alias set. The actual owner
	// must refuse it if aliases changed after preview; it may not expand it.
	Tags []string
}

func PruneAliasDigest(tags []string) string {
	canonical := append([]string{}, tags...)
	slices.Sort(canonical)
	raw, _ := json.Marshal(canonical)
	sum := sha256.Sum256(append([]byte("mydc-registry-prune-aliases-1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func (i PruneItem) Valid() bool {
	if !i.Image.Valid() || len(i.Tags) > MaxCatalogueNames || !strings.HasPrefix(i.Image.Reference, "sha256:") && len(i.Tags) != 0 {
		return false
	}
	for n, tag := range i.Tags {
		copy := i.Image
		copy.Reference = tag
		if strings.HasPrefix(tag, "sha256:") || !copy.Valid() || n > 0 && tag <= i.Tags[n-1] {
			return false
		}
	}
	return true
}

type PruneRetained struct {
	Image ImageMetadata
	Code  string
}

func ValidPruneRetainedCode(code string) bool {
	switch code {
	case "REPOSITORY_FILTER", "PROTECTED", "IMAGE_IN_USE", "EXCLUDED_TAG", "RECENT", "UPLOAD_TIME_UNKNOWN", "TOO_RECENT", "UNTAGGED_EXCLUDED", "MANIFEST_DEPENDENCY":
		return true
	}
	return false
}

type PrunePreview struct {
	Schema                  uint8
	Authority               string
	Conditions              PruneConditions
	Inventory               [32]byte
	Live, UntaggedComplete  bool
	Items                   []PruneItem
	Retained                []PruneRetained
	ImageBytes              int64
	EstimatedReclaimedBytes int64
	EstimateKnown           bool
}

func (p PrunePreview) Digest() [32]byte {
	raw, _ := json.Marshal(p)
	return sha256.Sum256(append([]byte("mydc-registry-prune-preview-1\x00"), raw...))
}

// ItemID separates per-item native receipts within a single original job.
// It does not allocate a new user operation or resolve an unknown side effect.
func (i PruneItem) ItemID() string {
	raw, _ := json.Marshal(i)
	sum := sha256.Sum256(append([]byte("mydc-registry-prune-item-1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func BuildPrunePreview(in PruneInventory, c PruneConditions) (PrunePreview, error) {
	if !c.Valid() {
		return PrunePreview{}, &Error{Code: "INVALID_IMAGE"}
	}
	in, err := in.canonical()
	if err != nil {
		return PrunePreview{}, err
	}
	if c.IncludeUntagged && !in.UntaggedComplete {
		return PrunePreview{}, &Error{Code: "UNSUPPORTED"}
	}
	raw, _ := json.Marshal(c)
	var owned PruneConditions
	_ = json.Unmarshal(raw, &owned)
	raw, _ = json.Marshal(in)
	p := PrunePreview{Schema: 1, Authority: in.Authority, Conditions: owned, Inventory: sha256.Sum256(append([]byte("mydc-registry-prune-inventory-1\x00"), raw...)), Live: in.Live, UntaggedComplete: in.UntaggedComplete, EstimateKnown: !in.Live && in.UntaggedComplete && in.PhysicalComplete}
	protected := map[string]string{}
	for _, row := range in.Protected {
		protected[pruneImageKey(row.Repository, row.Digest)] = row.Code
	}
	tags := map[string][]ImageMetadata{}
	groups := map[string][]ImageMetadata{}
	for _, image := range in.Images {
		key := pruneImageKey(image.Repository, image.Digest)
		groups[key] = append(groups[key], image)
		if !strings.HasPrefix(image.Reference, "sha256:") {
			tags[image.Repository] = append(tags[image.Repository], image)
		}
	}
	recent := map[string]bool{}
	for _, rows := range tags {
		slices.SortFunc(rows, func(a, b ImageMetadata) int {
			if a.UploadedAt != b.UploadedAt {
				if a.UploadedAt > b.UploadedAt {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Reference, b.Reference)
		})
		known := uint32(0)
		for _, image := range rows {
			if image.UploadedAtKnown && known < c.KeepRecentPerRepository {
				recent[pruneRefKey(image.Repository, image.Reference)] = true
				known++
			}
		}
	}
	keep := func(image ImageMetadata) string {
		if len(c.Repositories) > 0 && !slices.Contains(c.Repositories, image.Repository) {
			return "REPOSITORY_FILTER"
		}
		if slices.Contains(c.ProtectedDigests, image.Digest) {
			return "PROTECTED"
		}
		if code := protected[pruneImageKey(image.Repository, image.Digest)]; code != "" {
			return code
		}
		if !strings.HasPrefix(image.Reference, "sha256:") {
			for _, pattern := range c.ExcludeTags {
				if yes, _ := path.Match(pattern, image.Reference); yes {
					return "EXCLUDED_TAG"
				}
			}
			if recent[pruneRefKey(image.Repository, image.Reference)] {
				return "RECENT"
			}
		}
		if (c.Before > 0 || c.KeepRecentPerRepository > 0) && !image.UploadedAtKnown {
			return "UPLOAD_TIME_UNKNOWN"
		}
		if c.Before > 0 && image.UploadedAt >= c.Before {
			return "TOO_RECENT"
		}
		return ""
	}
	selected := map[string]bool{}
	items := map[string]PruneItem{}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		rows := groups[key]
		var digest *ImageMetadata
		var aliases []string
		var eligible []ImageMetadata
		var kept []PruneRetained
		for _, image := range rows {
			if strings.HasPrefix(image.Reference, "sha256:") {
				copy := image
				digest = &copy
				continue
			}
			aliases = append(aliases, image.Reference)
			if code := keep(image); code != "" {
				kept = append(kept, PruneRetained{image, code})
			} else {
				eligible = append(eligible, image)
			}
		}
		if len(aliases) == 0 {
			if digest == nil {
				return PrunePreview{}, &Error{Code: "INVALID_IMAGE"}
			}
			code := keep(*digest)
			if code == "" && !c.IncludeUntagged {
				code = "UNTAGGED_EXCLUDED"
			}
			if code != "" {
				p.Retained = append(p.Retained, PruneRetained{*digest, code})
				continue
			}
		} else if len(kept) > 0 {
			p.Retained = append(p.Retained, kept...)
			for _, image := range eligible {
				items[pruneRefKey(image.Repository, image.Reference)] = PruneItem{Image: image}
			}
			continue
		}
		if digest == nil {
			copy := rows[0]
			copy.Reference = copy.Digest
			digest = &copy
		}
		slices.Sort(aliases)
		items[key] = PruneItem{Image: *digest, Tags: aliases}
		selected[key] = true
	}
	// A kept index/subject keeps its children. Propagate once per node/edge,
	// rather than repeatedly scanning a long index/subject chain.
	children := map[string][]string{}
	for _, edge := range in.Edges {
		parent, child := pruneImageKey(edge.Repository, edge.Parent), pruneImageKey(edge.Repository, edge.Child)
		children[parent] = append(children[parent], child)
	}
	queue := []string{}
	for _, key := range keys {
		if !selected[key] {
			queue = append(queue, key)
		}
	}
	for head := 0; head < len(queue); head++ {
		for _, child := range children[queue[head]] {
			if !selected[child] {
				continue
			}
			item := items[child]
			delete(selected, child)
			delete(items, child)
			p.Retained = append(p.Retained, PruneRetained{item.Image, "MANIFEST_DEPENDENCY"})
			for _, row := range groups[child] {
				if !strings.HasPrefix(row.Reference, "sha256:") {
					items[pruneRefKey(row.Repository, row.Reference)] = PruneItem{Image: row}
				}
			}
			queue = append(queue, child)
		}
	}
	// Tag-only operations precede deterministic topological digest removal.
	itemKeys := make([]string, 0, len(items))
	for key, item := range items {
		if !strings.HasPrefix(item.Image.Reference, "sha256:") {
			itemKeys = append(itemKeys, key)
		}
	}
	slices.Sort(itemKeys)
	for _, key := range itemKeys {
		p.Items = append(p.Items, items[key])
	}
	indegree := map[string]int{}
	for key := range selected {
		indegree[key] = 0
	}
	for parent, next := range children {
		if selected[parent] {
			for _, child := range next {
				if selected[child] {
					indegree[child]++
				}
			}
		}
	}
	ready := []string{}
	for key, degree := range indegree {
		if degree == 0 {
			ready = append(ready, key)
		}
	}
	done := 0
	for len(ready) > 0 {
		slices.Sort(ready)
		next := []string{}
		for _, key := range ready {
			p.Items = append(p.Items, items[key])
			done++
			for _, child := range children[key] {
				if !selected[child] {
					continue
				}
				indegree[child]--
				if indegree[child] == 0 {
					next = append(next, child)
				}
			}
		}
		ready = next
	}
	if done != len(selected) {
		return PrunePreview{}, &Error{Code: "INVALID_IMAGE"}
	}
	logical := map[string]bool{}
	for _, item := range p.Items {
		key := pruneImageKey(item.Image.Repository, item.Image.Digest)
		if !logical[key] {
			if item.Image.ImageBytes > (1<<63-1)-p.ImageBytes {
				return PrunePreview{}, &Error{Code: "IMAGE_BUDGET"}
			}
			p.ImageBytes += item.Image.ImageBytes
			logical[key] = true
		}
	}
	physical := map[string]int64{}
	live := map[string]bool{}
	for _, blob := range in.Blobs {
		physical[blob.Digest] = blob.Size
		if blob.Manifest == "" || !selected[pruneImageKey(blob.Repository, blob.Manifest)] {
			live[blob.Digest] = true
		}
	}
	if p.EstimateKnown {
		for digest, size := range physical {
			if !live[digest] {
				if size > (1<<63-1)-p.EstimatedReclaimedBytes {
					return PrunePreview{}, &Error{Code: "IMAGE_BUDGET"}
				}
				p.EstimatedReclaimedBytes += size
			}
		}
	}
	slices.SortFunc(p.Retained, func(a, b PruneRetained) int {
		return strings.Compare(pruneRefKey(a.Image.Repository, a.Image.Reference), pruneRefKey(b.Image.Repository, b.Image.Reference))
	})
	raw, err = json.Marshal(p)
	if err != nil || len(raw) > MaxPrunePreviewBytes {
		return PrunePreview{}, &Error{Code: "METADATA_BUDGET"}
	}
	if !p.Valid() {
		return PrunePreview{}, &Error{Code: "INVALID_IMAGE"}
	}
	return p, nil
}

type PrunePage struct {
	Schema   uint8
	Root     [32]byte
	Part     string
	Total    uint64
	Items    []PruneItem     `json:",omitempty"`
	Retained []PruneRetained `json:",omitempty"`
	Next     string
}

func (p PrunePreview) Valid() bool {
	if p.Schema != 1 || !p.Conditions.Valid() || p.Inventory == ([32]byte{}) || p.ImageBytes < 0 || p.EstimatedReclaimedBytes < 0 || !p.EstimateKnown && p.EstimatedReclaimedBytes != 0 || (p.Live || !p.UntaggedComplete) && p.EstimateKnown || len(p.Items) > MaxCatalogueNames || len(p.Items)+len(p.Retained) > 2*MaxCatalogueNames {
		return false
	}
	_, host, _, err := Normalize(p.Authority + "/mydc-prune:check")
	if err != nil || host != p.Authority {
		return false
	}
	seen := map[string]bool{}
	logical := map[string]bool{}
	var total int64
	for _, item := range p.Items {
		key := pruneRefKey(item.Image.Repository, item.Image.Reference)
		if !item.Valid() || seen[key] {
			return false
		}
		seen[key] = true
		imageKey := pruneImageKey(item.Image.Repository, item.Image.Digest)
		if !logical[imageKey] {
			if item.Image.ImageBytes > (1<<63-1)-total {
				return false
			}
			total += item.Image.ImageBytes
			logical[imageKey] = true
		}
	}
	if total != p.ImageBytes {
		return false
	}
	for _, row := range p.Retained {
		key := pruneRefKey(row.Image.Repository, row.Image.Reference)
		if !row.Image.Valid() || seen[key] {
			return false
		}
		seen[key] = true
		if !ValidPruneRetainedCode(row.Code) {
			return false
		}
	}
	raw, err := json.Marshal(p)
	return err == nil && len(raw) <= MaxPrunePreviewBytes
}

func (p PrunePreview) Page(part, after string) (PrunePage, error) {
	if !p.Valid() {
		return PrunePage{}, &Error{Code: "INVALID_IMAGE"}
	}
	return p.page(part, after, p.Digest())
}

// RangePages commits/checks the full preview only once. A native owner can
// store bounded page records without hashing a multi-megabyte plan per page.
func (p PrunePreview) RangePages(part string, consume func(PrunePage) error) error {
	if !p.Valid() || consume == nil {
		return &Error{Code: "INVALID_IMAGE"}
	}
	root := p.Digest()
	after := ""
	for {
		page, err := p.page(part, after, root)
		if err != nil {
			return err
		}
		if err = consume(page); err != nil {
			return err
		}
		if page.Next == "" {
			return nil
		}
		after = page.Next
	}
}

func (p PrunePreview) page(part, after string, digest [32]byte) (PrunePage, error) {
	out := PrunePage{Schema: 1, Root: digest, Part: part}
	count := len(p.Items)
	if part == "retained" {
		count = len(p.Retained)
	}
	start, end, next, err := PrunePageRange(part, digest, uint32(count), after)
	if err != nil {
		return out, err
	}
	out.Total = uint64(count)
	out.Next = next
	if part == "items" {
		raw, _ := json.Marshal(p.Items[start:end])
		_ = json.Unmarshal(raw, &out.Items)
	} else {
		out.Retained = slices.Clone(p.Retained[start:end])
	}
	return out, nil
}

// PruneResultRange pages immutable owner result rows by their original ordinal.
// The caller commits its current processed count/result into root before use.
func PruneResultRange(root [32]byte, total uint32, after string) (start, end uint32, next string, err error) {
	if total > MaxCatalogueNames {
		return 0, 0, "", &Error{Code: "INVALID_CURSOR"}
	}
	return PrunePageRange("items", root, total, after)
}

// PrunePageRange operates on an already verified immutable owner preview. It
// avoids rehashing/revalidating its multi-megabyte body for every wire page.
func PrunePageRange(part string, root [32]byte, total uint32, after string) (start, end uint32, next string, err error) {
	if root == ([32]byte{}) || total > 2*MaxCatalogueNames || part != "items" && part != "retained" {
		return 0, 0, "", &Error{Code: "INVALID_CURSOR"}
	}
	cursor, last, err := CatalogueCursor(after)
	if err != nil {
		return 0, 0, "", err
	}
	if after != "" {
		if cursor != root || !strings.HasPrefix(last, part+":") {
			return 0, 0, "", ErrCatalogueChanged
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(last, part+":"), 10, 32)
		if err != nil || n == 0 || n >= uint64(total) || n%8 != 0 || last != fmt.Sprintf("%s:%d", part, n) {
			return 0, 0, "", &Error{Code: "INVALID_CURSOR"}
		}
		start = uint32(n)
	}
	end = min(start+8, total)
	if end < total {
		next = catalogueNext(root, fmt.Sprintf("%s:%d", part, end))
	}
	return start, end, next, nil
}
