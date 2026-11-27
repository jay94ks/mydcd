// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	oci "github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/registryclient"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

var ErrImageInUse = errors.New("registry image in use")

// ErrBudget is a known pre-transaction refusal, distinct from an uncertain DB
// write/sync error. No manifest/blob mutation has occurred on this return.
var ErrBudget = errors.New("registry metadata budget exhausted")

const imageDeletePrefix = "registry/image-delete/"
const gcPrefix = "registry/gc/"

type ImageDelete struct {
	Operation, Authority, Repository, Reference, ExpectedDigest string
	Item                                                        string `json:",omitempty"`
	Aliases                                                     string `json:",omitempty"`
}

func pruneHexID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func imageDeleteReceiptKey(q ImageDelete) string {
	if q.Item == "" {
		return actionReceiptKey(imageDeletePrefix, q.Operation)
	}
	raw, _ := json.Marshal(struct{ Operation, Item string }{q.Operation, q.Item})
	return imageDeletePrefix + "item/" + hexHash(raw)
}

func (q ImageDelete) Valid() bool {
	if q.Item != "" && !pruneHexID(q.Item) || q.Aliases != "" && (!pruneHexID(q.Aliases) || q.Item == "" || !strings.HasPrefix(q.Reference, "sha256:")) || q.Item != "" && strings.HasPrefix(q.Reference, "sha256:") && q.Aliases == "" {
		return false
	}
	if !validImageActionScope(q.Operation, q.Authority) || !registryclient.ValidRepository(q.Repository) || !manifestReference(q.Repository, q.Reference) {
		return false
	}
	_, host, repo, err := registryclient.Normalize(q.Authority + "/" + q.Repository + "@" + q.ExpectedDigest)
	return err == nil && host == q.Authority && repo == q.Repository && (!strings.HasPrefix(q.Reference, "sha256:") || q.Reference == q.ExpectedDigest)
}

func validImageActionScope(operation, authority string) bool {
	if operation == "" || len(operation) > 256 || strings.ContainsAny(operation, "\x00\r\n") {
		return false
	}
	rules, err := access.CanonicalTrust([]access.TrustRule{{Registry: authority, Repository: "**"}})
	return err == nil && len(rules) == 1 && rules[0].Registry == authority
}

type RetiredBlob struct {
	Digest string
	Size   int64
}
type ImageDeleteReceipt struct {
	Schema      uint8
	Scope       Scope
	Request     ImageDelete
	State, Code string
	At          uint64
	Blobs       []RetiredBlob `json:",omitempty"`
}

func (r ImageDeleteReceipt) Valid() bool {
	if r.Schema != 1 || !r.Scope.valid() || !r.Request.Valid() || r.At == 0 || len(r.Blobs) > registryclient.MaxLayers+1 {
		return false
	}
	switch r.State {
	case "deleted", "already-absent":
		if r.Code != "OK" {
			return false
		}
	case "rejected":
		if r.Code != "IMAGE_IN_USE" && r.Code != "REFERENCE_CHANGED" && r.Code != "DENIED" {
			return false
		}
	default:
		return false
	}
	if (r.State != "deleted" || !strings.HasPrefix(r.Request.Reference, "sha256:")) && len(r.Blobs) != 0 {
		return false
	}
	last := ""
	for _, blob := range r.Blobs {
		if _, err := blobPath(blob.Digest); err != nil || blob.Digest <= last || blob.Size < 0 || blob.Size > registryclient.MaxImageBytes {
			return false
		}
		last = blob.Digest
	}
	return true
}
func actionReceiptKey(prefix, operation string) string {
	digest := sha256.Sum256([]byte(operation))
	return prefix + hex.EncodeToString(digest[:])
}

// The callback performs the current shared Task/CD/previous-version/build
// reference and original authority checks. It runs after actual digest CAS,
// immediately before the one native transaction, while requests are joined.
// This store API itself grants no user or node management permission.
func (s *Store) DeleteImage(ctx context.Context, q ImageDelete, guard func(context.Context, []string) error) (ImageDeleteReceipt, error) {
	if !q.Valid() || guard == nil {
		return ImageDeleteReceipt{}, ErrStorage
	}
	release, err := s.gate.acquire(ctx, true)
	if err != nil {
		return ImageDeleteReceipt{}, err
	}
	defer release()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.Metadata == nil || s.Blobs == nil {
		return ImageDeleteReceipt{}, ErrStorage
	}
	m, b := s.Metadata, s.Blobs
	m.mu.Lock()
	defer m.mu.Unlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	if m.enter(ctx) != nil || b.enter(ctx, true) != nil {
		return ImageDeleteReceipt{}, ErrStorage
	}
	key := imageDeleteReceiptKey(q)
	old, err := s.db.GetBounded(key, 1<<20)
	if err == nil {
		receipt, err := schema.Decode[ImageDeleteReceipt](old)
		if err != nil || !receipt.Valid() || receipt.Scope != m.scope || receipt.Request != q {
			return ImageDeleteReceipt{}, ErrStorage
		}
		return receipt, nil // actual atomic receipt, never a new effect/revision
	}
	if !errors.Is(err, storage.ErrMissing) {
		return ImageDeleteReceipt{}, ErrStorage
	}
	receipt := ImageDeleteReceipt{Schema: 1, Scope: m.scope, Request: q, State: "deleted", Code: "OK", At: uint64(time.Now().UnixMilli())}
	changes := map[string][]byte{}
	data, err := m.getManifest(ctx, q.Repository, q.Reference)
	switch {
	case errors.Is(err, oci.ErrNotFound), errors.Is(err, oci.ErrNameUnknown):
		receipt.State = "already-absent"
	case err != nil:
		return ImageDeleteReceipt{}, err
	default:
		actual := "sha256:" + hexHash(data.Body)
		if actual != q.ExpectedDigest {
			receipt.State = "rejected"
			receipt.Code = "REFERENCE_CHANGED"
			break
		}
		if q.Aliases != "" {
			matches, err := m.pruneAliasSet(ctx, q)
			if err != nil {
				return ImageDeleteReceipt{}, err
			}
			if !matches {
				receipt.State = "rejected"
				receipt.Code = "REFERENCE_CHANGED"
				break
			}
		}
		refs := []string{q.Authority + "/" + q.Repository + "@" + actual}
		if !strings.HasPrefix(q.Reference, "sha256:") {
			refs = append(refs, q.Authority+"/"+q.Repository+":"+q.Reference)
		}
		if err = guard(ctx, refs); err != nil {
			if errors.Is(err, ErrImageInUse) {
				receipt.State = "rejected"
				receipt.Code = "IMAGE_IN_USE"
				break
			}
			if errors.Is(err, ErrForbidden) {
				receipt.State = "rejected"
				receipt.Code = "DENIED"
				break
			}
			return ImageDeleteReceipt{}, err
		}
		id, _ := repoID(q.Repository)
		if strings.HasPrefix(q.Reference, "sha256:") {
			used, err := m.manifestDependedOn(ctx, q.Repository, actual)
			if err != nil {
				return ImageDeleteReceipt{}, err
			}
			if used {
				receipt.State = "rejected"
				receipt.Code = "IMAGE_IN_USE"
				break
			}
			blobs, err := directManifestBlobs(data)
			if err != nil {
				return ImageDeleteReceipt{}, err
			}
			for _, blob := range blobs {
				association, _ := blobKey(q.Repository, blob.Digest)
				v, ok := b.blobs[association]
				if !ok || v.Size != blob.Size {
					return ImageDeleteReceipt{}, ErrStorage
				}
				v.Retired = true
				raw, _ := json.Marshal(v)
				changes[association] = raw
				receipt.Blobs = append(receipt.Blobs, blob)
			}
			names, err := m.manifestReferences(ctx, q.Repository)
			if err != nil {
				return ImageDeleteReceipt{}, err
			}
			retained := 0
			for _, name := range names {
				refKey := manifestPrefix + "ref/" + id + "/" + name
				target, err := s.db.GetBounded(refKey, 71)
				if err != nil {
					return ImageDeleteReceipt{}, ErrStorage
				}
				if string(target) == actual {
					changes[refKey] = nil
					changes[manifestPrefix+"published/"+id+"/"+name] = nil
				} else {
					retained++
				}
			}
			changes[manifestPrefix+"data/"+id+"/"+actual] = nil
			if retained == 0 {
				changes[manifestPrefix+"repo/"+id] = nil
			}
		} else {
			changes[manifestPrefix+"ref/"+id+"/"+q.Reference] = nil
			changes[manifestPrefix+"published/"+id+"/"+q.Reference] = nil
		}
	}
	if !receipt.Valid() {
		return ImageDeleteReceipt{}, ErrStorage
	}
	raw, _ := json.Marshal(receipt)
	changes[key] = raw
	if err = s.maintenanceBudget(changes); err != nil {
		return ImageDeleteReceipt{}, err
	}
	if ctx.Err() != nil {
		return ImageDeleteReceipt{}, ctx.Err()
	}
	if err = s.db.Write(changes); err != nil {
		m.failed = true
		b.failed = true
		return ImageDeleteReceipt{}, ErrStorage
	}
	for key, raw := range changes {
		if strings.HasPrefix(key, blobPrefix) && raw != nil {
			v, _ := schema.Decode[blobRecord](raw)
			b.blobs[key] = v
		}
	}
	return receipt, nil
}
func hexHash(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }

func directManifestBlobs(data oci.ManifestData) ([]RetiredBlob, error) {
	if types.MediaType(data.ContentType).IsIndex() {
		return nil, nil
	}
	if !types.MediaType(data.ContentType).IsImage() {
		return nil, ErrStorage
	}
	image, err := v1.ParseManifest(strings.NewReader(string(data.Body)))
	if err != nil {
		return nil, ErrStorage
	}
	sizes := map[string]int64{}
	for _, d := range append([]v1.Descriptor{image.Config}, image.Layers...) {
		if !descriptorHash(d) {
			return nil, ErrStorage
		}
		if previous, ok := sizes[d.Digest.String()]; ok && previous != d.Size {
			return nil, ErrStorage
		}
		sizes[d.Digest.String()] = d.Size
	}
	out := []RetiredBlob{}
	for digest, size := range sizes {
		out = append(out, RetiredBlob{Digest: digest, Size: size})
	}
	slices.SortFunc(out, func(a, b RetiredBlob) int { return strings.Compare(a.Digest, b.Digest) })
	return out, nil
}
func (m *Metadata) manifestDependedOn(ctx context.Context, repo, digest string) (bool, error) {
	refs, err := m.manifestReferences(ctx, repo)
	if err != nil {
		return false, err
	}
	for _, ref := range refs {
		if ref == digest || !strings.HasPrefix(ref, "sha256:") {
			continue
		}
		data, err := m.getManifest(ctx, repo, ref)
		if err != nil {
			return false, err
		}
		if types.MediaType(data.ContentType).IsIndex() {
			index, err := v1.ParseIndexManifest(strings.NewReader(string(data.Body)))
			if err != nil {
				return false, ErrStorage
			}
			for _, child := range index.Manifests {
				if child.Digest.String() == digest {
					return true, nil
				}
			}
			if index.Subject != nil && index.Subject.Digest.String() == digest {
				return true, nil
			}
		} else {
			image, err := v1.ParseManifest(strings.NewReader(string(data.Body)))
			if err != nil {
				return false, ErrStorage
			}
			if image.Subject != nil && image.Subject.Digest.String() == digest {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *Store) maintenanceBudget(changes map[string][]byte) error {
	rows, err := s.Metadata.inventory()
	if err != nil {
		return err
	}
	for k, v := range changes {
		if !strings.HasPrefix(k, manifestPrefix) && !strings.HasPrefix(k, imageDeletePrefix) && !strings.HasPrefix(k, gcPrefix) && !strings.HasPrefix(k, pushPrefix) {
			continue
		}
		if v == nil {
			delete(rows, k)
		} else {
			rows[k] = uint64(len(v))
		}
	}
	if len(rows) > s.Metadata.limits.Records {
		return ErrBudget
	}
	var total uint64
	for key, n := range rows {
		if n > uint64(s.Metadata.limits.TotalBytes)-total || uint64(len(key)) > uint64(s.Metadata.limits.TotalBytes)-total-n {
			return ErrBudget
		}
		total += n + uint64(len(key))
	}
	return nil
}
