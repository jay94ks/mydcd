// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/distribution/reference"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const MaxCatalogueNames = 16384

var ErrCatalogueChanged = errors.New("registry catalogue changed")

func ValidRepository(repo string) bool {
	if len(repo) == 0 || len(repo) > 255 {
		return false
	}
	_, authority, path, err := Normalize("registry.example/" + repo + ":check")
	return err == nil && authority == "registry.example" && path == repo
}

type ImageMetadata struct {
	Repository, Reference, Digest, MediaType string
	ManifestBytes, ImageBytes                int64
	UploadedAt                               uint64
	UploadedAtKnown                          bool
}

func (m ImageMetadata) Valid() bool {
	named, err := reference.WithName(m.Repository)
	if err != nil || named.Name() != m.Repository || !ValidRepository(m.Repository) {
		return false
	}
	if strings.HasPrefix(m.Reference, "sha256:") {
		if m.Reference != m.Digest {
			return false
		}
	} else if _, err := reference.WithTag(named, m.Reference); err != nil {
		return false
	}
	_, _, _, err = Normalize("registry.example/" + m.Repository + "@" + m.Digest)
	return err == nil && m.ManifestBytes > 0 && m.ManifestBytes <= MaxMetadataBytes && m.ImageBytes >= 0 && m.ImageBytes <= MaxImageBytes && m.UploadedAtKnown == (m.UploadedAt > 0) && len(m.MediaType) <= 128 && (types.MediaType(m.MediaType).IsImage() || types.MediaType(m.MediaType).IsIndex())
}

type CataloguePage struct {
	Schema                uint8
	Authority, Repository string
	Code                  string
	Root                  [32]byte
	// Live means a remote registry has no transaction spanning list/manifest
	// reads. Each image still carries its independently verified immutable digest.
	Live             bool
	UntaggedComplete bool
	Repositories     []string        `json:",omitempty"`
	Images           []ImageMetadata `json:",omitempty"`
	Next             string
}

func CatalogueCursor(after string) ([32]byte, string, error) {
	if after == "" {
		return [32]byte{}, "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(after)
	if len(after) > 512 || err != nil || len(raw) < 34 || len(raw) > 288 || raw[0] != 1 || base64.RawURLEncoding.EncodeToString(raw) != after {
		return [32]byte{}, "", &Error{Code: "INVALID_CURSOR"}
	}
	root := [32]byte(raw[1:33])
	last := string(raw[33:])
	if root == ([32]byte{}) || last == "" {
		return [32]byte{}, "", &Error{Code: "INVALID_CURSOR"}
	}
	return root, last, nil
}
func catalogueNext(root [32]byte, last string) string {
	raw := append([]byte{1}, root[:]...)
	return base64.RawURLEncoding.EncodeToString(append(raw, []byte(last)...))
}

// CatalogueRange is shared by managed metadata and authenticated external
// I/O. Basis binds current source generation/read-set and user selection. Data
// contains only authorized sorted names/mappings; unrelated repos cannot alter
// a public view's cursor. Entries hold owner revision facts when available.
func CatalogueRange(authority, repository string, basis [32]byte, names []string, entries any, after string) (CataloguePage, []string, error) {
	page := CataloguePage{Schema: 1, Authority: authority, Repository: repository, Code: "OK"}
	if basis == ([32]byte{}) || len(names) > MaxCatalogueNames {
		return page, nil, &Error{Code: "METADATA_BUDGET"}
	}
	_, host, _, err := Normalize(authority + "/mydc-catalogue:check")
	if err != nil || host != authority {
		return page, nil, &Error{Code: "INVALID_SOURCE"}
	}
	names = slices.Clone(names)
	slices.Sort(names)
	for i, name := range names {
		if name == "" || len(name) > 255 || i > 0 && name == names[i-1] {
			return page, nil, &Error{Code: "INVALID_IMAGE"}
		}
		if repository == "" {
			n, e := reference.WithName(name)
			if e != nil || n.Name() != name || !ValidRepository(name) {
				return page, nil, &Error{Code: "INVALID_IMAGE"}
			}
		} else {
			n, e := reference.WithName(repository)
			if e != nil || n.Name() != repository || !ValidRepository(repository) {
				return page, nil, &Error{Code: "INVALID_IMAGE"}
			}
			if strings.HasPrefix(name, "sha256:") {
				if _, _, _, e := Normalize(authority + "/" + repository + "@" + name); e != nil {
					return page, nil, e
				}
			} else if _, e := reference.WithTag(n, name); e != nil {
				return page, nil, &Error{Code: "INVALID_IMAGE"}
			}
		}
	}
	raw, err := json.Marshal(struct {
		Basis                 [32]byte
		Authority, Repository string
		Names                 []string
		Entries               any
	}{basis, authority, repository, names, entries})
	if err != nil {
		return page, nil, &Error{Code: "INVALID_IMAGE"}
	}
	page.Root = sha256.Sum256(append([]byte("mydc-registry-catalogue-1\x00"), raw...))
	root, last, err := CatalogueCursor(after)
	if err != nil {
		return page, nil, err
	}
	start := 0
	if after != "" {
		if root != page.Root {
			return page, nil, ErrCatalogueChanged
		}
		index, found := slices.BinarySearch(names, last)
		if !found {
			return page, nil, ErrCatalogueChanged
		}
		start = index + 1
	}
	end := min(start+8, len(names))
	selected := names[start:end]
	if end < len(names) {
		page.Next = catalogueNext(page.Root, selected[len(selected)-1])
	}
	return page, selected, nil
}
func (p CataloguePage) Valid(authority, repository, after string) bool {
	_, host, _, err := Normalize(authority + "/mydc-catalogue:check")
	if err != nil || host != authority || repository != "" && !ValidRepository(repository) {
		return false
	}
	if p.Schema != 1 || p.Authority != authority || p.Repository != repository {
		return false
	}
	if p.Code != "OK" {
		return ValidResultCode(p.Code) && p.Root == ([32]byte{}) && len(p.Repositories) == 0 && len(p.Images) == 0 && p.Next == ""
	}
	if p.Root == ([32]byte{}) || len(p.Repositories) > 8 || len(p.Images) > 8 || repository == "" && len(p.Images) != 0 || repository != "" && len(p.Repositories) != 0 {
		return false
	}
	root, last, err := CatalogueCursor(after)
	if err != nil || after != "" && root != p.Root {
		return false
	}
	count := 0
	for _, name := range p.Repositories {
		n, e := reference.WithName(name)
		if e != nil || n.Name() != name || !ValidRepository(name) || name <= last {
			return false
		}
		last = name
		count++
	}
	for _, image := range p.Images {
		if !image.Valid() || image.Repository != repository || image.Reference <= last {
			return false
		}
		last = image.Reference
		count++
	}
	if p.Next != "" {
		nextRoot, nextLast, e := CatalogueCursor(p.Next)
		if e != nil || count != 8 || nextRoot != p.Root || nextLast != last {
			return false
		}
	}
	return true
}
