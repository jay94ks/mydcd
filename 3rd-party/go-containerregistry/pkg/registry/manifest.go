// Copyright 2018 Google LLC All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type catalog struct {
	Repos []string `json:"repositories"`
}

type listTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type manifest struct {
	contentType string
	blob        []byte
}

type manifests struct {
	store   ManifestStore
	maxBody int64
	// maps repo -> manifest tag/digest -> manifest
	manifests map[string]map[string]manifest
	lock      sync.RWMutex
	log       *log.Logger
}

func isManifest(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "manifests"
}

func isTags(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "tags"
}

func isCatalog(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 2 {
		return false
	}

	return elems[len(elems)-1] == "_catalog"
}

// Returns whether this url should be handled by the referrers handler
func isReferrers(req *http.Request) bool {
	elems := strings.Split(req.URL.Path, "/")
	elems = elems[1:]
	if len(elems) < 4 {
		return false
	}
	return elems[len(elems)-2] == "referrers"
}

// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pulling-an-image-manifest
// https://github.com/opencontainers/distribution-spec/blob/master/spec.md#pushing-an-image
func (m *manifests) handle(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	switch req.Method {
	case http.MethodGet, http.MethodHead:
		m.lock.RLock()
		defer m.lock.RUnlock()
		mf, err := m.readManifest(req.Context(), repo, target)
		if err != nil {
			return manifestStoreError(err)
		}
		h, _, _ := v1.SHA256(bytes.NewReader(mf.blob))
		resp.Header().Set("Docker-Content-Digest", h.String())
		resp.Header().Set("Content-Type", mf.contentType)
		resp.Header().Set("Content-Length", fmt.Sprint(len(mf.blob)))
		resp.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = io.Copy(resp, bytes.NewReader(mf.blob))
		}
		return nil

	case http.MethodPut:
		b := &bytes.Buffer{}
		var input io.Reader = req.Body
		if m.store != nil {
			if m.maxBody < 1 {
				return regErrUnsupported
			}
			input = io.LimitReader(input, m.maxBody+1)
		}
		if _, err := io.Copy(b, input); err != nil {
			return regErrInternal(err)
		}
		if m.store != nil && int64(b.Len()) > m.maxBody {
			return &regError{Status: http.StatusRequestEntityTooLarge, Code: "MANIFEST_INVALID", Message: "manifest exceeds configured limit"}
		}
		h, _, _ := v1.SHA256(bytes.NewReader(b.Bytes()))
		digest := h.String()
		if strings.Contains(target, ":") && target != digest {
			return regErrDigestMismatch
		}
		mf := manifest{
			blob:        b.Bytes(),
			contentType: req.Header.Get("Content-Type"),
		}

		// If the manifest is a manifest list, check that the manifest
		// list's constituent manifests are already uploaded.
		// This isn't strictly required by the registry API, but some
		// registries require this.
		if types.MediaType(mf.contentType).IsIndex() {
			if err := func() *regError {
				m.lock.RLock()
				defer m.lock.RUnlock()

				im, err := v1.ParseIndexManifest(b)
				if err != nil {
					return &regError{
						Status:  http.StatusBadRequest,
						Code:    "MANIFEST_INVALID",
						Message: err.Error(),
					}
				}
				for _, desc := range im.Manifests {
					if !desc.MediaType.IsDistributable() {
						continue
					}
					if desc.MediaType.IsIndex() || desc.MediaType.IsImage() {
						if _, err := m.readManifest(req.Context(), repo, desc.Digest.String()); err != nil {
							if !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrNameUnknown) {
								return regErrInternal(err)
							}
							return &regError{
								Status:  http.StatusNotFound,
								Code:    "MANIFEST_UNKNOWN",
								Message: fmt.Sprintf("Sub-manifest %q not found", desc.Digest),
							}
						}
					} else {
						// TODO: Probably want to do an existence check for blobs.
						m.log.Printf("TODO: Check blobs for %q", desc.Digest)
					}
				}
				return nil
			}(); err != nil {
				return err
			}
		}

		m.lock.Lock()
		defer m.lock.Unlock()

		if err := m.writeManifest(req.Context(), repo, target, digest, mf); err != nil {
			return manifestStoreError(err)
		}
		resp.Header().Set("Docker-Content-Digest", digest)
		resp.WriteHeader(http.StatusCreated)
		return nil

	case http.MethodDelete:
		m.lock.Lock()
		defer m.lock.Unlock()
		if err := m.deleteManifest(req.Context(), repo, target); err != nil {
			return manifestStoreError(err)
		}
		resp.WriteHeader(http.StatusAccepted)
		return nil

	default:
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}
}

func (m *manifests) handleTags(resp http.ResponseWriter, req *http.Request) *regError {
	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	if req.Method == "GET" {
		m.lock.RLock()
		defer m.lock.RUnlock()

		refs, err := m.manifestReferences(req.Context(), repo)
		if err != nil {
			return manifestStoreError(err)
		}
		var tags []string
		for _, tag := range refs {
			if !strings.Contains(tag, ":") {
				tags = append(tags, tag)
			}
		}
		sort.Strings(tags)

		// https://github.com/opencontainers/distribution-spec/blob/b505e9cc53ec499edbd9c1be32298388921bb705/detail.md#tags-paginated
		// Offset using last query parameter.
		if last := req.URL.Query().Get("last"); last != "" {
			i := sort.Search(len(tags), func(i int) bool { return tags[i] > last })
			tags = tags[i:]
		}

		// Limit using n query parameter.
		if ns := req.URL.Query().Get("n"); ns != "" {
			if n, err := strconv.Atoi(ns); err != nil || n < 0 {
				return &regError{
					Status:  http.StatusBadRequest,
					Code:    "BAD_REQUEST",
					Message: fmt.Sprintf("parsing n: %v", err),
				}
			} else if n < len(tags) {
				tags = tags[:n]
			}
		}

		tagsToList := listTags{
			Name: repo,
			Tags: tags,
		}

		msg, _ := json.Marshal(tagsToList)
		resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader([]byte(msg)))
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

func (m *manifests) handleCatalog(resp http.ResponseWriter, req *http.Request) *regError {
	query := req.URL.Query()
	nStr := query.Get("n")
	n := 10000
	if nStr != "" {
		n, _ = strconv.Atoi(nStr)
	}

	if req.Method == "GET" {
		m.lock.RLock()
		defer m.lock.RUnlock()

		repos, err := m.repositories(req.Context())
		if err != nil {
			return manifestStoreError(err)
		}
		sort.Strings(repos)
		if n < 0 {
			return &regError{Status: http.StatusBadRequest, Code: "BAD_REQUEST", Message: "invalid page size"}
		}
		if n < len(repos) {
			repos = repos[:n]
		}

		repositoriesToList := catalog{
			Repos: repos,
		}

		msg, _ := json.Marshal(repositoriesToList)
		resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
		resp.WriteHeader(http.StatusOK)
		io.Copy(resp, bytes.NewReader([]byte(msg)))
		return nil
	}

	return &regError{
		Status:  http.StatusBadRequest,
		Code:    "METHOD_UNKNOWN",
		Message: "We don't understand your method + url",
	}
}

// TODO: implement handling of artifactType querystring
func (m *manifests) handleReferrers(resp http.ResponseWriter, req *http.Request) *regError {
	// Ensure this is a GET request
	if req.Method != "GET" {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "METHOD_UNKNOWN",
			Message: "We don't understand your method + url",
		}
	}

	elem := strings.Split(req.URL.Path, "/")
	elem = elem[1:]
	target := elem[len(elem)-1]
	repo := strings.Join(elem[1:len(elem)-2], "/")

	// Validate that incoming target is a valid digest
	if _, err := v1.NewHash(target); err != nil {
		return &regError{
			Status:  http.StatusBadRequest,
			Code:    "UNSUPPORTED",
			Message: "Target must be a valid digest",
		}
	}

	m.lock.RLock()
	defer m.lock.RUnlock()

	refs, err := m.manifestReferences(req.Context(), repo)
	if err != nil {
		return manifestStoreError(err)
	}

	im := v1.IndexManifest{
		SchemaVersion: 2,
		MediaType:     types.OCIImageIndex,
		Manifests:     []v1.Descriptor{},
	}
	for _, digest := range refs {
		h, err := v1.NewHash(digest)
		if err != nil {
			continue
		}
		manifest, err := m.readManifest(req.Context(), repo, digest)
		if err != nil {
			return manifestStoreError(err)
		}
		var refPointer struct {
			Subject *v1.Descriptor `json:"subject"`
		}
		json.Unmarshal(manifest.blob, &refPointer)
		if refPointer.Subject == nil {
			continue
		}
		referenceDigest := refPointer.Subject.Digest
		if referenceDigest.String() != target {
			continue
		}
		// At this point, we know the current digest references the target
		var imageAsArtifact struct {
			Config struct {
				MediaType string `json:"mediaType"`
			} `json:"config"`
			Annotations map[string]string `json:"annotations"`
		}
		json.Unmarshal(manifest.blob, &imageAsArtifact)
		im.Manifests = append(im.Manifests, v1.Descriptor{
			MediaType:    types.MediaType(manifest.contentType),
			Size:         int64(len(manifest.blob)),
			Digest:       h,
			ArtifactType: imageAsArtifact.Config.MediaType,
			Annotations:  imageAsArtifact.Annotations,
		})
	}
	msg, _ := json.Marshal(&im)
	resp.Header().Set("Content-Length", fmt.Sprint(len(msg)))
	resp.Header().Set("Content-Type", string(types.OCIImageIndex))
	resp.WriteHeader(http.StatusOK)
	io.Copy(resp, bytes.NewReader([]byte(msg)))
	return nil
}
