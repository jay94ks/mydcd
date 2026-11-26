// Copyright 2026 MyDC Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

package registry

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func uploadStoreError(err error) *regError {
	switch {
	case errors.Is(err, ErrNotFound):
		return &regError{Status: 404, Code: "BLOB_UPLOAD_UNKNOWN", Message: "Unknown upload"}
	case errors.Is(err, ErrUploadOffset):
		return &regError{Status: 416, Code: "BLOB_UPLOAD_INVALID", Message: "Upload offset mismatch"}
	case errors.Is(err, ErrDigestMismatch):
		return regErrDigestMismatch
	default:
		return regErrInternal(err)
	}
}

func (b *blobs) handleStoredUpload(w http.ResponseWriter, r *http.Request, repo, service, id string) *regError {
	if r.Method == http.MethodPost && service == "uploads" {
		return regErrUnsupported
	}
	digest := r.URL.Query().Get("digest")
	if r.Method == http.MethodPut || r.Method == http.MethodPost && digest != "" {
		h, err := v1.NewHash(digest)
		if err != nil || h.Algorithm != "sha256" {
			return regErrDigestInvalid
		}
	}
	var u Upload
	var err error
	if r.Method == http.MethodPost {
		u, err = b.uploadStore.Begin(r.Context(), repo)
	} else {
		if service != "uploads" {
			return regErrUnsupported
		}
		u, err = b.uploadStore.Status(r.Context(), repo, id)
	}
	if err != nil {
		return uploadStoreError(err)
	}
	location := strings.TrimSuffix(r.URL.Path, "/")
	if r.Method == http.MethodPost {
		location += "/" + u.ID
	}
	headers := func() {
		w.Header().Set("Docker-Upload-UUID", u.ID)
		w.Header().Set("Location", location)
		w.Header().Set("Range", fmt.Sprintf("0-%d", max(int64(0), u.Offset-1)))
	}
	appendBody := func() error {
		length := r.ContentLength
		if raw := r.Header.Get("Content-Range"); raw != "" {
			parts := strings.Split(raw, "-")
			if len(parts) != 2 {
				return ErrUploadOffset
			}
			start, e1 := strconv.ParseInt(parts[0], 10, 64)
			end, e2 := strconv.ParseInt(parts[1], 10, 64)
			if e1 != nil || e2 != nil || start != u.Offset || start < 0 || end < start || end == 1<<63-1 {
				return ErrUploadOffset
			}
			if length >= 0 && length != end-start+1 {
				return ErrUploadOffset
			}
			length = end - start + 1
		}
		// Finalizing a closed ID is only an original digest/receipt lookup.
		if u.Digest != "" {
			if length != 0 {
				return ErrUploadOffset
			}
			return nil
		}
		next, appendErr := b.uploadStore.Append(r.Context(), repo, u.ID, u.Offset, length, r.Body)
		if appendErr != nil {
			return appendErr
		}
		u = next
		return nil
	}
	finish := func() *regError {
		next, finishErr := b.uploadStore.Commit(r.Context(), repo, u.ID, digest)
		if finishErr != nil {
			headers()
			return uploadStoreError(finishErr)
		}
		u = next
		prefix := strings.LastIndex(location, "/blobs/uploads/")
		if prefix < 0 {
			return regErrUnsupported
		}
		w.Header().Set("Docker-Content-Digest", u.Digest)
		w.Header().Set("Location", location[:prefix]+"/blobs/"+u.Digest)
		w.Header().Set("Docker-Upload-UUID", u.ID)
		w.WriteHeader(http.StatusCreated)
		return nil
	}
	switch r.Method {
	case http.MethodGet:
		headers()
		w.WriteHeader(http.StatusNoContent)
	case http.MethodPost, http.MethodPatch:
		if err = appendBody(); err != nil {
			headers()
			return uploadStoreError(err)
		}
		if r.Method == http.MethodPost && digest != "" {
			return finish()
		}
		headers()
		w.WriteHeader(http.StatusAccepted)
	case http.MethodPut:
		if err = appendBody(); err != nil {
			headers()
			return uploadStoreError(err)
		}
		return finish()
	case http.MethodDelete:
		if err = b.uploadStore.Cancel(r.Context(), repo, u.ID); err != nil {
			return uploadStoreError(err)
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		return regErrUnsupported
	}
	return nil
}
