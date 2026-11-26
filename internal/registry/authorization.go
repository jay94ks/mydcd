// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrUnauthorized = errors.New("registry authentication required")
	ErrForbidden    = errors.New("registry permission denied")
	ErrUnavailable  = errors.New("current registry authority unavailable")
)

// Permission describes only the operation on this already-fixed server. The
// authorizer receives neither a caller-supplied tenant nor a filesystem path.
type Permission struct{ Repository, Action string }

func (p Permission) Scope() string {
	if p.Action == "login" {
		return ""
	}
	if p.Action == "catalog" {
		return "registry:catalog:*"
	}
	return "repository:" + p.Repository + ":" + p.Action
}

type TokenRequest struct {
	Username, Service, Scope, Source string
	Secret                           []byte
}

func (TokenRequest) MarshalJSON() ([]byte, error) { return nil, ErrUnauthorized }
func (TokenRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted registry login]")
}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"`
	IssuedAt  string `json:"issued_at"`
}

// Both callbacks are required. Runtime performs current quorum/account/run
// admission; the HTTP owner never accepts anonymous or a nil auth fallback.
type Authorization struct {
	Check func(context.Context, string, Permission) error
	Token func(context.Context, TokenRequest) (TokenResponse, error)
}

func requestPermission(r *http.Request) (Permission, error) {
	p := r.URL.Path
	if p == "/v2" || p == "/v2/" {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			return Permission{Action: "login"}, nil
		}
		return Permission{}, ErrForbidden
	}
	if p == "/v2/_catalog" && r.Method == http.MethodGet {
		return Permission{Action: "catalog"}, nil
	}
	if !strings.HasPrefix(p, "/v2/") || strings.Contains(p, "//") || strings.ContainsAny(p, "%\\\x00") || r.URL.RawPath != "" {
		return Permission{}, ErrForbidden
	}
	parts := strings.Split(strings.TrimPrefix(p, "/v2/"), "/")
	if len(parts) < 3 {
		return Permission{}, ErrForbidden
	}
	var repo, action string
	n := len(parts)
	switch {
	case n >= 4 && parts[n-3] == "blobs" && parts[n-2] == "uploads":
		repo = strings.Join(parts[:n-3], "/")
		action = "push"
		if parts[n-1] == "" {
			if r.Method != http.MethodPost {
				return Permission{}, ErrForbidden
			}
		} else if !validUploadID(parts[n-1]) || r.Method != http.MethodGet && r.Method != http.MethodPatch && r.Method != http.MethodPut && r.Method != http.MethodDelete {
			return Permission{}, ErrForbidden
		}
	case parts[n-2] == "manifests":
		repo = strings.Join(parts[:n-2], "/")
		if !manifestReference(repo, parts[n-1]) {
			return Permission{}, ErrForbidden
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			action = "pull"
		case http.MethodPut:
			action = "push"
		default:
			return Permission{}, ErrForbidden
		}
	case parts[n-2] == "blobs":
		repo = strings.Join(parts[:n-2], "/")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			return Permission{}, ErrForbidden
		}
		if _, err := blobPath(parts[n-1]); err != nil {
			return Permission{}, ErrForbidden
		}
		action = "pull"
	case parts[n-2] == "tags" && parts[n-1] == "list":
		repo = strings.Join(parts[:n-2], "/")
		action = "pull"
		if r.Method != http.MethodGet {
			return Permission{}, ErrForbidden
		}
	default:
		return Permission{}, ErrForbidden
	}
	if _, err := repoID(repo); err != nil || strings.Contains(repo, ":") {
		return Permission{}, ErrForbidden
	}
	for _, part := range strings.Split(repo, "/") {
		if part == "." || part == ".." || part == "" {
			return Permission{}, ErrForbidden
		}
	}
	return Permission{repo, action}, nil
}
