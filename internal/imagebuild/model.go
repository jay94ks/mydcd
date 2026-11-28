// SPDX-License-Identifier: Apache-2.0

// Package imagebuild owns the reusable image-build/context algorithms. Large
// artifacts belong to the node storage root; replicated state contains their
// identities, receipts and references, never ZIP bytes.
package imagebuild

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/containerd/platforms"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

const (
	MaxZIPBytes        int64 = 500_000_000 // decimal MB, including ZIP metadata
	MaxExpandedBytes   int64 = 1 << 40
	PartBytes                = 24 << 10
	UploadPartBytes          = 32 << 10
	MaxTreeEntries           = 16_384
	MaxDockerfileBytes       = 1 << 20
	MaxUploadLifetime        = 24 * 60 * 60
)

var (
	ErrInvalid       = errors.New("invalid image build input")
	ErrConflict      = errors.New("image build input changed")
	ErrDigest        = errors.New("image build content digest mismatch")
	ErrStorage       = errors.New("image build storage unavailable or changed")
	ErrExpired       = errors.New("image build upload expired")
	ErrUsed          = errors.New("image build artifact is referenced")
	ErrUntrustedBase = errors.New("UNTRUSTED_BASE")
	ErrSourceFetch   = errors.New("SOURCE_FETCH")
)

// NodeRoot is a registered root, not an app-controlled host path. The native
// caller must retain RootManager.Pin until all readers/writers have closed.
type NodeRoot struct {
	Node string
	Root nodestorage.Reference
}

type Policy struct {
	Schema         uint8
	Tenant         string
	Nodes          []NodeRoot
	Concurrency    uint32
	Seconds        uint64
	CPUMillis      uint64
	MemoryBytes    int64
	WorkspaceBytes int64
	CacheBytes     int64
	Registry       string
	Platforms      []string
	BuilderImage   string
	Cleanup        CleanupPolicy
}

type CleanupPolicy struct {
	HighWaterPercent uint8
	UnusedDays       uint32
}

func (p Policy) Own() Policy {
	p.Nodes = slices.Clone(p.Nodes)
	p.Platforms = slices.Clone(p.Platforms)
	return p
}

func (p Policy) Validate(cluster [32]byte) error {
	if p.Schema != 1 || cluster == ([32]byte{}) || !lifecycle.ValidID(p.Tenant) || len(p.Nodes) == 0 || len(p.Nodes) > 64 || p.Concurrency == 0 || p.Concurrency > 32 || p.Seconds == 0 || p.Seconds > 86400 || p.CPUMillis == 0 || p.CPUMillis > 256000 || p.MemoryBytes <= 0 || p.WorkspaceBytes <= 0 || p.WorkspaceBytes > MaxExpandedBytes || p.CacheBytes <= 0 || !lifecycle.ValidID(p.Registry) || len(p.Platforms) == 0 || len(p.Platforms) > 16 || p.Cleanup.HighWaterPercent == 0 || p.Cleanup.HighWaterPercent > 100 || p.Cleanup.UnusedDays == 0 {
		return ErrInvalid
	}
	// The builder may be a tag: it is never pinned in the policy, and each
	// build creates its container from the image the node has for it then.
	if image, err := access.NormalizeImage(p.BuilderImage); err != nil || len(p.BuilderImage) > 512 || image != p.BuilderImage {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, n := range p.Nodes {
		if !lifecycle.ValidID(n.Node) || n.Root.Validate() != nil || n.Root.Cluster != cluster || n.Root.Node != n.Node || seen[n.Node] {
			return ErrInvalid
		}
		seen[n.Node] = true
	}
	seen = map[string]bool{}
	for _, platform := range p.Platforms {
		if !ValidPlatform(platform) || seen[platform] {
			return ErrInvalid
		}
		seen[platform] = true
	}
	return nil
}

func ValidPlatform(platform string) bool {
	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "linux" {
		return false
	}
	for _, part := range parts[1:] {
		if part == "" || len(part) > 32 || strings.IndexFunc(part, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') }) >= 0 {
			return false
		}
	}
	parsed, err := platforms.Parse(platform)
	return err == nil && platforms.FormatAll(platforms.Normalize(parsed)) == platform
}

// ContextPath is shared by ZIP admission, draft operations and Dockerfile
// selection. It accepts only canonical relative POSIX paths.
func ContextPath(name string) bool {
	return name != "" && name != "." && len(name) <= 1024 && utf8.ValidString(name) && !strings.HasPrefix(name, "/") && !strings.Contains(name, "\\") && !strings.Contains(name, ":") && path.Clean(name) == name && name != ".." && !strings.HasPrefix(name, "../") && strings.IndexFunc(name, unicode.IsControl) < 0
}

func digestJSON(domain string, value any) [32]byte {
	raw, _ := json.Marshal(value)
	return sha256.Sum256(append([]byte(domain+"\x00"), raw...))
}
