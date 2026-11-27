// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jay94ks/seafield/internal/registry"
)

// Exact production post-authorization adapter and actual retained Store. Grant
// contents/current permissions are a fixture, not a claim of real quorum/auth.
func TestRegistryAuthAdapterRecordsPushBeforeIssueAndCoversPullHEAD(t *testing.T) {
	ctx := context.Background()
	root, err := os.MkdirTemp(t.TempDir(), "private-registry-")
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.OpenStore(ctx, root, registry.Scope{Schema: 1, Cluster: [32]byte{1}, Node: [32]byte{2}, Tenant: "tenant", Registry: "private"}, registry.MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}, registry.BlobLimits{BlobBytes: 1024, TotalBytes: 4096, Records: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	grant := registry.Grant{Repository: "team/app", Actions: []string{"pull", "push"}, IssuedAt: 100, ExpiresAt: 160}
	if err = recordRegistryPushLease(ctx, store, grant, true, 100); err != nil {
		t.Fatal(err)
	}
	until, err := store.BeginWriteFence(ctx, "gc-original", 101)
	if err != nil || until != 160 {
		t.Fatal(until, err)
	}
	if err = recordRegistryPushLease(ctx, store, grant, false, 110); err != nil {
		t.Fatal("finite existing push-capable HEAD not covered", err)
	}
	if err = recordRegistryPushLease(ctx, store, grant, true, 110); !errors.Is(err, registry.ErrUnavailable) {
		t.Fatal("new token emitted during maintenance", err)
	}
	unknown := grant
	unknown.ExpiresAt++
	if err = recordRegistryPushLease(ctx, store, unknown, false, 110); !errors.Is(err, registry.ErrUnavailable) {
		t.Fatal("uncovered token entered native request", err)
	}
	if err = recordRegistryPushLease(ctx, nil, grant, true, 110); !errors.Is(err, registry.ErrUnavailable) {
		t.Fatal("missing retained Store bypassed lease persistence", err)
	}
	readonly := grant
	readonly.Actions = []string{"pull"}
	if err = recordRegistryPushLease(ctx, nil, readonly, false, 110); err != nil {
		t.Fatal("read-only grant acquired a write lease", err)
	}
}
