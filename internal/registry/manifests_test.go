// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	oci "github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/jay94ks/seafield/internal/storage"
)

func metadataScope(tenant string) Scope {
	return Scope{Schema: 1, Cluster: sha256.Sum256([]byte("cluster")), Node: sha256.Sum256([]byte("node")), Tenant: tenant, Registry: "private"}
}

func metadataFixture(t *testing.T, scope Scope, limits MetadataLimits) (*Metadata, *storage.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	m, err := OpenMetadata(db, scope, limits)
	if err != nil {
		t.Fatal(err)
	}
	return m, db, path
}

func manifestData(version int) (oci.ManifestData, string) {
	data := oci.ManifestData{ContentType: string(types.OCIManifestSchema1), Body: []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","annotations":{"revision":"%d"}}`, version))}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(data.Body))
	return data, digest
}

func TestRegistryManifestOriginalBytesTagsAndOwnerSurviveActualDBReopen(t *testing.T) {
	ctx := context.Background()
	scope := metadataScope("alpha")
	limits := MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}
	m, db, path := metadataFixture(t, scope, limits)
	body, digest := manifestData(1)
	if err := m.PutManifest(ctx, "team/app", "stable", digest, body); err != nil {
		t.Fatal(err)
	}
	h := oci.New(oci.WithManifestStore(m, int64(limits.ManifestBytes)), oci.Logger(log.New(io.Discard, "", 0)))
	for _, target := range []string{"stable", digest} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/team/app/manifests/"+target, nil))
		if w.Code != 200 || w.Header().Get("Docker-Content-Digest") != digest || !bytes.Equal(w.Body.Bytes(), body.Body) {
			t.Fatal(w.Code, w.Header())
		}
	}
	// A new handler and a reopened DB must not resurrect an empty manifest map.
	if m.Close() != nil || db.Close() != nil {
		t.Fatal("close original")
	}
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m, err = OpenMetadata(reopened, scope, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMetadata(reopened, metadataScope("beta"), limits); err == nil {
		t.Fatal("other tenant adopted original DB")
	}
	got, err := m.GetManifest(ctx, "team/app", "stable")
	if err != nil || !bytes.Equal(got.Body, body.Body) {
		t.Fatal(err)
	}
	refs, err := m.ManifestReferences(ctx, "team/app")
	if err != nil || len(refs) != 2 {
		t.Fatal(refs, err)
	}
	if err = m.DeleteManifest(ctx, "team/app", digest); !errors.Is(err, oci.ErrReadOnly) {
		t.Fatal("implicit delete", err)
	}
}

func TestRegistryManifestQuotaFailedWriteAndDifferentTenantDoNotPublishTag(t *testing.T) {
	ctx := context.Background()
	// One repo/data/digest/tag and their two atomic publication facts.
	limits := MetadataLimits{ManifestBytes: 4096, Records: 6, TotalBytes: 1 << 20}
	m, db, path := metadataFixture(t, metadataScope("alpha"), limits)
	first, d1 := manifestData(1)
	second, d2 := manifestData(2)
	if err := m.PutManifest(ctx, "app", "stable", d1, first); err != nil {
		t.Fatal(err)
	}
	if err := m.PutManifest(ctx, "app", "stable", d2, second); err == nil {
		t.Fatal("unbounded immutable manifest count")
	}
	got, err := m.GetManifest(ctx, "app", "stable")
	if err != nil || !bytes.Equal(got.Body, first.Body) {
		t.Fatal("quota rejection changed tag", err)
	}
	other, _, _ := metadataFixture(t, metadataScope("beta"), limits)
	if _, err := other.GetManifest(ctx, "app", "stable"); !errors.Is(err, oci.ErrNameUnknown) {
		t.Fatal("cross tenant data", err)
	}
	// Larger quota allows the candidate, but a failed real DB transaction must
	// never be replaced by the upstream handler's optimistic in-memory tag.
	m.limits.Records = 64
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	h := oci.New(oci.WithManifestStore(m, 4096), oci.Logger(log.New(io.Discard, "", 0)))
	request := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/stable", bytes.NewReader(second.Body))
	request.Header.Set("Content-Type", second.ContentType)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request)
	if w.Code >= 200 && w.Code < 300 {
		t.Fatal("unsynced manifest acknowledged")
	}
	reopened, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	m, err = OpenMetadata(reopened, metadataScope("alpha"), limits)
	if err != nil {
		t.Fatal(err)
	}
	got, err = m.GetManifest(ctx, "app", "stable")
	if err != nil || !bytes.Equal(got.Body, first.Body) {
		t.Fatal("failed write displaced original tag", err)
	}
}

func TestRegistryManifestDigestBodyAndRequestBoundsAreNotPositivePublication(t *testing.T) {
	ctx := context.Background()
	m, _, _ := metadataFixture(t, metadataScope("alpha"), MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20})
	data, digest := manifestData(1)
	if err := m.PutManifest(ctx, "app", digest, "sha256:"+fmt.Sprintf("%064d", 0), data); err == nil {
		t.Fatal("wrong digest accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := m.PutManifest(cancelled, "app", "stable", digest, data); err == nil {
		t.Fatal("canceled publication")
	}
	h := oci.New(oci.WithManifestStore(m, 16), oci.Logger(log.New(io.Discard, "", 0)))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v2/app/manifests/stable", bytes.NewReader(data.Body))
	req.Header.Set("Content-Type", data.ContentType)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatal(w.Code)
	}
	if _, err := m.GetManifest(ctx, "app", "stable"); !errors.Is(err, oci.ErrNameUnknown) {
		t.Fatal("rejected body published repository", err)
	}
}

func TestRegistryManifestRecoveryRejectsMissingOrOrphanRecordsWithoutRepair(t *testing.T) {
	for _, fault := range []string{"missing-body", "orphan-alias", "changed-body", "changed-repo"} {
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			scope := metadataScope("alpha")
			limits := MetadataLimits{ManifestBytes: 4096, Records: 64, TotalBytes: 1 << 20}
			m, db, _ := metadataFixture(t, scope, limits)
			body, digest := manifestData(1)
			if err := m.PutManifest(ctx, "app", "stable", digest, body); err != nil {
				t.Fatal(err)
			}
			id, _ := repoID("app")
			key := manifestPrefix + "data/" + id + "/" + digest
			value := []byte(nil)
			switch fault {
			case "orphan-alias":
				key = manifestPrefix + "ref/" + id + "/orphan"
				value = []byte(fmt.Sprintf("sha256:%064d", 0))
			case "changed-body":
				value = []byte(`{"ContentType":"application/vnd.oci.image.manifest.v1+json","Body":"e30="}`)
			case "changed-repo":
				key = manifestPrefix + "repo/" + id
				value = []byte("other")
			}
			if err := db.Write(map[string][]byte{key: value}); err != nil {
				t.Fatal(err)
			}
			before, err := db.ScanBounded(manifestPrefix, 64, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenMetadata(db, scope, limits); err == nil {
				t.Fatal("damaged graph accepted", fault)
			}
			after, err := db.ScanBounded(manifestPrefix, 64, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			if len(before) != len(after) {
				t.Fatal("recovery repaired evidence")
			}
			for key, value := range before {
				if !bytes.Equal(value, after[key]) {
					t.Fatal("recovery changed original", key)
				}
			}
		})
	}
}
