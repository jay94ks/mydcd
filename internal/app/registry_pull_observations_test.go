// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/storage"
)

// Existing report-store reducer, actual bbolt persistence and signatures. This
// does not substitute for a real private-registry deployment at RQ6's end.
func TestRegistryPullStorePreservesNewestCompletionAcrossRepublishAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	r := &Runtime{reports: db}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{63}, 32))
	report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 2000,
		RegistryPull: &observability.RegistryPull{Tenant: "tenant", Authority: "registry.example", Source: "private", Stage: "load", Code: "OK", CompletedAt: 1000, Sequence: 1}}
	save := func(rpt observability.Report) {
		rpt.Signature = ed25519.Sign(key, observability.SigningBytes(rpt))
		if !rpt.Valid() {
			t.Fatal("invalid fixture")
		}
		raw, _ := json.Marshal(rpt)
		r.reportMu.Lock()
		err := r.storeValidatedNodeObservation(rpt, raw)
		r.reportMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	save(report)
	next := report
	pull := *report.RegistryPull
	next.RegistryPull = &pull
	next.RegistryPull.Code = "IMAGE_LOAD_FAILED"
	next.RegistryPull.Sequence = 2
	save(next) // same sample millisecond, a newer actual completion
	stale := report
	stale.At = 3000
	save(stale) // late old refresh must not win
	conflicting := next
	changed := *next.RegistryPull
	conflicting.RegistryPull = &changed
	conflicting.RegistryPull.Code = "OK"
	conflicting.At = 4000
	save(conflicting) // a sequence cannot change its outcome
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.reports = db
	raw, err := db.Get("node-observation/node-a/" + report.Source())
	if err != nil {
		t.Fatal(err)
	}
	got, err := observability.Decode(raw)
	if err != nil || got.RegistryPull.Sequence != 2 || got.RegistryPull.Code != "IMAGE_LOAD_FAILED" || got.RegistryPull.CompletedAt != 1000 || got.At != 2000 {
		t.Fatal("latest actual completion replaced", got, err)
	}
	refreshed := next
	refreshed.At = 5000
	save(refreshed)
	raw, _ = db.Get("node-observation/node-a/" + report.Source())
	got, err = observability.Decode(raw)
	if err != nil || got.At != 5000 || got.RegistryPull.CompletedAt != 1000 || got.RegistryPull.Sequence != 2 {
		t.Fatal("refresh fabricated pull completion", got, err)
	}
}
