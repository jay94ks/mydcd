// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/storage"
)

// An accepted observation is announced once, by reference; an identical
// republish and a stale sample are not.
func TestNodeObservationPublishesOnlyStoredChanges(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	r := &Runtime{reports: db, bus: eventbus.New()}
	sub := r.Events().Subscribe(0, nil)
	defer sub.Close()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{64}, 32))
	report := observability.Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 2000,
		RegistryPull: &observability.RegistryPull{Tenant: "tenant", Authority: "registry.example", Source: "private", Stage: "load", Code: "OK", CompletedAt: 1000, Sequence: 1}}
	save := func(rpt observability.Report) {
		rpt.Signature = ed25519.Sign(key, observability.SigningBytes(rpt))
		raw, _ := json.Marshal(rpt)
		r.reportMu.Lock()
		err := r.storeValidatedNodeObservation(rpt, raw)
		r.reportMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	save(report)
	save(report) // identical bytes
	stale := report
	stale.At = 1000
	save(stale)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, resync, err := sub.Next(ctx)
	want := eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindNodeObservation, Node: "node-a", Source: report.Source(), Tenant: "tenant", Changed: true}
	if err != nil || resync || len(got) != 1 || got[0].Topic != want.Topic || got[0].Kind != want.Kind || got[0].Node != want.Node || got[0].Source != want.Source || got[0].Tenant != want.Tenant || !got[0].Changed {
		t.Fatalf("events = %+v resync=%v err=%v", got, resync, err)
	}
}
