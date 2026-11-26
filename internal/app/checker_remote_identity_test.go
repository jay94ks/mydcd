// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Real original provider observation DB and structural selection; no current
// quorum/TLS or native Docker execution is claimed by this source boundary.
func TestCheckerRemoteRetainedProviderKeepsOriginalJournalAcrossTwoRotations(t *testing.T) {
	original, clusterID, provider := checkerRemoteFixture(t)
	ctx := context.Background()
	openDB := func(label string) *storage.DB {
		t.Helper()
		db, err := storage.Open(filepath.Join(t.TempDir(), label+".db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	old := &Runtime{Identity: &identity.Identity{Public: provider}, ctx: ctx, controlPolicy: control.Policy{Cluster: clusterID}, reports: openDB("original"), workload: &workload.Manager{}}
	queryBefore := original.Query
	for _, label := range []string{"current-one", "current-two"} {
		current := sha256.Sum256([]byte(label))
		r := &Runtime{Identity: &identity.Identity{Public: current}, ctx: ctx, controlPolicy: old.controlPolicy, reports: openDB(label), nativeOwners: []*Runtime{old}}
		old.parentRuntime, old.controlIdentity = r, r.Identity
		owner, selected, err := r.checkerRemoteOriginal(original.Query)
		if err != nil || owner != old || selected.Consumer != original.Consumer || selected.Provider != provider || selected.Header != original.Header || selected.Call != original.Call || !reflect.DeepEqual(selected.Query, queryBefore) {
			t.Fatal("current TLS key replaced frozen original roles", err)
		}
		result, err := owner.executeCheckerRemote(ctx, selected, "recover", nil)
		if err != nil || !result.Closed || len(result.Data) != 0 {
			t.Fatal("exact original recovery not closed", err)
		}
		storedRaw, err := old.reports.GetBounded(original.key(), checkerRemoteRowBytes)
		stored, decodeErr := schema.Decode[checkerRemoteCall](storedRaw)
		if err != nil || decodeErr != nil || stored.Provider != provider || stored.Consumer != original.Consumer || stored.Header != original.Header || stored.Call != original.Call || stored.Phase != "closed" || stored.Execution != nil {
			t.Fatal("original observation changed or execution invented", err, decodeErr)
		}
		if _, err = r.reports.GetBounded(original.key(), checkerRemoteRowBytes); !errors.Is(err, storage.ErrMissing) {
			t.Fatal("recovery wrote current namespace", err)
		}
		// Duplicate run can only read the original closed tombstone. No
		// payload/native/quorum adapter exists to execute another operation.
		if result, err = owner.executeCheckerRemote(ctx, selected, "run", []byte("not a new effect")); err != nil || !result.Closed {
			t.Fatal("late original run defeated closure", err)
		}
	}
}

func TestCheckerRemoteRetainedSelectionRejectsAmbiguousAndForeignRoles(t *testing.T) {
	original, clusterID, provider := checkerRemoteFixture(t)
	old := &Runtime{Identity: &identity.Identity{Public: provider}}
	r := &Runtime{Identity: &identity.Identity{Public: sha256.Sum256([]byte("current"))}, controlPolicy: control.Policy{Cluster: clusterID}, nativeOwners: []*Runtime{old}}
	old.parentRuntime = r
	for _, change := range []struct {
		name   string
		mutate func(*control.CheckerProbeRequest)
	}{
		{"ambiguous-consumer", func(q *control.CheckerProbeRequest) {
			q.Run.Request.Targets = append(q.Run.Request.Targets, q.Run.Request.Targets[0])
		}},
		{"ambiguous-provider", func(q *control.CheckerProbeRequest) {
			q.Run.Request.Targets = append(q.Run.Request.Targets, q.Run.Request.Targets[1])
		}},
		{"foreign-provider", func(q *control.CheckerProbeRequest) {
			foreign := sha256.Sum256([]byte("foreign"))
			q.Run.Request.Targets[1].Owner = hex.EncodeToString(foreign[:])
		}},
		{"unknown-provider", func(q *control.CheckerProbeRequest) {
			q.Run.Request.Targets[1].Owner = hex.EncodeToString(make([]byte, 32))
		}},
		{"missing-consumer", func(q *control.CheckerProbeRequest) { q.Task.Generation++ }},
		{"missing-provider", func(q *control.CheckerProbeRequest) { q.Service = "absent" }},
	} {
		t.Run(change.name, func(t *testing.T) {
			q := original.Query
			q.Run.Request.Targets = append(q.Run.Request.Targets[:0:0], q.Run.Request.Targets...)
			change.mutate(&q)
			q.Run.RequestDigest = checker.ProbeBinding(q.Run.Request)
			if _, _, err := r.checkerRemoteOriginal(q); err == nil {
				t.Fatal("invalid frozen roles selected a native namespace")
			}
		})
	}
	deleteOwner := &Runtime{Identity: r.Identity, controlPolicy: r.controlPolicy}
	if _, _, err := deleteOwner.checkerRemoteOriginal(original.Query); err == nil {
		t.Fatal("missing original journal adopted current namespace")
	}
}
