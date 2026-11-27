// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// This is the actual Machine and private provider DB. No live quorum or
// Docker effect is provided; only original-identity/closure paths run here.
func checkerRemoteFixture(t *testing.T) (checkerRemoteCall, [32]byte, [32]byte) {
	t.Helper()
	point, cluster, source := checkerObservationFixture(t, checker.Prepared)
	provider := sha256.Sum256([]byte("remote provider"))
	d := point.Checkpoint.Definition
	d.Scope = ""
	d.Request.Targets[0].StartedAt = time.Unix(100, 0).UTC().Format(time.RFC3339Nano)
	target := d.Request.Targets[0]
	target.Service = "z-remote"
	target.TaskKey += "-remote"
	target.Owner = hex.EncodeToString(provider[:])
	target.NativeID = "provider-native"
	d.Request.Targets = append(d.Request.Targets, target)
	m, err := checker.New(d, point.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(point.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	q := control.CheckerProbeRequest{Schema: 1, Task: point.Task, Binding: sha256.Sum256([]byte("accepted binding")), Run: *m.Checkpoint().Active, PolicyRevision: 1, Sequence: 1, Kind: "exec", Service: target.Service, Payload: sha256.Sum256([]byte("original typed payload")), DeadlineUnixMilli: run.Request.DeadlineUnixMilli}
	p := checkerRemoteCall{Schema: 1, Consumer: source, Provider: provider, Query: q, Header: q.HeaderDigest(), Call: (checker.ProbeCall{Binding: checker.ProbeBinding(q.Run.Request), Sequence: q.Sequence}).ID(), Phase: "prepared"}
	if err = p.validate(cluster, provider); err != nil {
		t.Fatal(err)
	}
	return p, cluster, provider
}

func TestCheckerRemoteMissingLookupSealsBeforeDelayedRunAndSurvivesReopen(t *testing.T) {
	p, cluster, provider := checkerRemoteFixture(t)
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
	r := &Runtime{Identity: &identity.Identity{Public: provider}, ctx: context.Background(), controlPolicy: control.Policy{Cluster: cluster}, reports: db, workload: &workload.Manager{}}
	result, err := r.executeCheckerRemote(context.Background(), p, "recover", nil)
	if err != nil || !result.Closed || len(result.Data) != 0 {
		t.Fatal("missing lookup not durably sealed", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.reports = db
	r.checkerRemoteReady = false
	// A delayed, previously authorized run reaches the SAME call after the
	// lookup. No quorum/native client exists: dispatch must never be reached.
	result, err = r.executeCheckerRemote(context.Background(), p, "run", []byte("invalid and never decoded"))
	if err != nil || !result.Closed || len(result.Data) != 0 {
		t.Fatal("late run defeated no-effect closure", err)
	}
	raw, err := db.GetBounded(p.key(), checkerRemoteRowBytes)
	stored, decodeErr := schema.Decode[checkerRemoteCall](raw)
	if err != nil || decodeErr != nil || stored.Phase != "closed" || stored.Header != p.Header || stored.Call != p.Call || stored.Execution != nil {
		t.Fatal("original identity/closure lost", err, decodeErr)
	}
	changed := p
	changed.Query.Payload[0] ^= 1
	changed.Header = changed.Query.HeaderDigest()
	if _, err = r.executeCheckerRemote(context.Background(), changed, "recover", nil); err == nil {
		t.Fatal("same call accepted changed payload")
	}
	changed = p
	changed.Consumer[0] ^= 1
	if changed.validate(cluster, provider) == nil {
		t.Fatal("foreign source role accepted")
	}
	// A known record disappearing is damage, not a fresh missing lookup.
	if err = db.Write(map[string][]byte{p.key(): nil}); err != nil {
		t.Fatal(err)
	}
	if _, err = r.executeCheckerRemote(context.Background(), p, "recover", nil); err == nil {
		t.Fatal("known missing record replaced with closure")
	}
}

func TestCheckerRemoteExecReceiptForwardOnlyAndPrivateDBReopen(t *testing.T) {
	p, cluster, provider := checkerRemoteFixture(t)
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
	r := &Runtime{Identity: &identity.Identity{Public: provider}, controlPolicy: control.Policy{Cluster: cluster}, reports: db}
	if err = r.checkerRemoteIndex(); err != nil {
		t.Fatal(err)
	}
	if err = r.saveCheckerRemote(p); err != nil {
		t.Fatal(err)
	}
	p.Phase = "dispatched"
	if err = r.saveCheckerRemote(p); err != nil {
		t.Fatal(err)
	}
	e := workload.ProbeExecReceipt{Schema: 1, RunID: p.Query.Run.Request.RunID, Call: p.Call, Payload: sha256.Sum256([]byte("private argv digest")), Target: p.Query.Run.Request.Targets[1], Phase: workload.ProbeExecCreating}
	if err = r.saveCheckerRemoteExec(&p, e); err != nil {
		t.Fatal(err)
	}
	if err = r.saveCheckerRemoteExec(&p, e); err == nil {
		t.Fatal("duplicate Create intent allowed")
	}
	e.ExecID = "original-exec"
	e.Phase = workload.ProbeExecCreated
	if err = r.saveCheckerRemoteExec(&p, e); err != nil {
		t.Fatal(err)
	}
	e.Phase = workload.ProbeExecSent
	if err = r.saveCheckerRemoteExec(&p, e); err != nil {
		t.Fatal(err)
	}
	closed := p
	closed.Phase = "closed"
	if err = r.saveCheckerRemote(closed); err == nil {
		t.Fatal("uncertain exec became closed")
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.reports = db
	r.checkerRemoteReady = false
	if err = r.checkerRemoteIndex(); err != nil {
		t.Fatal(err)
	}
	raw, err := db.GetBounded(p.key(), checkerRemoteRowBytes)
	got, decodeErr := schema.Decode[checkerRemoteCall](raw)
	if err != nil || decodeErr != nil || got.Execution == nil || *got.Execution != e || got.Phase != "dispatched" {
		t.Fatal("original pending exec lost", err, decodeErr)
	}
	if bytes.Contains(raw, []byte("private argv digest")) {
		t.Fatal("private argument stored instead of digest")
	}
	changed := *got.Execution
	changed.ExecID = "replacement-exec"
	if err = r.saveCheckerRemoteExec(&got, changed); err == nil {
		t.Fatal("exec identity replaced")
	}
	e.Phase = workload.ProbeExecCompleted
	if err = r.saveCheckerRemoteExec(&got, e); err != nil {
		t.Fatal(err)
	}
	got.Phase = "closed"
	if err = r.saveCheckerRemote(got); err != nil {
		t.Fatal(err)
	}
	if err = r.saveCheckerRemote(p); err == nil {
		t.Fatal("closed call reopened")
	}
	without := got
	without.Execution = nil
	if err = r.saveCheckerRemote(without); err == nil {
		t.Fatal("closure erased original exec receipt")
	}
}
