// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

// The actual reusable Machine constructs this original run. Target/native
// facts are injected; this helper is not evidence of a real app/quorum/native.
func checkerRemoteSourceFixture(t *testing.T, owner, provider [32]byte) (checkerObservation, checkerRemoteReceipt, [32]byte) {
	t.Helper()
	p, cluster, _ := checkerObservationFixture(t, checker.Prepared)
	d := p.Checkpoint.Definition
	d.Scope = ""
	d.Request.Targets[0].Owner = hex.EncodeToString(owner[:])
	d.Request.Targets[0].StartedAt = time.Unix(100, 0).UTC().Format(time.RFC3339Nano)
	target := d.Request.Targets[0]
	target.Service = "z-remote"
	target.TaskKey += "-remote"
	target.Owner = hex.EncodeToString(provider[:])
	target.NativeID = "remote-native"
	d.Request.Targets = append(d.Request.Targets, target)
	m, err := checker.New(d, p.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, run, err := m.Plan(p.Checkpoint.StartedAt)
	if err != nil {
		t.Fatal(err)
	}
	m, err = m.Dispatch(run.Request.RunID)
	if err != nil {
		t.Fatal(err)
	}
	p.Checkpoint = m.Checkpoint()
	e := checkerRemoteReceipt{Schema: 1, Binding: sha256.Sum256([]byte("accepted app binding")), Provider: provider, Payload: sha256.Sum256([]byte("original private typed payload")), PolicyRevision: 1, Sequence: 1, Kind: "file", Service: target.Service, DeadlineUnixMilli: run.Request.DeadlineUnixMilli, Phase: "sent"}
	q, err := e.query(p)
	if err != nil {
		t.Fatal(err)
	}
	e.Header = q.HeaderDigest()
	return p, e, cluster
}

func TestCheckerRemoteSourcePendingCannotFinishAndReceiptsSurviveDBReopen(t *testing.T) {
	owner, provider := sha256.Sum256([]byte("source")), sha256.Sum256([]byte("provider"))
	p, e, cluster := checkerRemoteSourceFixture(t, owner, provider)
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
	r := &Runtime{Identity: &identity.Identity{Public: owner}, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(p); err != nil {
		t.Fatal(err)
	}
	legacy, _ := json.Marshal(p)
	if bytes.Contains(legacy, []byte("RemoteCalls")) {
		t.Fatal("nil optional field changed old schema1 bytes")
	}
	if err = r.saveCheckerRemoteReceipt(&p, e); err != nil {
		t.Fatal(err)
	}
	if err = r.saveCheckerRemoteReceipt(&p, e); err == nil {
		t.Fatal("same original send intent admitted twice")
	}
	m, err := checker.Restore(p.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	active := *p.Checkpoint.Active
	finished, _, err := m.Finish(checker.Completion{RunID: active.Request.RunID, RequestDigest: active.RequestDigest, At: time.Now().UnixMilli(), Result: contract.Result{Schema: 1, Status: contract.Unknown, Reason: "interrupted"}, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	wrong := p
	wrong.Checkpoint = finished.Checkpoint()
	if err = r.saveCheckerObservation(wrong); err == nil {
		t.Fatal("pending remote let parent Finish commit")
	}
	changed := e
	changed.Provider[0] ^= 1
	if err = r.saveCheckerRemoteReceipt(&p, changed); err == nil {
		t.Fatal("original provider changed")
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
	raw, err := db.GetBounded(checkerObservationKey(p.Checkpoint.Definition), maxCheckerObservationBytes)
	got, decodeErr := schema.Decode[checkerObservation](raw)
	if err != nil || decodeErr != nil || got.validate(cluster, owner) != nil || len(got.RemoteCalls) != 1 || got.RemoteCalls[0] != e || got.Checkpoint.Active == nil {
		t.Fatal("pending original call lost", err, decodeErr)
	}
	if bytes.Contains(raw, []byte("original private typed payload")) {
		t.Fatal("private body persisted")
	}
	e.Phase = "closed"
	e.Response = sha256.Sum256(nil)
	if err = r.saveCheckerRemoteReceipt(&got, e); err != nil {
		t.Fatal(err)
	}
	got.Checkpoint = finished.Checkpoint()
	if err = r.saveCheckerObservation(got); err != nil {
		t.Fatal("positive closure did not permit parent result", err)
	}
	if got.Checkpoint.Last.Run.Request.RunID != active.Request.RunID || got.RemoteCalls[0].Header != e.Header {
		t.Fatal("closure replaced original identity")
	}
}

func TestCheckerRemoteSourceActualRecoveryWireKeepsParentUntilProviderClosure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	source, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(source.Private)
	provider, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(provider.Private)
	p, e, cluster := checkerRemoteSourceFixture(t, source.Public, provider.Public)
	active := *p.Checkpoint.Active
	base := t.TempDir()
	path := filepath.Join(base, "observations.db")
	journalPath := filepath.Join(base, "workload.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	r := &Runtime{Identity: source, ctx: ctx, controlPolicy: control.Policy{Cluster: cluster}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(p); err != nil {
		t.Fatal(err)
	}
	if err = r.saveCheckerRemoteReceipt(&p, e); err != nil {
		t.Fatal(err)
	}
	// Native Apply alone is mocked. Cleanup below uses the actual local A3
	// journal and source observation, without a working Docker/native client.
	j, err := reconcile.OpenJournal(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = j.Desired(p.Task.Key, reconcile.Desired{Revision: p.Task.Revision, Resource: reconcile.Resource{Generation: p.Task.Generation, Present: true, Spec: "simulated source native"}}, 4); err != nil {
		_ = j.Close()
		t.Fatal(err)
	}
	driver := &checkerJournalApply{}
	if err = j.Step(ctx, p.Task.Key, driver); err != nil {
		_ = j.Close()
		t.Fatal(err)
	}
	unrelated, err := j.Borrow(p.Task.Key, "workload/unrelated", p.Task.Generation)
	if err != nil {
		_ = j.Close()
		t.Fatal(err)
	}
	call := sha256.Sum256([]byte("joined local I/O"))
	if _, err = j.Borrow(p.Task.Key, "checker-read/"+active.Request.RunID+"/"+hex.EncodeToString(call[:]), p.Task.Generation); err != nil {
		_ = j.Close()
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	r.workload, err = workload.OpenManager(journalPath, &engine.Client{Owner: engine.Owner(cluster, source.Public)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.workload.Close()
	if err = r.settleInterruptedChecker(ctx, &p); !errors.Is(err, errCheckerRemotePending) || p.Checkpoint.Active == nil || p.remoteCallsClosed() {
		t.Fatal("unreachable provider became parent completion", err)
	}
	local, err := r.workload.View(p.Task.Key)
	if err != nil || len(local.Consumers) != 1 || local.Consumers["workload/unrelated"] != unrelated || driver.calls != 1 {
		t.Fatal("remote pending retained joined local reader or changed workload", err)
	}
	peers := map[sfcp.Identity]sfcp.Peer{
		sfcp.Identity(source.Public):   {ID: "source", Policy: sfcp.Policy{Key: sfcp.Identity(source.Public), Member: true, Respond: true}},
		sfcp.Identity(provider.Public): {ID: "provider", Policy: sfcp.Policy{Key: sfcp.Identity(provider.Public), Member: true, Respond: true}},
	}
	lookup := func(key sfcp.Identity) (sfcp.Peer, bool) { peer, ok := peers[key]; return peer, ok }
	server, err := sfcp.NewTransport(provider, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	var lookups atomic.Int32
	// Quorum/native provider is simulated HERE. This exercises the actual
	// source wire/DB/parent recovery, not production provider execution.
	if err = server.OnCheckerProbe(func(_ context.Context, s *sfcp.Session, wire sfcp.CheckerProbeRequest) (sfcp.CheckerProbeHandler, error) {
		q, err := schema.Decode[control.CheckerProbeRequest](wire.Metadata)
		if err != nil || wire.Action != "recover" || wire.Bytes != 0 || wire.Digest != e.Payload || q.HeaderDigest() != e.Header || q.Run.Request.RunID != active.Request.RunID || [32]byte(s.Peer().Key) != source.Public {
			return sfcp.CheckerProbeHandler{}, sfcp.ErrAdmission
		}
		return sfcp.CheckerProbeHandler{Execute: func(context.Context, []byte) (sfcp.CheckerProbeResult, error) {
			lookups.Add(1)
			return sfcp.CheckerProbeResult{Closed: true}, nil
		}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	peer := peers[sfcp.Identity(provider.Public)]
	peer.Endpoint = server.Addr().String()
	peers[peer.Key] = peer
	r.Mesh, err = sfcp.NewTransport(source, cluster, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Mesh.Close()
	// This fixture has no quorum Engine: select the injected current peer at
	// the wire boundary only. Product callCheckerRemote obtains this peer
	// from the committed resource lineage before using the SAME wire adapter.
	q, err := e.query(p)
	if err != nil {
		t.Fatal(err)
	}
	// Original run deadline is already expired; only this readonly recovery
	// window is fresh. No script, run, native exec or operation is recreated.
	if _, err = r.callCheckerRemotePeer(ctx, q, peer, "recover", nil, func(closed bool, data []byte) error {
		if !closed || len(data) != 0 {
			return checker.ErrContract
		}
		e.Phase, e.Response = "closed", sha256.Sum256(nil)
		return r.saveCheckerRemoteReceipt(&p, e)
	}); err != nil {
		t.Fatal(err)
	}
	if err = r.settleInterruptedChecker(ctx, &p); err != nil {
		t.Fatal(err)
	}
	if lookups.Load() != 1 || p.Checkpoint.Active != nil || !p.remoteCallsClosed() || p.Checkpoint.Last == nil || p.Checkpoint.Last.Run.Request.RunID != active.Request.RunID || p.Checkpoint.Last.Result.Status != contract.Unknown {
		t.Fatal("original recovery changed run/result", lookups.Load())
	}
	if err = r.settleInterruptedChecker(ctx, &p); err != nil || lookups.Load() != 1 {
		t.Fatal("terminal source called provider again", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := db.GetBounded(checkerObservationKey(p.Checkpoint.Definition), maxCheckerObservationBytes)
	stored, decodeErr := schema.Decode[checkerObservation](raw)
	if err != nil || decodeErr != nil || stored.validate(cluster, source.Public) != nil || stored.Checkpoint.Active != nil || !stored.remoteCallsClosed() {
		t.Fatal("source closure not durable before ACK", err, decodeErr)
	}
}
