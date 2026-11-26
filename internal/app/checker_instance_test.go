// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/workload"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"

	"github.com/hashicorp/raft"
)

// openEmptyTestEngine opens a real single-node engine whose replicated state is
// empty, so restart evidence can come only from the local checker receipts.
func openEmptyTestEngine(t *testing.T, node *identity.Identity, clusterID [32]byte) *cluster.Engine {
	t.Helper()
	admin, err := identity.Create(filepath.Join(t.TempDir(), "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	self := mydcp.Peer{ID: "node-a", Policy: mydcp.Policy{Key: mydcp.Identity(node.Public), Member: true, Read: true, Respond: true, Snapshot: true, Replicate: true}}
	mesh, err := mydcp.NewTransport(node, clusterID, func(k mydcp.Identity) (mydcp.Peer, bool) { return self, k == self.Key })
	if err != nil {
		t.Fatal(err)
	}
	if err = mesh.Listen("127.0.0.1:0"); err != nil {
		_ = mesh.Close()
		t.Fatal(err)
	}
	self.Endpoint = mesh.Addr().String()
	engine, err := cluster.Open(cluster.Options{ID: self.ID, Root: filepath.Join(t.TempDir(), "state"), Admin: admin.Actor(), Cluster: clusterID, Mesh: mesh, Bootstrap: true,
		Servers: []raft.Server{{ID: raft.ServerID(self.ID), Address: raft.ServerAddress(self.Endpoint), Suffrage: raft.Voter}},
		Resolve: func(id raft.ServerID, address raft.ServerAddress) (mydcp.Peer, bool) {
			return self, string(id) == self.ID && string(address) == self.Endpoint
		}})
	if err != nil {
		_ = mesh.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = engine.Close()
		_ = mesh.Close()
	})
	return engine
}

func TestCompletedRestartEvidenceSurvivesLocalBindingReplacementAndDBReopen(t *testing.T) {
	point, cluster, owner := checkerObservationFixture(t, checker.Prepared)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{159}, 32))
	defer clear(key)
	owner = [32]byte(key.Public().(ed25519.PublicKey))
	d := point.Checkpoint.Definition
	d.Request.Targets[0].Owner = hex.EncodeToString(owner[:])
	base := time.Now().Add(-3 * time.Minute).UTC()
	d.Request.Targets[0].StartedAt = base.Format(time.RFC3339Nano)
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
	m, o, err := m.Finish(checker.Completion{RunID: run.Request.RunID, RequestDigest: run.RequestDigest, Result: contract.Result{Schema: 1, Status: contract.Fail, Reason: "dead"}, At: point.Checkpoint.StartedAt + 1, HelperExited: true, ProbesClosed: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := checker.NewContainerControl(o, checker.ActionPolicy{OnDead: checker.RestartContainer}, contract.Fail, true)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := c.Dispatch(checker.StopContainer)
	if err != nil {
		t.Fatal(err)
	}
	stop, err = stop.Observe(checker.ControlView{NativeID: c.Target.NativeID, StartedAt: c.Target.StartedAt, Startable: true})
	if err != nil {
		t.Fatal(err)
	}
	start, err := stop.Dispatch(checker.StartContainer)
	if err != nil {
		t.Fatal(err)
	}
	newStamp := base.Add(time.Minute).Format(time.RFC3339Nano)
	done, err := start.Observe(checker.ControlView{NativeID: c.Target.NativeID, StartedAt: newStamp, Running: true})
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	point.setControl(done)
	m, err = m.Retire()
	if err != nil {
		t.Fatal(err)
	}
	d.Request.Targets[0].StartedAt = newStamp
	m, err = m.Replace(d, point.Checkpoint.StartedAt+2)
	if err != nil {
		t.Fatal(err)
	}
	point.Checkpoint = m.Checkpoint()
	point.Control = nil
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	node := &identity.Identity{Public: owner, Private: key}
	r := &Runtime{Identity: node, engine: openEmptyTestEngine(t, node, cluster), ctx: context.Background(), controlPolicy: control.Policy{Cluster: cluster, TrustRoot: owner}, reports: db, checkerObservationSizes: map[string]int{}}
	if err = r.saveCheckerObservation(point); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	r.reports, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.reports.Close()
	before, _ := parseAppInstance(c.Target.StartedAt)
	after, _ := parseAppInstance(newStamp)
	exit := engine.ContainerExit{StartedAt: before, FinishedAt: before + int64(time.Second)}
	stage := deployment.StageRecord{Key: point.Task.Key, Command: &state.Command{}, Result: &state.Result{Generation: point.Task.Generation, Revision: point.Task.Revision}, Observation: &deployment.Observation{Native: c.Target.NativeID, StartedAt: before, Exit: &exit}}
	proof, err := r.checkerRestartEvidence(stage, after)
	if err != nil || proof.Control.RunID != run.Request.RunID || proof.PreviousExit == nil || *proof.PreviousExit != exit {
		t.Fatal("original receipt lost after new checker binding", proof, err)
	}
	proof.Control.RunID = "changed"
	proof.PreviousExit.Code = 9
	again, err := r.checkerRestartEvidence(stage, after)
	if err != nil || again.Control.RunID != run.Request.RunID || again.PreviousExit.Code != 0 {
		t.Fatal("caller rewrote durable receipt", again, err)
	}
	stage.Observation.StartedAt = after
	stage.Observation.Exit = nil
	stage.Observation.Restart = again
	if copy, err := r.checkerRestartEvidence(stage, after); err != nil || copy == again || copy.Control != again.Control {
		t.Fatal("same-instance heartbeat lost receipt", copy, err)
	}
	app := control.AppView{Operation: deployment.OperationSummary{ID: "operation", Plan: point.Program}}
	status := workload.ContainerStatus{NativeID: c.Target.NativeID, StartedAt: newStamp, Running: true}
	observed, err := r.appTaskObservation(app, stage, status)
	if err != nil || observed.StartedAt != after || observed.Restart == nil || !ed25519.Verify(owner[:], deployment.ObservationBytes(observed), observed.Signature) {
		t.Fatal("instance/receipt missing from signed report", observed, err)
	}
	stage.Observation = &observed
	if !(&Runtime{}).freshAppTaskObservation(stage, status) {
		t.Fatal("same instance forced duplicate report")
	}
	status.StartedAt = base.Add(2 * time.Minute).Format(time.RFC3339Nano)
	if (&Runtime{}).freshAppTaskObservation(stage, status) {
		t.Fatal("new instance reused old heartbeat")
	}
	if _, err = r.appTaskObservation(app, stage, status); err == nil {
		t.Fatal("external restart reported without its own receipt")
	}
}
