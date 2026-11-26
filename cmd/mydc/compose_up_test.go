// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"github.com/hashicorp/raft"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func verifyComposeUpCLI(t *testing.T, ctx context.Context, home, root string, call func(int, ...string) []byte, login func(), c *userauth.Client, session access.Session, peer mydcp.Peer, p control.Policy, view func() state.State, runtime **app.Runtime, cfg config.Node) {
	t.Helper()
	file, planFile := filepath.Join(root, "compose.yaml"), filepath.Join(root, "plan.json")
	originalDocument := appComposeDocument(24)
	if err := os.WriteFile(file, originalDocument, 0600); err != nil {
		t.Fatal(err)
	}
	call(0, "compose", "plan", "--tenant", "tenant", "-f", file, "--out", planFile)
	raw, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) <= deployment.ArtifactPartBytes {
		t.Fatal("fixture must cross artifact part boundary")
	}
	targetDigest := [32]byte{23}
	frozen, err := userauth.StageComposeTarget(home, *c, session, "target-journal", raw, 7, max(1, view().ModuleEpoch()), targetDigest)
	if err != nil {
		t.Fatal("target intent staging", err)
	}
	frozen.Target[0] ^= 1
	targetLoaded, err := userauth.LoadCompose(home, *c, session, "target-journal")
	if err != nil || targetLoaded.Target == nil || *targetLoaded.Target != targetDigest || targetLoaded.Expected != 7 {
		t.Fatal("target journal lost owned original mode/coordinates", err)
	}
	if _, err := userauth.StageCompose(home, *c, session, "target-journal", raw, 7, targetLoaded.Epoch); err == nil {
		t.Fatal("target intent silently became legacy CAS")
	}
	otherTarget := targetDigest
	otherTarget[0] ^= 1
	if _, err := userauth.StageComposeTarget(home, *c, session, "target-journal", raw, 7, targetLoaded.Epoch, otherTarget); err == nil {
		t.Fatal("same operation adopted a new target")
	}
	intent, err := userauth.StageCompose(home, *c, session, "rollout", raw, 0, max(1, view().ModuleEpoch()))
	if err != nil {
		t.Fatal(err)
	}
	if intent.Digest != sha256.Sum256(raw) {
		t.Fatal("frozen artifact changed")
	}
	if _, err := userauth.StageComposeTarget(home, *c, session, "rollout", raw, 7, intent.Epoch, targetDigest); err == nil {
		t.Fatal("legacy original intent silently upgraded its CAS")
	}
	payload := control.AppUploadBegin{Tenant: "tenant", App: "app", Deployment: "app", ID: "rollout", Length: len(raw), Digest: intent.Digest}
	changeBytes, err := control.ChangeBytes("begin-app-upload", session.User, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	var change control.Change
	_ = json.Unmarshal(changeBytes, &change)
	original, err := c.Prepare(ctx, peer, session, "compose/rollout/upload", change)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = userauth.StageOperation(home, *c, original); err != nil {
		t.Fatal(err)
	}
	before := view().Index()
	call(4, "compose", "up", "--tenant", "tenant", "--operation", "rollout")
	if view().Index() != before {
		t.Fatal("default up retransmitted an existing uncertain intent")
	}
	if err = os.WriteFile(file, []byte("changed after original freeze"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(planFile); err != nil {
		t.Fatal(err)
	}
	login()
	call(0, "compose", "resume", "--tenant", "tenant", "--operation", "rollout")
	record, err := userauth.LoadOperation(home, *c, session, original.RequestID)
	if err != nil || record.Result == nil || record.Result.Code != state.Applied || !bytes.Equal(control.OperationBytes(record.Operation), control.OperationBytes(original)) || !bytes.Equal(record.Operation.Signature, original.Signature) {
		t.Fatal("resume replaced original actor/session/CAS/ID", err)
	}
	apps, err := p.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	rows := apps.Records()
	if len(rows) != 1 || rows[0].Operation.ID != "rollout" || rows[0].Operation.Status != "Planned" {
		t.Fatal("same daemon accepted inventory mismatch")
	}
	if source := call(0, "--tenant", "tenant", "manage", "app-source", "--app", "app", "--raw"); !bytes.Equal(source, originalDocument) {
		t.Fatal("actual compose up/resume lost frozen original document")
	}
	before = view().Index()
	call(0, "compose", "up", "--tenant", "tenant", "--operation", "rollout")
	if view().Index() != before {
		t.Fatal("accepted up duplicated writes")
	}
	if _, err = userauth.StageCompose(home, *c, session, "rollout", raw, 1, intent.Epoch); err == nil {
		t.Fatal("frozen operation rebound to another CAS")
	}
	if err = (*runtime).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err = (*runtime).Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	*runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = (*runtime).InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	// Opening the original Raft DB restores state before a new local election.
	// Wait on its read-only quorum barrier; never retry a management mutation.
	for {
		_, err = (*runtime).Engine().Read(ctx, true)
		if err == nil {
			break
		}
		if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	before = view().Index()
	call(0, "compose", "resume", "--tenant", "tenant", "--operation", "rollout")
	if view().Index() != before {
		t.Fatal("same DB resume repeated accepted effect")
	}
	loaded, err := userauth.LoadCompose(home, *c, session, "rollout")
	if err != nil || loaded.Digest != intent.Digest || !bytes.Equal(loaded.Artifact, raw) {
		t.Fatal("frozen artifact lost after re-login/restart", err)
	}
	t.Log("real CLI plan -> private frozen multipart artifact -> existing signed but unconfirmed upload stays Unknown/no resend -> new login -> explicit original resume -> multipart upload/CAS/Inventory.Begin -> default up no duplicate -> Snapshot/same daemon DB -> original result-only resume; native modules disabled, acceptance is not Ready")
}

func TestRealComposeCreateTargetAndSameDB(t *testing.T) {
	testRealComposeAppBoundary(t, false, false, "create-target")
}

func verifyComposeCreateTargetCLI(t *testing.T, ctx context.Context, home, root string, call func(int, ...string) []byte, login func(), c *userauth.Client, session access.Session, peer mydcp.Peer, view func() state.State, runtime **app.Runtime, cfg config.Node) {
	t.Helper()
	path := filepath.Join(root, "create.yaml")
	if err := os.WriteFile(path, appComposeDocument(1), 0600); err != nil {
		t.Fatal(err)
	}
	call(0, "compose", "up", "--tenant", "tenant", "-f", path, "--operation", "create-target")
	intent, err := userauth.LoadCompose(home, *c, session, "create-target")
	target := control.AppCreateTarget(c.Cluster, "tenant", "app", "app")
	if err != nil || intent.Target == nil || *intent.Target != target || intent.Expected != 0 {
		t.Fatal("actual new CLI intent did not freeze absence", err)
	}
	accepted, err := userauth.LoadOperation(home, *c, session, "compose/create-target/accept")
	if err != nil || accepted.Result == nil || accepted.Result.Code != state.Applied {
		t.Fatal("actual target create not accepted", err)
	}
	command, err := accepted.Operation.Command()
	if err != nil || command.Kind != state.ModuleAppCAS {
		t.Fatal("signed new create used strict global root", err)
	}
	original, signature := control.OperationBytes(accepted.Operation), bytes.Clone(accepted.Operation.Signature)
	wrong := target
	wrong[0] ^= 1
	if _, err := userauth.StageComposeTarget(home, *c, session, "wrong-absence", intent.Artifact, 0, intent.Epoch, wrong); err == nil {
		t.Fatal("journal accepted another absent-app scope")
	}
	if _, err := userauth.StageCompose(home, *c, session, "legacy-create", intent.Artifact, 0, intent.Epoch); err != nil {
		t.Fatal("legacy create staging", err)
	}
	if _, err := userauth.StageComposeTarget(home, *c, session, "legacy-create", intent.Artifact, 0, intent.Epoch, target); err == nil {
		t.Fatal("legacy intent silently upgraded")
	}
	if err := (*runtime).Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (*runtime).Close(); err != nil {
		t.Fatal(err)
	}
	*runtime = nil
	*runtime, err = app.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (*runtime).InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		_, err = (*runtime).Engine().Read(ctx, true)
		if err == nil {
			break
		}
		if !errors.Is(err, raft.ErrNotLeader) && !errors.Is(err, raft.ErrLeadershipLost) {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	login()
	before := view().Index()
	call(0, "compose", "resume", "--tenant", "tenant", "--operation", "create-target")
	if view().Index() != before {
		t.Fatal("accepted create resume wrote new effects")
	}
	loaded, err := userauth.LoadCompose(home, *c, session, "create-target")
	if err != nil || loaded.Target == nil || *loaded.Target != target || loaded.Digest != intent.Digest || loaded.Expected != 0 {
		t.Fatal("same DB/relogin changed frozen absent target", err)
	}
	again, err := userauth.LoadOperation(home, *c, session, accepted.Operation.RequestID)
	if err != nil || !bytes.Equal(original, control.OperationBytes(again.Operation)) || !bytes.Equal(signature, again.Operation.Signature) || again.Result == nil || *again.Result != *accepted.Result {
		t.Fatal("same create request/signature/result changed", err)
	}
}
