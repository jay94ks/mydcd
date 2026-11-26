// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/app"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestRealComposeAppScopeAdmissionAndFrozenOriginalRecovery(t *testing.T) {
	testRealComposeAppBoundary(t, false, false, "app-scope")
}

func verifyComposeAppScopeCLI(t *testing.T, ctx context.Context, root string, call func(int, ...string) []byte, login func(), current func() (*userauth.Client, access.Session), client *userauth.Client, session access.Session, peer mydcp.Peer, policy control.Policy, view func() state.State, prepare func(string, string, uint64, any) control.UserOperation, apply func(control.UserOperation, state.Code) state.Result, runtime **app.Runtime, cfg config.Node) {
	t.Helper()
	// This fixture has no network/workload/Ingress native modules. Seed one
	// PRE-CHANGE accepted record through the unchanged consensus reducer only;
	// every NEW public request below uses the authenticated product edge.
	c, err := deployment.ParseCompose(legacyAppComposeDocument(1))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := policy.Catalog(view())
	if err != nil {
		t.Fatal(err)
	}
	planning, err := policy.AppPlanning(view(), session.User, "tenant")
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := deployment.Compile(c, catalog, planning)
	if err != nil {
		t.Fatal(err)
	}
	frozenRaw, _ := frozen.Encode()
	upload := func(id string, b deployment.Blueprint, raw []byte) {
		t.Helper()
		scope := b.Scope()
		apply(prepare(id+"-upload", "begin-app-upload", 0, control.AppUploadBegin{Tenant: "tenant", App: scope.App, Deployment: scope.Deployment, ID: id, Length: len(raw), Digest: sha256.Sum256(raw)}), state.Applied)
		for part, start := 0, 0; start < len(raw); part, start = part+1, start+deployment.ArtifactPartBytes {
			apply(prepare(fmt.Sprintf("%s-part%d", id, part), "put-app-part", uint64(part+1), control.AppUploadPart{Tenant: "tenant", ID: id, Index: part, Data: raw[start:min(start+deployment.ArtifactPartBytes, len(raw))]}), state.Applied)
		}
	}
	legacyFile := filepath.Join(root, "legacy-plan.json")
	if err = os.WriteFile(legacyFile, frozenRaw, 0600); err != nil {
		t.Fatal(err)
	}
	beforeLegacy := view().Index()
	call(2, "compose", "up", "--tenant", "tenant", "--operation", "new-old-contract", "--plan", legacyFile)
	if view().Index() != beforeLegacy {
		t.Fatal("legacy plan changed state before input rejection")
	}
	upload("legacy", frozen, frozenRaw)
	origin := prepare("legacy-accept", "begin-app", 0, control.AppBegin{Tenant: "tenant", App: "app", Deployment: "app", Upload: "legacy", Operation: "legacy"})
	deniedIndex := view().Index()
	reply, err := client.Operation(ctx, peer, origin, false)
	if err == nil || reply.Code != "denied" || reply.Result != nil || view().Index() != deniedIndex {
		t.Fatal("new legacy begin not blocked before Raft", reply.Code, err)
	}
	oldCommand, err := origin.Command()
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := (*runtime).Engine().Submit(ctx, oldCommand)
	if err != nil || accepted.Result.Code != state.Applied {
		t.Fatal("historical reducer replay changed", accepted.Result, err)
	}
	bridge := ""
	for _, step := range frozen.Steps() {
		if step.Kind == "bridge" {
			bridge = step.Key
		}
	}
	if bridge == "" {
		t.Fatal("historical bridge missing")
	}
	progress := func(action string) {
		t.Helper()
		s := view()
		apps, e := policy.Apps(s)
		if e != nil {
			t.Fatal(e)
		}
		inv, ok := apps.Inventory("tenant", "app")
		if !ok {
			t.Fatal("historical inventory missing")
		}
		r := control.AppProgress{Schema: 1, Cluster: policy.Cluster, Reporter: (*runtime).Identity.Public, Tenant: "tenant", App: "app", Operation: "legacy", Key: bridge, Action: action, Expected: inv.Revision(), At: uint64(time.Now().Unix()), Epoch: s.ModuleEpoch(), RequestID: "legacy-" + action, RootRevision: s.Object(control.AppsKey).Revision}
		if control.StageReport(r.Action) {
			r.Stage = policy.StageDigest(s, r.Tenant, r.App, r.Key)
		}
		r.Signature = ed25519.Sign((*runtime).Identity.Private, control.AppProgressBytes(r))
		raw, _ := json.Marshal(r)
		cmd, e := policy.ResolveAppCommand(s, "app-progress", r.Reporter, raw)
		if e != nil {
			t.Fatal(action, e)
		}
		committed, e := (*runtime).Engine().Submit(ctx, cmd)
		if e != nil || committed.Result.Code != state.Applied {
			t.Fatal(action, committed.Result, e)
		}
	}
	progress("prepare")
	progress("send")
	apps, err := policy.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	execution, ok := apps.Execution("tenant", "app")
	if !ok {
		t.Fatal("historical execution missing")
	}
	stage, ok := execution.Stage(bridge)
	if !ok || stage.Command == nil {
		t.Fatal("historical exact source command missing")
	}
	sourceCommand := *stage.Command
	committed, err := (*runtime).Engine().Submit(ctx, sourceCommand)
	if err != nil || committed.Result.Code != state.Applied {
		t.Fatal("original source metadata", committed.Result, err)
	}
	progress("collect")
	source := view().Object(bridge)
	if !source.Present {
		t.Fatal("source metadata absent")
	}
	// No NativeReady/observation is fabricated. This source is only registered
	// desired metadata; the new app must remain Planned in this fixture.
	managedName := deployment.PoolID("tenant", "app", "app", "node-a")
	raw := appReferenceDocument(managedName)
	raw = []byte(strings.Replace(string(raw), "name: app\n", "name: consumer\n", 1))
	raw = []byte(strings.ReplaceAll(string(raw), "10.79.0.10", "10.79.0.30"))
	file := filepath.Join(root, "app.yaml")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	readIndex := view().Index()
	plannedRaw := bytes.TrimSpace(call(0, "compose", "plan", "--tenant", "tenant", "-f", file))
	plan, err := deployment.DecodeBlueprint(plannedRaw)
	if err != nil || plan.CheckAppInput() != nil || view().Index() != readIndex {
		t.Fatal("new named-reference plan", err)
	}
	refs := 0
	for _, step := range plan.Steps() {
		if step.Kind == "bridge" || step.Kind == "tunnel" {
			t.Fatal("new app recreated management network")
		}
		if step.Kind == "network-ref" {
			refs++
			var ref deployment.NetworkReference
			if json.Unmarshal(step.Goal, &ref) != nil || ref.Source.Key != bridge || ref.Source.Generation != source.Generation || ref.Source.Revision != source.Revision {
				t.Fatal("wrong immutable source")
			}
		}
	}
	if refs != 1 {
		t.Fatal("missing borrowed reference", refs)
	}
	call(0, "compose", "up", "--tenant", "tenant", "-f", file, "--operation", "consumer-up")
	apps, err = policy.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	consumer, ok := apps.Execution("tenant", "consumer")
	if !ok || consumer.Status() != "Planned" || consumer.Blueprint().CheckAppInput() != nil {
		t.Fatal("new public app acceptance")
	}
	badFile := filepath.Join(root, "management-in-app.yaml")
	if err = os.WriteFile(badFile, legacyAppComposeDocument(1), 0600); err != nil {
		t.Fatal(err)
	}
	readIndex = view().Index()
	if _, err = client.PlanApp(ctx, peer, session, "tenant", control.AppPlanRequest{Document: legacyAppComposeDocument(1)}); err == nil {
		t.Fatal("daemon planning accepted inline management network")
	}
	call(1, "compose", "plan", "--tenant", "tenant", "-f", badFile)
	if view().Index() != readIndex {
		t.Fatal("invalid app planning mutated state")
	}
	login()
	client, session = current()
	for _, resume := range []bool{false, true} {
		var recovered userauth.Reply
		if resume {
			recovered, err = client.Resume(ctx, peer, session, origin)
		} else {
			recovered, err = client.Result(ctx, peer, session, origin)
		}
		if err != nil || recovered.Result == nil || *recovered.Result != accepted.Result {
			t.Fatal("historical original receipt", resume, recovered.Code, err)
		}
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
	apps, err = policy.Apps(view())
	if err != nil {
		t.Fatal(err)
	}
	old, ok := apps.Execution("tenant", "app")
	if !ok || old.Blueprint().Digest() != frozen.Digest() {
		t.Fatal("historical artifact rewritten")
	}
	originalStage, ok := old.Stage(bridge)
	if !ok || originalStage.Command == nil || *originalStage.Command != sourceCommand {
		t.Fatal("original stage/command lost")
	}
	consumer, ok = apps.Execution("tenant", "consumer")
	if !ok || consumer.Blueprint().CheckAppInput() != nil {
		t.Fatal("new app same DB restore")
	}
	if view().Object(bridge) != source {
		t.Fatal("borrow changed original management object")
	}
	receipt, err := client.Resume(ctx, peer, session, origin)
	if err != nil || receipt.Result == nil || *receipt.Result != accepted.Result {
		t.Fatal("same DB historical receipt", err)
	}
	t.Log("authenticated CLI/MYDCP/N1/Raft/DB: new app-only plan and acceptance with exact registered source; old new submission denied; historical reducer/stage/receipt and same DB/Snapshot retained; native modules disabled, no NativeReady or borrow closure claimed")
}
