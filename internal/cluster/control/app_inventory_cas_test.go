// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/reconcile"
)

func preparedInventoryReport(t *testing.T) (*backupCoreFixture, AppProgress) {
	t.Helper()
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	key := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	managedDNSTaskCoreProgress(t, f, "first", "prepare", key, nil)
	a, _ := f.p.Apps(f.s)
	i, _ := a.Inventory("tenant", "first")
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "first", Operation: "run-first", Key: key, Action: "send", Expected: i.Revision(), At: 10, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "same-prepared-send"}
	r.Stage = f.p.StageDigest(f.s, r.Tenant, r.App, r.Key)
	return f, r
}

func TestAppProgressSendAcrossUnrelatedRoot(t *testing.T) {
	f, r := preparedInventoryReport(t)
	a, _ := f.p.Apps(f.s)
	e, _ := a.Execution(r.Tenant, r.App)
	before, _ := e.Stage(r.Key)
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	cmd, err := r.Command()
	if err != nil || cmd.Target != state.AppInventoryTarget {
		t.Fatal(err)
	}
	f.apply("unrelated-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "other", Deployment: "deploy", ID: "other", Length: 1, Digest: sha256.Sum256([]byte{1})}, state.Applied)
	var result state.Result
	f.s, result, err = state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("unchanged original inventory send blocked by unrelated Apps root", result, err)
	}
	a, _ = f.p.Apps(f.s)
	e, _ = a.Execution(r.Tenant, r.App)
	after, _ := e.Stage(r.Key)
	if before.Command == nil || after.Command == nil || *before.Command != *after.Command || after.Journal.Pending == nil || after.Journal.Pending.Phase != reconcile.Dispatched {
		t.Fatal("report replaced the original command")
	}
	wire, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, duplicateResult, err := state.ApplyTransactional(restored, restored.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || duplicateResult != result || duplicate.Object(AppsKey) != restored.Object(AppsKey) {
		t.Fatal("snapshot duplicate changed original outcome", duplicateResult, err)
	}
}

func TestAppInventoryCASRejectsChangedCoordinatesAuthorityAndMode(t *testing.T) {
	for _, mode := range []string{"future-root", "zero-root", "future-inventory", "stale-stage", "no-stage", "operation", "step", "signature", "target-tamper", "actor", "unknown-member", "current-credential", "observe-mode"} {
		t.Run(mode, func(t *testing.T) {
			f, r := preparedInventoryReport(t)
			signer := f.node
			switch mode {
			case "future-root":
				r.RootRevision = f.s.Object(AppsKey).Revision + 100
			case "zero-root":
				r.RootRevision = 0
			case "future-inventory":
				r.Expected++
			case "stale-stage":
				r.Stage = strings.Repeat("0", 64)
			case "no-stage":
				r.Stage = ""
			case "operation":
				r.Operation = "other"
			case "step":
				r.Key = deployment.ResourceKey("task", "tenant", "first", "other")
			case "unknown-member":
				signer = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{89}, 32))
				r.Reporter = [32]byte(signer.Public().(ed25519.PublicKey))
			case "observe-mode":
				r.Action = "observe"
			case "current-credential":
				key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{77}, 32))
				f.replaceOwnKey("key", "replacement", [32]byte(key.Public().(ed25519.PublicKey)), nil)
			}
			r.Signature = ed25519.Sign(signer, AppProgressBytes(r))
			if mode == "signature" {
				r.Signature[0] ^= 1
			}
			cmd, err := r.Command()
			if mode == "zero-root" {
				if err == nil {
					t.Fatal("invalid basis encoded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "target-tamper" {
				cmd.Target = state.AppObservationTarget
				cmd.RequestID = state.ReportRequestID(cmd)
			}
			if mode == "actor" {
				cmd.Actor = "user/reporter"
				cmd.RequestID = state.ReportRequestID(cmd)
			}
			before := f.s.Object(AppsKey)
			after, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code == state.Applied || after.Object(AppsKey) != before {
				t.Fatal("invalid progress changed an app", result, err)
			}
		})
	}
}

func TestAppInventoryCASBindingPreflightUsesCurrentReducer(t *testing.T) {
	f := deliveryControlFixture(t)
	const app = "source-app"
	managedDNSTaskCoreSubmit(t, f, app, deployment.ResourceKey("network-ref", "tenant", app, "lan/node-a"), true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	key := deployment.ResourceKey("task", "tenant", app, "web")
	managedDNSTaskCoreSubmit(t, f, app, key, true, state.Applied)
	a, _ := f.p.Apps(f.s)
	i, _ := a.Inventory("tenant", app)
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: app, Operation: "run-" + app, Key: key, Action: "bind-inputs", Expected: i.Revision(), At: 10, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "original-binding"}
	r.Stage = f.p.StageDigest(f.s, r.Tenant, r.App, r.Key)
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	f.apply("unrelated-bind-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "other", Deployment: "deploy", ID: "other", Length: 1, Digest: sha256.Sum256([]byte{1})}, state.Applied)
	if err := f.p.CheckAppBinding(f.s, r); err != nil {
		t.Fatal("same inventory binding preflight", err)
	}
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("current binding reducer", result, err)
	}
	a, err = f.p.Apps(next)
	if err != nil || len(a.bindings.Live()) != 1 {
		t.Fatal("exact original binding missing", err)
	}
}

func TestAppInventoryCASRetirementKeepsOriginalRemoval(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	key := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	managedDNSTaskCoreSubmit(t, f, "first", key, true, state.Applied)
	a, _ := f.p.Apps(f.s)
	i, _ := a.Inventory("tenant", "first")
	f.apply("stop-first", "down-app", i.Revision(), AppDown{Tenant: "tenant", App: "first", Operation: "stop-first"}, state.Applied)
	a, _ = f.p.Apps(f.s)
	i, _ = a.Inventory("tenant", "first")
	retirement, _ := i.Retirement()
	mutation, ok := i.Removal(key, "drain")
	if !ok || !i.CanRetire(key) {
		t.Fatal("original removal not ready")
	}
	r := AppProgress{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(f.node.Public().(ed25519.PublicKey)), Tenant: "tenant", App: "first", Operation: retirement.ID, Key: key, Action: "retire-send", Expected: i.Revision(), At: 11, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision, RequestID: "original-removal", Retire: &AppRetirementProgress{Phase: "drain"}}
	r.Signature = ed25519.Sign(f.node, AppProgressBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	f.apply("unrelated-retire-upload", "begin-app-upload", 0, AppUploadBegin{Tenant: "tenant", App: "other", Deployment: "deploy", ID: "other", Length: 1, Digest: sha256.Sum256([]byte{1})}, state.Applied)
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("original retirement send", result, err)
	}
	a, _ = f.p.Apps(next)
	i, _ = a.Inventory("tenant", "first")
	after, _ := i.Removal(key, "drain")
	if after.Command != mutation.Command || after.Journal.Pending == nil || after.Journal.Pending.Phase != reconcile.Dispatched {
		t.Fatal("retirement changed original mutation")
	}
}
