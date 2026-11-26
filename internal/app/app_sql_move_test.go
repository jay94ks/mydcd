// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

// One new integration path consumes the existing two-Engine/DNS SQL fixture.
// It does not re-run the old CRUD matrix or submit intermediate owner/App CAS.
func testManagedSQLColdMove(t *testing.T, ctx context.Context, a *Runtime, root, file, document string, docker [2]*engine.Client, cli func([]*os.File, ...string) []byte, stageMove func(string, string), request func(int, string, string, string, ...int) map[string]any, observeB func(string) (ModuleObservation, error), read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool), stopB, startB func(), cutB func(func()), nodeBConfig, nodeBNetNS string) *moveProcessCutEvidence {
	t.Helper()
	p := a.controlPolicy
	registry := func() control.Volumes {
		v, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	original, ok := registry().Native("tenant", "app", "data")
	if !ok || original.Owner.Node != "node-b" {
		t.Fatal("original SQL owner")
	}
	const reserve = uint64(512 << 20)
	core, _ := registry().Volume(original.Spec.Scope)
	change("sql-move-source-capacity", "set-volume-capacity", core.Revision(), control.VolumeCapacity{Scope: original.Spec.Scope, Native: control.VolumeNativeDigest(original), Bytes: reserve})
	for _, node := range []string{"node-a", "node-b"} {
		for _, tenant := range []string{"", "tenant"} {
			change("sql-move-budget-"+node+tenant, "set-volume-backup-limit", 0, control.VolumeBackupLimit{Tenant: tenant, Node: node, Bytes: reserve, Count: 1, StagingBytes: reserve, StagingCount: 1, Original: &control.OriginalVolumeLimit{Bytes: reserve, Count: 1}})
		}
	}
	value := strings.Repeat("M", 128<<10)
	if r := request(0, "POST", "/row?key=move-original&operation=move-create", value); r["value"] != value || r["operation"] != "move-create" {
		t.Fatal("source SQL original operation")
	}
	if r := request(0, "GET", "/dns", ""); r["db_address"] != "198.19.80.18" || r["db_host"] != "db" {
		t.Fatal("source PHP resolver", r)
	}
	input, err := deployment.ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	db := input.Services["db"]
	db.MyDC.Node = "node-a"
	attachment := db.Networks["app"]
	attachment.IPv4 = "198.19.80.3"
	db.Networks["app"] = attachment
	resources, err := p.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	network, exists := resources.Networks.NamedNetwork("tenant", input.Networks["app"].Name, db.MyDC.Node)
	if !exists || len(network.Pools) != 1 {
		t.Fatal("explicit target-node managed resolver is required")
	}
	db.DNS = []string{network.Pools[0].Gateway.String()}
	input.Services["db"] = db
	volume := input.Volumes["data"]
	volume.MyDC.Node = "node-a"
	volume.MyDC.Capacity = deployment.VolumeSize(reserve)
	input.Volumes["data"] = volume
	if input.MyDC.Ingress == nil {
		t.Fatal("original SQL ingress declaration required")
	}
	input.MyDC.Ingress.Listeners = append(input.MyDC.Ingress.Listeners, deployment.ListenerDeclaration{Address: sqlMoveBlockedTCP}, deployment.ListenerDeclaration{Address: sqlMoveBlockedUDP, TLS: true, HTTP3: true})
	target, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, target, 0600); err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(root, "sql-move-plan.json")
	cli(nil, "--tenant", "tenant", "volume", "move", "app/data", "--id", "sql-cold-move", "-f", file, "--max-size", strconv.FormatUint(reserve, 10), "--max-entries", "4096", "--transfer-timeout", "5m", "--dry-run", "--save-plan", planFile)
	raw, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := control.DecodeAppMovePlan(bytes.TrimSpace(raw))
	if err != nil || plan.Begin.Scope != original.Spec.Scope || plan.Begin.Target.Node != "node-a" {
		t.Fatal("same logical SQL move plan", err)
	}
	applyMove := func(id, plan string, resume bool) {
		t.Helper()
		var fds []*os.File
		for range 2 {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err = writer.Write([]byte("private-native-group-password\n")); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			writer.Close()
			fds = append(fds, reader)
		}
		// A first run and a continuation are the same command: the saved plan
		// names the move, and an accepted move is continued, never restarted.
		_ = resume
		args := []string{"--tenant", "tenant", "volume", "move", "--plan", plan, "--group-password-fd", "tenant/common=3", "--group-password-fd", "tenant/db-admin=4"}
		cli(fds, args...)
		for _, fd := range fds {
			fd.Close()
		}
	}
	// Upload and accept before native failures trigger new health/DNS reports.
	// Missing Group input is an explicit product barrier, not a test-owned pause
	// or a reason to re-sign/re-submit a rejected root CAS.
	stageMove("sql-cold-move", planFile)
	selection := control.VolumeMoveSelection{Scope: original.Spec.Scope, ID: "sql-cold-move"}
	accepted, pending, found := registry().Move(selection)
	if !found || pending.Phase != volumes.Prepared || pending.Preparation != nil || pending.Fence != nil || pending.CommitRevision != 0 {
		t.Fatal("original accepted SQL move must await target approval before native readiness probes")
	}
	releasePort := holdSQLMovePorts(t, ctx, root, nodeBNetNS, wait)
	resumePreparation := armSQLMoveNativePreparation(t, ctx, a, docker[1], original, input.Networks["app"].Name, filepath.Join(root, "private.pem"), releasePort, read, wait)
	applyMove("sql-cold-move", planFile, true)
	t.Log("original SQL row/operation128KiB -> target upload and move accepted before native faults -> missing Group input preserves original Prepared intent -> explicit CLI resume approves same request; normal daemon source/target own intermediate transitions")
	resumePreparation(accepted)
	last := ""
	lastTargetCause := ""
	progressed := time.Now()
	lastProgressNotice := time.Time{}
	lastNativeCheck := time.Time{}
	seenNative := map[string]string{}
	wait("same SQL move normal daemon target app Healthy", func() bool {
		v := registry()
		_, move, ok := v.Move(selection)
		apps, err := p.Apps(read().State)
		if err != nil {
			t.Fatal(err)
		}
		ex, active := apps.Execution("tenant", "app")
		status := string(move.Phase) + "/" + ex.ActiveOperation() + "/" + ex.Status()
		inventory, _ := apps.Inventory("tenant", "app")
		a.mu.RLock()
		cause := fmt.Sprint(a.moduleError)
		a.mu.RUnlock()
		if cause != lastTargetCause {
			lastTargetCause = cause
			t.Log("original SQL local owner cause", move.Phase, cause)
		}
		if retirement, ok := inventory.Retirement(); ok {
			for _, target := range retirement.Targets {
				status += fmt.Sprintf("/%s:%t:%t:%t:%t", target.Original.Step.Key, target.Closed, target.Drain != nil && target.Drain.Result != nil, target.Proof != nil, target.Delete != nil && target.Delete.Result != nil)
			}
		} else {
			for _, step := range ex.Steps() {
				stage, _ := ex.Stage(step.Key)
				status += fmt.Sprintf("/%s:%t:%t", step.Key, stage.Result != nil, stage.Observation != nil && stage.Observation.Applied)
			}
		}
		if status != last {
			last, progressed = status, time.Now()
			t.Log("original SQL move phase", status)
		}
		// Applied metadata can remain unchanged during the original image pull,
		// Create and Start. Count actual matching native transitions as progress,
		// never an age string or evidence that the Task is Applied/Healthy.
		if move.Phase == volumes.Activating && time.Since(lastNativeCheck) >= time.Second {
			lastNativeCheck = time.Now()
			for _, step := range ex.Steps() {
				stage, _ := ex.Stage(step.Key)
				if step.Kind != "task" || stage.Result == nil || stage.Result.Code != state.Applied || stage.Observation != nil && stage.Observation.Applied {
					continue
				}
				for _, native := range docker {
					if native.Owner != engine.Owner(p.Cluster, step.Owner) {
						continue
					}
					inspectCtx, stop := context.WithTimeout(ctx, 2*time.Second)
					rows, err := native.API.ContainerList(inspectCtx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+native.Owner, "org.mydc.key="+step.Key, "org.mydc.generation="+strconv.FormatUint(stage.Result.Generation, 10))})
					stop()
					if err != nil {
						t.Fatal("original SQL target native progress read", step.Key, err)
					}
					for _, row := range rows.Items {
						nativeState := fmt.Sprint(row.State)
						if seenNative[row.ID] != nativeState {
							seenNative[row.ID], progressed = nativeState, time.Now()
							t.Log("original SQL target native progress", step.Key, stage.Result.Generation, row.ID, nativeState)
						}
						if row.State == "exited" || row.State == "dead" {
							t.Fatal("original SQL target exited before readiness", step.Key, row.ID, row.Status)
						}
					}
				}
			}
		}
		// Image pull/unpack can precede the first native container. Absence of
		// a new observation is diagnostic, not proof that this operation failed.
		// The fixture's finite overall context still bounds this wait.
		if time.Since(progressed) > 60*time.Second && time.Since(lastProgressNotice) >= 60*time.Second {
			lastProgressNotice = time.Now()
			for _, step := range ex.Steps() {
				stage, _ := ex.Stage(step.Key)
				if o := stage.Observation; o != nil {
					t.Log("original SQL verification observation", step.Key, "completion", step.Completion, "sequence", o.Sequence, "at", o.At, "now", time.Now().Unix(), "applied", o.Applied, "healthy", o.Healthy)
				}
			}
			if retirement, retiring := inventory.Retirement(); retiring {
				for _, target := range retirement.Targets {
					if !target.Closed {
						t.Log("original SQL retirement blocked target", target.Original.Step.Key, "eligible", inventory.CanRetire(target.Original.Step.Key))
					}
				}
			}
			for _, step := range ex.Steps() {
				if step.Kind != "task" || step.Owner != a.Identity.Public {
					continue
				}
				stage, _ := ex.Stage(step.Key)
				if stage.Result == nil {
					continue
				}
				binding, found := apps.Binding(deployment.ObjectRef{Key: step.Key, Generation: stage.Result.Generation, Revision: stage.Result.Revision})
				t.Log("target original Binding", step.Key, "present", found, "Volume pins", len(binding.Pins()), "Secret grants", len(binding.Grants()))
			}
			t.Log("original SQL move awaiting new progress; preserve original operation/refs", status)
		}
		return ok && move.Irreversible && move.Fence != nil && move.Verified != nil && active && ex.ActiveOperation() == "sql-cold-move" && ex.Status() == "Succeeded" && ex.Health(uint64(time.Now().Unix())) == "Healthy"
	})
	job, move, ok := registry().Move(selection)
	if !ok || job.Origin.Change.Action != "begin-volume-move" || move.Fence == nil || !move.Fence.Stopped || move.Fence.Binding.Source != original.Owner || move.Verified == nil {
		t.Fatal("original source fence/copy evidence missing")
	}
	next, ok := registry().Native("tenant", "app", "data")
	if !ok || next.Spec.Scope != original.Spec.Scope || next.Owner.Node != "node-a" || next.Owner.Native == original.Owner.Native {
		t.Fatal("logical Volume replaced or wrong target owner")
	}
	if r := request(0, "GET", "/dns", ""); r["db_host"] != "db" || r["db_address"] != "198.19.80.3" {
		t.Fatal("PHP original name did not follow new address", r)
	}
	if r := request(0, "GET", "/row?key=move-original", ""); r["value"] != value {
		t.Fatal("copied SQL row missing")
	}
	if r := request(0, "GET", "/operation?id=move-create", ""); r["operation"] != "move-create" || r["value"] != value {
		t.Fatal("original committed SQL result missing")
	}
	updated := strings.Repeat("N", 128<<10)
	if r := request(0, "PUT", "/row?key=move-original&operation=move-target-write", updated); r["value"] != updated {
		t.Fatal("target new SQL write")
	}
	// Allow real SQL recovery/new writes before transfer cleanup completes.
	// Cleanup must retire only the original artifact/restore responsibility;
	// it cannot rehash, recopy or delete the now-writable target tree.
	wait("original SQL move actual activation and both transfer cleanups", func() bool {
		_, current, ok := registry().Move(selection)
		return ok && current.Phase == volumes.Completed && current.ReaderClosed != nil && current.Activated != nil && current.SourceCleanup != nil && current.TargetCleanup != nil
	})
	if r := request(0, "GET", "/operation?id=move-target-write", ""); r["value"] != updated || r["operation"] != "move-target-write" {
		t.Fatal("target new SQL result lost during transfer cleanup")
	}
	cli(nil, "--tenant", "tenant", "op", "show", "sql-cold-move")
	cli(nil, "--tenant", "tenant", "op", "resume", "sql-cold-move")
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	stopB()
	startB()
	wait("original node-b DB/Ingress resumes beside moved SQL writer", func() bool {
		r, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		e, ok := r.Execution("tenant", "app")
		if !ok || e.ActiveOperation() != "sql-cold-move" || e.Health(uint64(time.Now().Unix())) != "Healthy" {
			return false
		}
		// The shared view can still contain a fresh, pre-stop observation.
		// Query the restarted original owner: it must have rebound this exact
		// Ingress generation/revision before sending the first HTTP request.
		for _, step := range e.Steps() {
			if step.Kind != "ingress" || step.Node != "node-b" {
				continue
			}
			stage, _ := e.Stage(step.Key)
			if stage.Result == nil || stage.Result.Code != state.Applied {
				return false
			}
			native, err := observeB(step.Key)
			return err == nil && native.Schema == 1 && native.Key == step.Key && native.Generation == stage.Result.Generation && native.Revision == stage.Result.Revision && native.Ready && native.Ingress != nil && native.Ingress.Ready && !native.Ingress.Draining && !native.Ingress.Gone && len(native.Ingress.Listeners) > 0
		}
		return false
	})
	if r := request(0, "GET", "/row?key=move-original", ""); r["value"] != updated {
		t.Fatal("target SQL write after source daemon restart")
	}
	old, err := docker[1].API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{})
	if err != nil || old.Volume.Mountpoint == "" {
		t.Fatal("retained fenced source lost", err)
	}
	mounted, err := docker[1].API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", original.Owner.Native)})
	if err != nil || len(mounted.Items) != 0 {
		t.Fatal("original source writer resurrected", err)
	}
	_, settledFirst, ok := registry().Move(selection)
	firstProofs, err := json.Marshal(settledFirst)
	if !ok || err != nil || settledFirst.Phase != volumes.Completed {
		t.Fatal("original SQL move facts missing before reverse", err)
	}
	// Returning to node-b needs a NEW physical copy in addition to its retained
	// old source. Keep backup/staging budgets and explicitly reserve that space.
	for _, limit := range registry().BackupLimits() {
		if limit.Node != "node-b" {
			continue
		}
		expected := limit.Revision
		limit.Revision, limit.Owner = 0, [32]byte{}
		limit.Original = &control.OriginalVolumeLimit{Bytes: 2 * reserve, Count: 2}
		change("sql-return-capacity-"+limit.Tenant, "set-volume-backup-limit", expected, limit)
	}
	returnInput, err := deployment.ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	returnVolume := returnInput.Volumes["data"]
	returnVolume.MyDC.Capacity = deployment.VolumeSize(reserve)
	returnInput.Volumes["data"] = returnVolume
	returnRaw, err := yaml.Marshal(returnInput)
	if err != nil {
		t.Fatal(err)
	}
	returnFile, returnPlanFile := filepath.Join(root, "sql-return-app.yaml"), filepath.Join(root, "sql-return-plan.json")
	if err = os.WriteFile(returnFile, returnRaw, 0600); err != nil {
		t.Fatal(err)
	}
	cli(nil, "--tenant", "tenant", "volume", "move", "app/data", "--id", "sql-return-move", "-f", returnFile, "--max-size", strconv.FormatUint(reserve, 10), "--max-entries", "4096", "--transfer-timeout", "5m", "--dry-run", "--save-plan", returnPlanFile)
	returnRaw, err = os.ReadFile(returnPlanFile)
	if err != nil {
		t.Fatal(err)
	}
	returnPlan, err := control.DecodeAppMovePlan(bytes.TrimSpace(returnRaw))
	if err != nil || returnPlan.Begin.Scope != original.Spec.Scope || returnPlan.Begin.Target.Node != original.Owner.Node || returnPlan.Begin.Target.Materialization != "m-sql-return-move" || returnPlan.Begin.App == nil || returnPlan.Begin.App.Operation != "sql-cold-move" {
		t.Fatal("reverse SQL plan did not preserve current writer or fresh materialization", err)
	}
	applyMove("sql-return-move", returnPlanFile, false)
	returnSelection := control.VolumeMoveSelection{Scope: original.Spec.Scope, ID: "sql-return-move"}
	cut := cutSQLReverseReceive(t, a, nodeBConfig, returnSelection, read, observeB, wait, cutB, startB)
	wait("normal reverse SQL move activation/transfer settlement and app Healthy", func() bool {
		v := registry()
		_, move, ok := v.Move(returnSelection)
		apps, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		execution, active := apps.Execution("tenant", "app")
		return ok && move.Phase == volumes.Completed && move.ReaderClosed != nil && move.Activated != nil && move.SourceCleanup != nil && move.TargetCleanup != nil && active && execution.ActiveOperation() == "sql-return-move" && execution.Status() == "Succeeded" && execution.Health(uint64(time.Now().Unix())) == "Healthy"
	})
	returned, ok := registry().Native("tenant", "app", "data")
	storedReturn, completedReturn, _ := registry().Move(returnSelection)
	if storedReturn.Digest() != cut.checkpoint.Intent.Job.Digest() || completedReturn.ReaderClosed == nil || completedReturn.ReaderClosed.Consumer != cut.reader || completedReturn.Manifest == nil || completedReturn.Manifest.Artifact != cut.checkpoint.Intent.Manifest.Artifact {
		t.Fatal("SQL reverse process recovery replaced original job/artifact/reader")
	}
	if !ok || returned.Spec.Scope != original.Spec.Scope || returned.Owner.Node != original.Owner.Node || returned.Owner.Native == original.Owner.Native || returned.Owner.Native == next.Owner.Native || returned.Spec.Materialization != returnPlan.Begin.Target.Materialization {
		t.Fatal("reverse SQL reused old data/materialization")
	}
	if r := request(0, "GET", "/dns", ""); r["db_host"] != "db" || r["db_address"] != "198.19.80.18" {
		t.Fatal("PHP original name did not follow reverse SQL address", r)
	}
	if r := request(0, "GET", "/row?key=move-original", ""); r["value"] != updated {
		t.Fatal("reverse SQL lost the first target's new write")
	}
	if r := request(0, "GET", "/operation?id=move-target-write", ""); r["operation"] != "move-target-write" || r["value"] != updated {
		t.Fatal("reverse SQL lost original target write result")
	}
	if r := request(0, "GET", "/operation?id=move-create", ""); r["operation"] != "move-create" || r["value"] != value {
		t.Fatal("reverse SQL lost original source write result")
	}
	returnedValue := strings.Repeat("R", 128<<10)
	if r := request(0, "PUT", "/row?key=move-original&operation=move-return-write", returnedValue); r["value"] != returnedValue {
		t.Fatal("fresh returned SQL writer cannot commit a new operation")
	}
	for _, retained := range []struct {
		engine *engine.Client
		native string
	}{{docker[1], original.Owner.Native}, {docker[0], next.Owner.Native}} {
		old, err := retained.engine.API.VolumeInspect(ctx, retained.native, client.VolumeInspectOptions{})
		if err != nil || old.Volume.Mountpoint == "" {
			t.Fatal("reverse lost a retained physical source", err)
		}
		attachments, err := retained.engine.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", retained.native)})
		if err != nil || len(attachments.Items) != 0 {
			t.Fatal("reverse resurrected an obsolete SQL source", err)
		}
	}
	volumeCore, _ := registry().Volume(original.Spec.Scope)
	_, firstCompleted, _ := registry().Move(selection)
	retainedProofs, err := json.Marshal(firstCompleted)
	if err != nil || !bytes.Equal(firstProofs, retainedProofs) || len(volumeCore.Moves()) != 2 || len(volumeCore.Retained()) != 2 || len(volumeCore.Consumers()) != 1 || firstCompleted.Phase != volumes.Completed {
		t.Fatal("reverse SQL discarded move history, retained sources or current writer")
	}
	cli(nil, "--tenant", "tenant", "op", "show", "sql-return-move")
	cli(nil, "--tenant", "tenant", "op", "resume", "sql-return-move")
	if err = a.Engine().Snapshot(ctx); err != nil {
		t.Fatal(err)
	}
	for _, moveID := range []string{"sql-cold-move", "sql-return-move"} {
		_, move, _ := registry().Move(control.VolumeMoveSelection{Scope: original.Spec.Scope, ID: moveID})
		retainedNode := move.Binding.Source.Node
		nativeRetainedSource(t, cli(nil, "--tenant", "tenant", "volume", "show", "app/data"), moveID, retainedNode, "retained")
		requestID := "delete-retained-" + moveID
		args := []string{"--tenant", "tenant", "volume", "delete", "app/data", "--retained", moveID, "--id", requestID, "--no-wait"}
		cli(nil, args...)
		cli(nil, args...) // Same original result; never a fresh CAS or target.
		cli(nil, "op", "show", requestID)
		selected := control.VolumeMoveSelection{Scope: original.Spec.Scope, ID: moveID}
		wait("explicit obsolete SQL source deletion/native Gone", func() bool {
			_, move, ok := registry().Move(selected)
			return ok && move.SourceDeletion != nil && move.SourceDeletion.Gone != nil
		})
		nativeRetainedSource(t, cli(nil, "--tenant", "tenant", "volume", "show", "app/data"), moveID, retainedNode, "removed")
	}
	for _, obsolete := range []struct {
		engine *engine.Client
		native string
	}{{docker[1], original.Owner.Native}, {docker[0], next.Owner.Native}} {
		if _, err := obsolete.engine.API.VolumeInspect(ctx, obsolete.native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("explicit SQL source deletion did not remove original native", err)
		}
	}
	volumeCore, _ = registry().Volume(original.Spec.Scope)
	if len(volumeCore.Retained()) != 0 || len(volumeCore.Consumers()) != 1 {
		t.Fatal("explicit source deletion kept an obsolete reference or removed current writer")
	}
	if r := request(0, "GET", "/row?key=move-original", ""); r["value"] != returnedValue {
		t.Fatal("obsolete SQL source deletion touched current returned data")
	}
	var inspected struct{ Volume control.VolumeView }
	if json.Unmarshal(cli(nil, "--tenant", "tenant", "volume", "show", "app/data"), &inspected.Volume) != nil || inspected.Volume.RetainedSources != 0 || inspected.Volume.RetainedPending != 0 || inspected.Volume.RetainedRemoved != 2 || inspected.Volume.Owner != returned.Owner {
		t.Fatal("CLI inspect lost explicit source-deletion progress/current owner")
	}
	cli(nil, "compose", "down", "--tenant", "tenant", "-p", "app", "--operation", "sql-move-down")
	wait("moved SQL app down and all original input/volume/network refs returned", func() bool {
		apps, err := p.Apps(read().State)
		if err != nil {
			return false
		}
		i, ok := apps.Inventory("tenant", "app")
		if !ok {
			return false
		}
		_, running := i.Execution()
		_, retiring := i.Retirement()
		v, _ := registry().Volume(original.Spec.Scope)
		return !running && !retiring && len(apps.Bindings().Live()) == 0 && len(v.Consumers()) == 0
	})
	cli(nil, "--tenant", "tenant", "volume", "delete", "app/data", "--id", "delete-returned-sql-volume", "--no-wait")
	wait("separate explicit current SQL Volume deletion after app down", func() bool {
		core, ok := registry().Volume(original.Spec.Scope)
		return ok && core.Deleted()
	})
	for _, c := range docker {
		rows, err := c.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("label", "org.mydc.owner="+c.Owner)})
		if err != nil || len(rows.Items) != 0 {
			t.Fatal("owned SQL containers remain", err)
		}
	}
	t.Log("actual independent Engines: original MySQL clean shutdown/fence -> same logical Volume cold move/Completed -> PHP DNS new address/SQL original and target new writes -> source same-DB restart without old writer resurrection -> separate reverse CLI plan/current writer recipe/new physical reservation/materialization -> actual node-b SIGSTOP/SIGKILL at original non-final receive offset -> same DB/key daemon resume -> reverse Completed/DNS original address/original operation results/new SQL writes preserved -> separate original CLI requests delete both obsolete native sources without touching current writer/data -> app down/reference return -> explicit current Volume delete")
	return cut
}
