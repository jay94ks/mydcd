// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
)

func moveFixtureRequest(t *testing.T, ctx context.Context, runtime *Runtime, method string, body []byte) []byte {
	t.Helper()
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	status, err := runtime.workload.Status(ctx, key)
	if err != nil || !status.Running || status.NativeID == "" {
		t.Fatal("original move fixture Task unavailable", err)
	}
	actual, err := runtime.docker.API.ContainerInspect(ctx, status.NativeID, client.ContainerInspectOptions{})
	if err != nil || actual.Container.NetworkSettings == nil {
		t.Fatal("original move fixture native inspection", err)
	}
	address := ""
	for _, endpoint := range actual.Container.NetworkSettings.Networks {
		if endpoint != nil && endpoint.IPAddress.IsValid() {
			if address != "" {
				t.Fatal("move fixture requires one explicit native endpoint")
			}
			address = endpoint.IPAddress.String()
		}
	}
	if address == "" {
		t.Fatal("move fixture native endpoint absent")
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(address, "8080")+"/move-state", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport, Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal("original application write/result is unknown; do not resubmit", err)
	}
	result, readErr := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK || len(result) > 32<<10 {
		t.Fatal("original application result", response.StatusCode, readErr, closeErr)
	}
	return result
}

func verifyReverseMoveTarget(t *testing.T, ctx context.Context, originalSource, firstTarget *Runtime, root string, sourceDocument []byte, original, current volumes.NativeReady, first control.VolumeMove, p control.Policy, read func() cluster.View, reject func(string, string, uint64, any, state.Code), wait func(string, func() bool), controls managedMoveNativeControls) *Runtime {
	t.Helper()
	// The new source is the actual running target of the first move. Its own
	// application writes and syncs this result; the test never edits host data.
	newData := []byte(strings.Repeat("new-target-data-", 1024))
	if !bytes.Equal(moveFixtureRequest(t, ctx, firstTarget, http.MethodPut, newData), newData) || !bytes.Equal(moveFixtureRequest(t, ctx, firstTarget, http.MethodGet, nil), newData) {
		t.Fatal("actual target application did not retain its new write")
	}
	oldDisk, err := originalSource.docker.API.VolumeInspect(ctx, original.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(filepath.Join(oldDisk.Volume.Mountpoint, "move-target-write")); !os.IsNotExist(err) {
		t.Fatal("obsolete retained source cannot contain the new target write", err)
	}
	registry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, firstMove, ok := registry.Move(first.Selection())
	if !ok || firstMove.Phase != volumes.Completed {
		t.Fatal("first move must settle before a new reverse request")
	}
	firstBytes, err := json.Marshal(firstMove)
	if err != nil {
		t.Fatal(err)
	}
	apps, err := p.Apps(read().State)
	if err != nil {
		t.Fatal(err)
	}
	inventory, ok := apps.Inventory("tenant", "app")
	active, running := inventory.Active()
	if !ok || !running || active.ID != first.App.Target.Operation || active.Status != "Succeeded" {
		t.Fatal("new source is not the original moved app")
	}
	row, err := firstTarget.workload.View(deployment.ResourceKey("task", "tenant", "app", "web"))
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource {
		t.Fatal("new source recipe is not settled", err)
	}
	compatibility := sha256.Sum256(append([]byte("sfc-volume-cold-recipe-1\x00"), []byte(row.State.Applied.Spec)...))
	core, ok := registry.Volume(first.Binding.Scope)
	owner, revision := core.Owner()
	if !ok || owner != current.Owner || len(core.Consumers()) != 1 {
		t.Fatal("new source is not the current exclusive writer")
	}
	target := original.Spec
	target.Materialization = "m-app-return"
	q := control.VolumeMoveBegin{Scope: first.Binding.Scope, ID: "app-return", OwnerRevision: revision, Target: target, Compatibility: compatibility, MaxBytes: first.Binding.MaxBytes, MaxEntries: first.MaxEntries, CapacityBytes: first.CapacityBytes, ExpiresAt: time.Now().Unix() + 120, App: &control.VolumeMoveApp{Operation: active.ID, Revision: inventory.Revision(), Plan: active.Plan}}
	input, err := deployment.ParseApp(sourceDocument)
	if err != nil {
		t.Fatal(err)
	}
	q, artifact, _, approve := beginMoveThroughCLI(t, ctx, root, input, q, firstTarget, p, read, wait)
	if err = artifact.CheckAppInput(); err != nil {
		t.Fatal("reverse target lost its app.yaml input kind", err)
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	job, _, ok := registry.Move(control.VolumeMoveSelection{Scope: q.Scope, ID: q.ID})
	if !ok || job.Source.Spec != current.Spec || job.Binding.Source != current.Owner || job.Binding.Target.Native == original.Owner.Native || job.Target.Materialization != target.Materialization {
		t.Fatal("reverse request reused an obsolete physical source/target")
	}
	if controls.reopenSource == nil {
		t.Fatal("reverse target must reopen the original node DB/key")
	}
	recoverReceiver := armMoveTargetSyncFailure(t, ctx, originalSource, job, p, read, wait, func() *Runtime { return controls.reopenSource(nil) })
	resumeReverse := func() *Runtime {
		originalSource = recoverReceiver()
		return originalSource
	}
	returned := verifyMoveTargetActive(t, ctx, firstTarget, originalSource, current, job, p, read, approve, wait, managedAppVolumeMoveAuto, resumeReverse, nil, nil)
	reverseReceive := moveReceiveIntent{Schema: 1, Job: job}
	completedRegistry, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	_, completedMove, foundMove := completedRegistry.Move(job.Selection())
	if !foundMove || completedMove.Manifest == nil {
		t.Fatal("reverse recovery lost original manifest")
	}
	reverseReceive.Manifest = *completedMove.Manifest
	receiveRow, err := originalSource.backupArtifacts.journal.Read(moveReceiveKey(reverseReceive))
	if err != nil || receiveRow.State.Pending != nil || receiveRow.State.LastID != 2 || receiveRow.State.Applied.Present || receiveRow.State.Desired.Present || len(receiveRow.Consumers) != 0 {
		t.Fatal("reverse recovery replaced original receive Apply/Remove", err)
	}
	if returned.Spec.Scope != original.Spec.Scope || returned.Owner.Key != original.Owner.Key || returned.Owner.Native == original.Owner.Native || returned.Owner.Native == current.Owner.Native || returned.Spec.Materialization != target.Materialization {
		t.Fatal("reverse did not produce a fresh physical target for the same logical Volume")
	}
	if !bytes.Equal(moveFixtureRequest(t, ctx, originalSource, http.MethodGet, nil), newData) {
		t.Fatal("reverse app lost the new target write")
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, ok = registry.Volume(first.Binding.Scope)
	_, retainedFirst, exists := registry.Move(first.Selection())
	retainedBytes, err := json.Marshal(retainedFirst)
	if !ok || !exists || err != nil || !bytes.Equal(firstBytes, retainedBytes) || len(core.Moves()) != 2 || len(core.Retained()) != 2 || len(core.Consumers()) != 1 {
		t.Fatal("reverse erased original move facts, retained sources or current writer", err)
	}
	// The returned original node now holds BOTH its obsolete source and a new
	// current materialization. Neither a successful move nor a new Goal releases
	// that old physical reservation without an explicit native deletion fact.
	limits := 0
	before := read().State.Object(control.VolumesKey)
	for _, limit := range registry.BackupLimits() {
		if limit.Node != original.Owner.Node {
			continue
		}
		expected := limit.Revision
		limit.Revision, limit.Owner = 0, [32]byte{}
		limit.Original = &control.OriginalVolumeLimit{Bytes: first.SourceCapacity, Count: 1}
		reject("reverse-retained-capacity-"+limit.Tenant, "set-volume-backup-limit", expected, limit, state.ConditionFailed)
		limits++
	}
	if limits != 2 || read().State.Object(control.VolumesKey) != before {
		t.Fatal("reverse physical reservation shrink changed/lost original global or tenant policy")
	}
	for _, retained := range []struct {
		runtime *Runtime
		ready   volumes.NativeReady
	}{{originalSource, original}, {firstTarget, current}} {
		cold, err := retained.runtime.activations.ColdSource(ctx, retained.ready)
		if err != nil || core.CheckActivation(cold.Writer.Consumer) == nil {
			t.Fatal("reverse released an obsolete source fence", err)
		}
		attachments, err := retained.runtime.docker.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", retained.ready.Owner.Native)})
		if err != nil || len(attachments.Items) != 0 {
			t.Fatal("obsolete physical source still has a native attachment", err)
		}
	}
	for i, selected := range []control.VolumeMoveSelection{first.Selection(), job.Selection()} {
		if i == 0 {
			originalSource = deleteRetainedMoveWithRecovery(t, ctx, originalSource, root, selected, original, returned, newData, p, read, wait, controls)
		} else {
			deleteRetainedMoveThroughCLI(t, ctx, root, selected, "delete-return-source-"+string(rune('a'+i)))
		}
		lastDeleteError := ""
		wait("explicit original obsolete source deletion and native Gone", func() bool {
			v, err := p.Volumes(read().State)
			if err != nil {
				t.Fatal(err)
			}
			_, move, ok := v.Move(selected)
			if i == 1 && ok && move.SourceDeletion != nil && move.SourceDeletion.Gone == nil {
				firstTarget.mu.RLock()
				cause := firstTarget.volumeBackupError
				firstTarget.mu.RUnlock()
				if cause != nil && cause.Error() != lastDeleteError {
					lastDeleteError = cause.Error()
					row, readErr := firstTarget.nativeVolumes.View(volumes.NativeKey(current.Spec))
					t.Log("original reverse source deletion waiting", selected.ID, cause, "native", compact(row), "read", readErr)
				}
			}
			return ok && move.SourceDeletion != nil && move.SourceDeletion.Gone != nil
		})
	}
	for _, obsolete := range []struct {
		runtime *Runtime
		ready   volumes.NativeReady
	}{{originalSource, original}, {firstTarget, current}} {
		if _, err := obsolete.runtime.docker.API.VolumeInspect(ctx, obsolete.ready.Owner.Native, client.VolumeInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("explicit deletion did not remove the exact obsolete native", err)
		}
	}
	registry, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	core, _ = registry.Volume(first.Binding.Scope)
	currentNative, ok := registry.Native(first.Binding.Scope.Tenant, first.Binding.Scope.App, first.Binding.Scope.ID)
	if !ok || currentNative.Owner != returned.Owner || len(core.Retained()) != 0 || len(core.Consumers()) != 1 || !bytes.Equal(moveFixtureRequest(t, ctx, originalSource, http.MethodGet, nil), newData) {
		t.Fatal("obsolete source deletion touched the active returned Volume/data/writer")
	}
	t.Log("actual target application durable new write -> separate authenticated reverse CLI intent/new source recipe -> fresh materialization on original node -> actual reverse receive data sync failure/Apply1 Unknown -> same original node DB/key reopen/original receive recovery -> normal reverse move/Active/Completed/Remove2 -> new app reads preserved target write; both obsolete sources/fences and physical holds retained until explicit original CLI deletion/native Gone, current writer/data preserved and no old-source reactivation")
	return originalSource
}
