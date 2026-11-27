// SPDX-License-Identifier: Apache-2.0

//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/moby/moby/api/types/events"
	"github.com/moby/moby/client"
)

// cancel-runtime consumes only the existing installed BuildKit, registered
// ext4 root, managed registry seed and synchronous CLI runner. The seed backend
// must include --build-cancel-fixture. Its public RUN marker, not the Dockerfile
// command text or a sent Solve alone, establishes that actual build execution
// began. The ten-minute fixture sleep is interrupted by the original cancel;
// the product's accepted job deadline and all normal cleanup budgets stay fixed.
func (f *managedRegistryNative) verifyImageBuildCancelNative(t *testing.T, ctx context.Context, r *Runtime, root string, base imagebuild.ContextSpec, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	const jobID = "rq6-cancel-runtime"
	const submitID = "rq6-cancel-submit"
	const cancelID = "rq6-cancel-original"
	const marker = "owned-build-cancel-ready"
	if r.imageBuildNative == nil || r.nodeRoots == nil {
		t.Fatal("existing native build/root owners required")
	}
	book := func() control.ImageBuildCatalog {
		t.Helper()
		b, err := p.ImageBuilds(read().State)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	spec := base.Own()
	spec.ID, spec.Secrets, spec.Tags = "native-cancel-runtime", nil, []string{"native-cancel-runtime"}
	change("rq6-cancel-context", "put-build-context", 0, control.ImageBuildContextPut{Spec: spec})
	// This uses the already pushed managed seed only as the tiny RUN base. It
	// does not repeat external/private-FROM, Git, draft, Tail or large ZIP roots.
	dockerfile := fmt.Sprintf("FROM %s\nUSER 0:0\nRUN [\"/backend\",\"--build-cancel-fixture\"]\n", f.reference)
	version := f.uploadBuildNative(t, root, spec.ID, "rq6-cancel-upload", dockerfile, "owned-cancel-context")
	f.cli(nil, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", submitID, "--no-input")
	var original control.ImageBuildJobRecord
	var running imagebuild.NativeRecord
	var nextLogRead time.Time
	registryNativeWait(t, ctx, "original SDK Solve and actual RUN ready output", func() bool {
		if time.Now().Before(nextLogRead) {
			return false
		}
		nextLogRead = time.Now().Add(time.Second)
		row, found := book().Job("tenant", jobID)
		if !found {
			t.Fatal("accepted original cancel build missing")
		}
		if row.Run.Terminal() {
			t.Fatal("build closed before actual RUN/cancel", row.Run.Phase, row.Run.Closure.Result.Code)
		}
		if row.Run.Phase != "running" {
			return false
		}
		native, err := r.imageBuildNative.Record(row.Run.Spec)
		if err != nil || native.Solve == nil || !native.Solve.Sent {
			return false
		}
		if native.Solve.Returned || native.Cancel || native.NativeID == "" || !native.StartSent {
			t.Fatal("original solve stopped before cancel readiness", err)
		}
		var logs control.ImageBuildLogPage
		q := imagebuild.LogQuery{Job: jobID, MaxBytes: imagebuild.MaxLogPageBytes, Tail: true}
		if err := json.Unmarshal(f.cli(nil, "registry", "build-logs", jobID, "--tenant", "tenant", "--tail"), &logs); err != nil || !logs.ValidQuery(p.Cluster, "tenant", q, "") || logs.Page.Job != row.Run.Spec.Digest() {
			t.Fatal("original actual CLI RUN progress", err)
		}
		if !logs.Page.Available || !bytes.Contains(logs.Page.Data, []byte(marker)) {
			return false
		}
		got, err := r.docker.API.ContainerInspect(ctx, native.NativeID, client.ContainerInspectOptions{})
		if err != nil || got.Container.ID != native.NativeID || got.Container.Image != native.ImageID || got.Container.State == nil || !got.Container.State.Running {
			t.Fatal("ready Solve does not own the original running native daemon", err)
		}
		original, running = row, native
		return true
	})
	if original.Origin.RequestID != submitID || original.Origin.VerifyOriginal(p.Cluster) != nil || original.Begin == nil || original.Run.Spec.Context.ID != spec.ID || original.Run.Spec.Version != version || original.Run.Spec.Scope.Root != spec.Root || original.Run.Cancel || running.Root == nil || running.Root.Lease.Token == 0 || running.Root.Returned || running.Workspace == nil || !running.Workspace.Ready || running.Workspace.Closed {
		t.Fatal("actual RUN lost original submit/version/context/root ownership")
	}
	// Committed reports keep the signed input/source arrays once, in the
	// job row. Restore that original signing view exactly as the FSM's
	// validateImageBuildJob does; the normalized Begin is not standalone.
	begin := *original.Begin
	begin.Inputs, begin.Sources = original.Run.Inputs, original.Sources
	if begin.Action != "begin" || begin.Expected != 1 || !begin.Valid(original.Run.Spec) {
		t.Fatal("original normalized begin lost its signed inputs/sources")
	}
	consumer, err := r.imageBuildNative.RootConsumer(original.Run.Spec, imagebuild.JobRoot)
	if err != nil {
		t.Fatal(err)
	}
	pin, held, err := r.nodeRoots.RecordedPin(spec.Root, consumer)
	if err != nil || !held || pin.Lease != running.Root.Lease {
		t.Fatal("running original job root dependency missing", err)
	}
	t.Log("RQ6-S11-A: actual RUN ready and original native running", jobID, running.NativeID)
	// Subscribe before sending cancel. The original journal has Wait/Remove
	// receipts; the actual Engine stop/die/destroy events supply the separate
	// stop observation for this exact native ID, without issuing native cleanup
	// from the test or replacing the product worker's own SDK calls.
	api, err := r.docker.StreamingAPI()
	if err != nil {
		t.Fatal(err)
	}
	eventCtx, stopEvents := context.WithCancel(ctx)
	stream := api.Events(eventCtx, client.EventsListOptions{Since: strconv.FormatInt(time.Now().Unix(), 10), Filters: client.Filters{}.Add("type", "container").Add("container", running.NativeID)})
	defer func() {
		stopEvents()
		for range stream.Err {
		}
	}()
	var accepted struct {
		Job, Request string
		Accepted     bool
		Result       *state.Result
	}
	if err := json.Unmarshal(f.cli(nil, "registry", "cancel-build", jobID, "--tenant", "tenant", "--expected-revision", strconv.FormatUint(original.Run.Revision, 10), "--request-id", cancelID), &accepted); err != nil || !accepted.Accepted || accepted.Job != jobID || accepted.Request != cancelID || accepted.Result == nil || accepted.Result.Code != state.Applied {
		t.Fatal("original actual CLI cancel was not accepted", err)
	}
	closed := f.waitImageBuildNative(t, ctx, r, p, read, jobID, "CANCELLED")
	native, err := r.imageBuildNative.Record(closed.Run.Spec)
	if err != nil || closed.Run.Phase != "cancelled" || !closed.Run.Cancel || closed.CancelledBy == nil || closed.CancelledBy.RequestID != cancelID || closed.CancelledBy.VerifyOriginal(p.Cluster) != nil || closed.CancelledBy.Change.Expected != original.Run.Revision || !reflect.DeepEqual(closed.Origin, original.Origin) || closed.Run.Spec.Digest() != original.Run.Spec.Digest() || !closed.Run.Closure.Valid(original.Run.Spec) || closed.Run.Closure.Result.Image != "" || closed.Run.Closure.Result.Bytes != 0 {
		t.Fatal("original cancel did not close the same accepted job", err)
	}
	if native.NativeID != running.NativeID || !native.Cancel || native.Solve == nil || !native.Solve.Sent || !native.Solve.Returned || native.Solve.Code == "OK" || !native.Exited || !native.Waited || !native.RemoveSent || !native.Removed || native.Publication != nil || native.Workspace == nil || !native.Workspace.Closed || native.Root == nil || !native.Root.Returned || native.Root.Lease != running.Root.Lease || native.Completion == nil || !reflect.DeepEqual(*native.Completion, *closed.Run.Closure) || native.Outcome == nil || *native.Outcome != closed.Run.Closure.Result {
		t.Fatal("actual original Solve/Stop/Wait/Remove/workspace/root did not close")
	}
	observed := map[events.Action]bool{}
	for !observed[events.ActionStop] || !observed[events.ActionDie] || !observed[events.ActionDestroy] {
		select {
		case event := <-stream.Messages:
			if event.Type != events.ContainerEventType || event.Actor.ID != running.NativeID {
				t.Fatal("native cancel event belongs to another container")
			}
			observed[event.Action] = true
		case err := <-stream.Err:
			t.Fatal("original native cancel event stream ended before stop/die/destroy", err)
		case <-ctx.Done():
			t.Fatal("original native stop/die/destroy missing", ctx.Err())
		}
	}
	t.Log("RQ6-S11-B: original CLI cancel, native stop/die/destroy and durable closure", jobID)
	if _, err = r.docker.API.ContainerInspect(ctx, running.NativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("cancelled original daemon survived its accepted closure", err)
	}
	jobDigest := original.Run.Spec.Digest()
	if _, err = os.Lstat(filepath.Join(spec.Root.Path, ".sfc-imagebuild", "jobs", hex.EncodeToString(jobDigest[:]))); !os.IsNotExist(err) {
		t.Fatal("cancelled original workspace was not removed", err)
	}
	if _, held, err = r.nodeRoots.RecordedPin(spec.Root, consumer); err != nil || held {
		t.Fatal("cancelled original job root lease was not returned", err)
	}
	projection, err := p.ProjectResources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	if _, held := projection.Resources.Quotas.Reservation("workload/imagebuild/tenant/" + jobID + "/builder"); held {
		t.Fatal("cancelled original closure retained execution budget")
	}
	// Same immutable operations recover their own receipts. Neither replay
	// starts a new job nor turns a missing response into a fresh cancellation.
	var replay struct {
		Job, Request string
		Accepted     bool
		Result       *state.Result
	}
	if err := json.Unmarshal(f.cli(nil, "registry", "cancel-build", jobID, "--tenant", "tenant", "--expected-revision", strconv.FormatUint(original.Run.Revision, 10), "--request-id", cancelID, "--resume-original"), &replay); err != nil || !replay.Accepted || replay.Job != jobID || replay.Request != cancelID || !reflect.DeepEqual(replay.Result, accepted.Result) {
		t.Fatal("same cancel operation changed its original receipt", err)
	}
	f.cli(nil, "registry", "build", spec.ID, hex.EncodeToString(version[:]), "--tenant", "tenant", "--job", jobID, "--request-id", submitID, "--resume-original", "--no-input")
	var page control.ImageBuildPage
	if err := json.Unmarshal(f.cli(nil, "registry", "build-job", jobID, "--tenant", "tenant"), &page); err != nil || len(page.Jobs) != 1 || page.Jobs[0].ID != jobID || page.Jobs[0].Version != version || page.Jobs[0].Context != spec.ID || page.Jobs[0].Phase != "cancelled" || !page.Jobs[0].Cancel || page.Jobs[0].Result == nil || *page.Jobs[0].Result != closed.Run.Closure.Result {
		t.Fatal("actual same-ID job query lost the original cancel result", err)
	}
	unchanged, found := book().Job("tenant", jobID)
	after, err := r.imageBuildNative.Record(original.Run.Spec)
	if !found || !reflect.DeepEqual(unchanged, closed) || err != nil || !reflect.DeepEqual(after, native) {
		t.Fatal("same-ID CLI recovery changed the original job or native effects", err)
	}
	// No publish was sent, so there is no output image to DELETE. Retire the
	// exact original shared references through existing signed management CAS.
	f.cli(nil, "registry", "delete-build-job", jobID, "--tenant", "tenant", "--request-id", "rq6-cancel-delete-job")
	stored, found := book().Version("tenant", version)
	if !found {
		t.Fatal("original cancel version missing")
	}
	change("rq6-cancel-delete-version", "delete-build-version", stored.Number, control.ImageBuildVersionSelection{Tenant: "tenant", ID: version})
	context, found := book().Context("tenant", spec.ID)
	if !found {
		t.Fatal("original cancel context missing")
	}
	change("rq6-cancel-delete-context", "delete-build-context", context.Revision, control.ImageBuildSelection{Tenant: "tenant", ID: spec.ID})
	policy, found := book().Policy("tenant")
	if !found {
		t.Fatal("original cancel policy missing")
	}
	change("rq6-cancel-delete-policy", "delete-image-build-policy", policy.Revision, control.ImageBuildSelection{Tenant: "tenant"})
	final := book()
	deletedJob, hasJob := final.Job("tenant", jobID)
	deletedVersion, hasVersion := final.Version("tenant", version)
	deletedContext, hasContext := final.Context("tenant", spec.ID)
	deletedPolicy, hasPolicy := final.Policy("tenant")
	if !hasJob || !deletedJob.Deleted || !hasVersion || !deletedVersion.Deleted || !hasContext || !deletedContext.Deleted || !hasPolicy || !deletedPolicy.Deleted {
		t.Fatal("cancel cleanup retained original shared job/version/context/policy references")
	}
	refs, err := p.ImageReferences(read().State, "tenant", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range refs {
		if ref.Operation == jobID || ref.Task == "image-build/tenant/"+jobID {
			t.Fatal("cancel cleanup retained original base/builder/output image usage", ref.Kind)
		}
	}
	t.Log("RQ6-S11-C: original replay, root/budget/shared references returned", jobID)
	f.public["ImageBuildScope"] = "cancel-runtime"
	f.public["ImageBuildCancelRuntime"] = map[string]any{"Job": jobID, "Submit": submitID, "Cancel": cancelID, "NativeID": running.NativeID, "RUNReady": true, "SolveSent": true, "EngineStopDieDestroy": true, "WaitedRemoved": true, "WorkspaceAndJobRootReturned": true, "OriginalClosure": closed.Run.Closure, "SameIDRecovered": true, "SharedReferencesDeleted": true}
	f.save()
}
