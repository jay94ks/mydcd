// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/observability"
	"gopkg.in/yaml.v3"
)

func beginMoveThroughCLI(t *testing.T, ctx context.Context, root string, input deployment.Compose, old control.VolumeMoveBegin, source *Runtime, p control.Policy, read func() cluster.View, wait func(string, func() bool)) (control.VolumeMoveBegin, deployment.Blueprint, []byte, func(control.UserOperation)) {
	t.Helper()
	file, planFile := filepath.Join(root, old.ID+"-target.yaml"), filepath.Join(root, old.ID+"-plan.json")
	raw, err := yaml.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	call := func(want int, files []*os.File, args ...string) []byte {
		t.Helper()
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), args, files)
		code := 0
		if err != nil {
			if exited, ok := err.(*exec.ExitError); ok {
				code = exited.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		if code != want {
			t.Fatal("move CLI", args, "exit", code, "want", want, string(diagnostic), string(out))
		}
		return out
	}
	// Unknown is a valid product response before asynchronous observations
	// arrive. This fixture specifically verifies the fresh result; wait for
	// the normal signed producer, without creating or publishing a report.
	wait("normal target disk report before fresh move-plan measurement", func() bool {
		view := read()
		reports, err := source.storedNodeObservations(ctx, view)
		if err != nil {
			t.Fatal("original node observation store", err)
		}
		for _, report := range reports {
			if report.Node == old.Target.Node && report.Key == old.Target.NodeKey && report.Disk != nil && report.Disk.Source == "container-runtime" && report.Index <= view.State.Index() && observability.Fresh(report.At, uint64(time.Now().UnixMilli())) {
				return true
			}
		}
		return false
	})
	before := read().State.Object(control.VolumesKey)
	call(0, nil, "--tenant", "tenant", "volume", "move", "app/data", "--id", old.ID, "-f", file, "--max-size", strconv.FormatUint(old.MaxBytes, 10), "--max-entries", strconv.FormatUint(uint64(old.MaxEntries), 10), "--transfer-timeout", "120s", "--dry-run", "--save-plan", planFile)
	if read().State.Object(control.VolumesKey) != before {
		t.Fatal("read-only plan changed Volume state")
	}
	saved, err := os.ReadFile(planFile)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := control.DecodeAppMovePlan(bytes.TrimSpace(saved))
	if err != nil {
		t.Fatal("CLI move plan", err)
	}
	if plan.Begin.Scope != old.Scope || plan.Begin.Compatibility != old.Compatibility || plan.Begin.Target != old.Target || plan.Begin.OwnerRevision != old.OwnerRevision || plan.Begin.App.Operation != old.App.Operation || plan.Begin.App.Plan != old.App.Plan {
		t.Fatal("source recipe/original app or target changed")
	}
	storage := plan.StoragePreflight
	if storage == nil || storage.Node != old.Target.Node || storage.RequiredBytes != plan.Begin.CapacityBytes || !storage.MeasurementOnly || storage.State != "available" || storage.AvailableBytes == nil || *storage.AvailableBytes < storage.RequiredBytes || storage.ObservedAt == 0 {
		t.Fatal("actual move plan lacks fresh signed target disk measurement", storage)
	}
	legacy := plan
	legacy.StoragePreflight = nil
	legacyRaw, _ := json.Marshal(legacy)
	if _, err := control.DecodeAppMovePlan(legacyRaw); err != nil {
		t.Fatal("original stored plan now requires a later measurement", err)
	}
	for _, mutate := range []func(*control.MoveStoragePreflight){
		func(v *control.MoveStoragePreflight) { v.Node = "unrelated-node" },
		func(v *control.MoveStoragePreflight) { v.RequiredBytes++ },
	} {
		bad := plan
		measurement := *storage
		mutate(&measurement)
		bad.StoragePreflight = &measurement
		raw, _ := json.Marshal(bad)
		if _, err := control.DecodeAppMovePlan(raw); err == nil {
			t.Fatal("measurement borrowed another node or capacity")
		}
	}
	t.Log("actual CLI/app-plan-stream returns fresh signed target disk measurement; legacy plan omission stays valid; other node/capacity rejected; measurement does not alter original Begin/Artifact")
	blueprint, err := deployment.DecodeBlueprint(plan.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	// CD consent belongs to the registered requester, separately from the
	// move signer. Accepting a move never supplies that target Group approval.
	isCD := plan.Begin.App.CD != nil
	firstCode := 2
	if isCD {
		firstCode = 0
	}
	call(firstCode, nil, "--tenant", "tenant", "volume", "move", "--plan", planFile)
	v, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	job, _, ok := v.Move(control.VolumeMoveSelection{Scope: old.Scope, ID: old.ID})
	if !ok || job.Origin.Change.Action != "begin-volume-move" {
		t.Fatal("CLI original not accepted")
	}
	owner, revision := v.Volume(old.Scope)
	if !revision || len(owner.Consumers()) != 1 {
		t.Fatal("missing Group stopped source writer")
	}
	// The approval step below runs the same saved plan again with the group
	// password descriptor; the accepted move itself no longer needs the file.
	kept := planFile + ".kept"
	if err = os.Rename(planFile, kept); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(file, []byte("changed after original acceptance"), 0600); err != nil {
		t.Fatal(err)
	}
	call(0, nil, "--tenant", "tenant", "op", "show", old.ID)
	call(0, nil, "--tenant", "tenant", "volume", "show", "app/data")
	call(2, nil, "compose", "up", "--tenant", "tenant", "--operation", old.ID, "-f", file, "--no-input")
	approve := func(origin control.UserOperation) {
		t.Helper()
		if !bytes.Equal(control.OperationBytes(origin), control.OperationBytes(job.Origin)) {
			t.Fatal("original move replaced before approval")
		}
		// Re-login keeps the stable user but changes the current login proof. The
		// resumed approval must remain bound to the original signed requester.
		call(0, nil, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
		withPassword := func(want int, password string) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if _, err = fmt.Fprintln(writer, password); err != nil {
				writer.Close()
				t.Fatal(err)
			}
			writer.Close()
			if isCD {
				call(want, []*os.File{reader}, "--tenant", "tenant", "cd", "approve", "app", "--secrets", "--operation", plan.Begin.App.Target.Operation, "--group-password-fd", "tenant/group=3")
			} else {
				call(want, []*os.File{reader}, "--tenant", "tenant", "volume", "move", "--plan", kept, "--group-password-fd", "tenant/group=3")
			}
		}
		withPassword(3, "wrong-native-group-password")
		withPassword(0, "private-native-group-password")
		if isCD {
			call(0, nil, "--tenant", "tenant", "cd", "approve", "app", "--secrets", "--operation", plan.Begin.App.Target.Operation)
		}
		call(0, nil, "--tenant", "tenant", "op", "resume", old.ID)
	}
	t.Log("real CLI authenticated target-file plan reads original live writer recipe; separate signed move/upload retained; default replay result-only with removed plan; ordinary up cannot consume move intent; Group approval resumes original after re-login")
	return plan.Begin, blueprint, plan.Artifact, approve
}

func deleteRetainedMoveThroughCLI(t *testing.T, ctx context.Context, root string, q control.VolumeMoveSelection, request string) {
	t.Helper()
	args := []string{"--tenant", q.Scope.Tenant, "volume", "delete", q.Scope.App + "/" + q.Scope.ID, "--retained", q.ID, "--id", request, "--no-wait"}
	for _, command := range [][]string{args, args, {"op", "show", request}} {
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), command, nil)
		if err != nil {
			t.Fatal("original retained deletion CLI", command, err, string(diagnostic), string(out))
		}
	}
}
