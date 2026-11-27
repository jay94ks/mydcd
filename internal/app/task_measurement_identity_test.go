// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/containerops"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
)

// Reuses the actual N3 authenticated Raft/membership/installation fixture with
// native modules disabled. The exact native status/TaskFact below are modeled
// inspection input; this does not claim Docker/container inspection success.
func TestRetainedTaskMeasurementUsesCurrentLogicalPublisherAcrossTwoRotations(t *testing.T) {
	testRealManagedJoin(t, false, "task-measurement-identity")
}

func verifyRetainedTaskMeasurementIdentity(t *testing.T, ctx context.Context, target **Runtime, policy control.Policy, submit func(string, string, uint64, any), wait func(string, func() bool)) {
	t.Helper()
	original := (*target).Identity.Public
	cfg := (*target).installation.config
	node := cfg.Node.ID
	present := true
	fact := containerops.TaskFact{Name: "modeled-original-task", Image: "docker.io/library/alpine@sha256:" + fmt.Sprintf("%064x", 1), State: "running", RestartCount: 2, LastCheck: &containerops.TaskCheck{Checker: "modeled-original-check", Status: "pass", At: uint64(time.Now().Unix())}, EndpointPresent: &present}
	status := workload.ContainerStatus{NativeID: "modeled-original-native", StartedAt: "2026-11-24T00:00:00Z", Running: true, Ready: true, TaskFact: &fact}
	key := deployment.ResourceKey("task", "tenant", "app", "modeled-original")
	stage := deployment.StageRecord{Command: &state.Command{Key: key}, Result: &state.Result{Code: state.Applied, Generation: 7, Revision: 11}}
	app := control.AppView{Tenant: "tenant", App: "app", Deployment: "original-deploy"}
	wanted := observability.Task{Tenant: app.Tenant, App: app.App, Deployment: app.Deployment, Key: key, Native: status.NativeID, Generation: 7, Revision: 11, Fact: fact.Clone(), StartedAt: status.StartedAt}
	statusBefore, _ := json.Marshal(status)
	stageBefore, _ := json.Marshal(stage)
	observationKey := "node-observation/" + node + "/task/" + key
	var oldRootKey [32]byte
	var oldRootBytes []byte
	for rotation := 1; rotation <= 2; rotation++ {
		before := *target
		view, err := before.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		members, err := policy.Members(view.State)
		entry, found := members.Entry(node)
		if err != nil || !found {
			t.Fatal("original installed member missing", err)
		}
		operation := fmt.Sprintf("measurement-identity-%d", rotation)
		submit(operation, "rotate-node-identity", entry.Revision, control.NodeIdentityChange{ID: node, Operation: operation})
		wait("original measurement owner requests identity restart", func() bool {
			select {
			case <-before.IdentityRestart():
				return true
			default:
				return false
			}
		})
		if err = before.Close(); err != nil {
			t.Fatal(err)
		}
		current, err := Open(cfg)
		if err != nil {
			t.Fatal("reopen current publisher and retained original namespace", err)
		}
		*target = current // enclosing fixture cleanup owns the replacement
		if _, err = current.ResumeInstallation(ctx); err != nil {
			t.Fatal(err)
		}
		wait("current publisher identity installation commits", func() bool {
			v, err := current.Engine().Read(ctx, false)
			if err != nil {
				return false
			}
			d, err := policy.Members(v.State)
			row, found := d.IdentityRotation(node, operation)
			return err == nil && found && row.Phase == "Installed" && d.MemberKey(current.Identity.Public) && !d.MemberKey(original) && current.commandIdentity().Public == current.Identity.Public
		})
		owner, found := current.nativeOwner(original)
		if !found || owner == current || owner.parentRuntime != current || owner.Identity.Public != original {
			t.Fatal("original native namespace lost after current key switch")
		}
		view, err = current.Engine().Read(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		if err = owner.publishTaskMeasurement(view, app, stage, status); err != nil {
			t.Fatal("retained original Task measurement was not published", err)
		}
		raw, err := current.reports.Get(observationKey)
		report, decodeErr := observability.Decode(raw)
		if err != nil || decodeErr != nil || report.Key != current.Identity.Public || report.Node != node || report.Index != view.State.Index() || report.Task == nil || !reflect.DeepEqual(*report.Task, wanted) {
			t.Fatal("current envelope changed frozen Task/native facts", err, decodeErr)
		}
		if _, err = owner.reports.Get(observationKey); !errors.Is(err, storage.ErrMissing) {
			t.Fatal("publisher adopted/wrote original owner DB", err)
		}
		if rotation == 2 {
			middle, found := current.nativeOwner(oldRootKey)
			if !found {
				t.Fatal("previous publisher namespace lost")
			}
			history, err := middle.reports.Get(observationKey)
			if err != nil || !bytes.Equal(history, oldRootBytes) {
				t.Fatal("new publisher rewrote historical signed measurement", err)
			}
		}
		// An externally supplied old-key report remains denied even if its
		// immutable TaskFact is identical and its signature is cryptographically
		// valid. The publisher must not weaken current membership admission.
		obsolete := report
		obsolete.Key = original
		obsolete.Signature = ed25519.Sign(owner.Identity.Private, observability.SigningBytes(obsolete))
		oldRaw, err := json.Marshal(obsolete)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = observability.Decode(oldRaw); err != nil {
			t.Fatal("old report must be structurally/signature valid before denial", err)
		}
		if err = current.storeNodeObservation(sfcp.Identity(original), oldRaw); !errors.Is(err, sfcp.ErrAdmission) {
			t.Fatal("old externally signed report authenticated as current", err)
		}
		after, err := current.reports.Get(observationKey)
		if err != nil || !bytes.Equal(raw, after) {
			t.Fatal("old external report changed current stored observation", err)
		}
		rows, err := current.nodeObservations(ctx, cluster.View{State: view.State})
		count := 0
		for _, row := range rows {
			if row.Task != nil && row.Task.Key == key {
				count++
				if row.Key != current.Identity.Public || !reflect.DeepEqual(*row.Task, wanted) {
					t.Fatal("query adopted a historical Task envelope")
				}
			}
		}
		if err != nil || count != 1 {
			t.Fatal("missing/duplicated current Task measurement", count, err)
		}
		statusAfter, _ := json.Marshal(status)
		stageAfter, _ := json.Marshal(stage)
		if !bytes.Equal(statusBefore, statusAfter) || !bytes.Equal(stageBefore, stageAfter) {
			t.Fatal("publication changed original status/Task generation or native identity")
		}
		oldRootKey, oldRootBytes = current.Identity.Public, bytes.Clone(raw)
	}
}
