// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Only native application is mocked. Reader consumers and restart use the
// actual journal/private DB, not a copy of its lease algorithm.
type checkerCleanupDriver struct{}

func (checkerCleanupDriver) Execute(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectApplied, nil
}
func (checkerCleanupDriver) Recover(context.Context, string, reconcile.Operation) (reconcile.Outcome, error) {
	return reconcile.EffectUnknown, nil
}

func TestReturnReadCallPreservesOtherCallTargetRunAndWorkloadPins(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "workload.db")
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if j != nil {
			_ = j.Close()
		}
	}()
	request := serviceProbeRequest()
	second := request.Targets[0]
	second.Service = "z-local"
	second.TaskKey = "workload/second"
	request.Targets = append(request.Targets, second)
	for _, target := range request.Targets {
		if err = j.Desired(target.TaskKey, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: "mock native"}}, 8); err != nil {
			t.Fatal(err)
		}
		if err = j.Step(ctx, target.TaskKey, checkerCleanupDriver{}); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{journal: j, driver: &DockerDriver{Engine: &engine.Client{Owner: request.Cluster + "/" + request.Targets[0].Owner}}}
	call := sha256.Sum256([]byte("original call"))
	otherCall := sha256.Sum256([]byte("other live call"))
	otherRun := sha256.Sum256([]byte("other live run"))
	firstConsumer := "checker-read/" + request.RunID + "/" + hex.EncodeToString(call[:])
	otherConsumer := "checker-read/" + request.RunID + "/" + hex.EncodeToString(otherCall[:])
	otherRunConsumer := "checker-read/" + hex.EncodeToString(otherRun[:]) + "/" + hex.EncodeToString(call[:])
	for _, consumer := range []string{firstConsumer, otherConsumer, otherRunConsumer, "workload/dependent", "volume/consumer"} {
		if _, err = j.Borrow(request.Targets[0].TaskKey, consumer, 1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = j.Borrow(second.TaskKey, firstConsumer, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.ReturnReadCall(ctx, request, request.Targets[0].Service, call); err != nil {
		t.Fatal(err)
	}
	if err = j.Close(); err != nil {
		t.Fatal(err)
	}
	j = nil
	j, err = reconcile.OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	m.journal = j
	row, err := j.Read(request.Targets[0].TaskKey)
	if err != nil || len(row.Consumers) != 4 || row.Consumers[firstConsumer].Generation != 0 {
		t.Fatal("original call cleanup not durable/isolated", err, row.Consumers)
	}
	for _, consumer := range []string{otherConsumer, otherRunConsumer, "workload/dependent", "volume/consumer"} {
		if row.Consumers[consumer].Generation != 1 {
			t.Fatal("unrelated owner released", consumer)
		}
	}
	sibling, err := j.Read(second.TaskKey)
	if err != nil || sibling.Consumers[firstConsumer].Generation != 1 {
		t.Fatal("same call on another target released", err)
	}
	if err = m.ReturnReadCall(ctx, request, request.Targets[0].Service, call); err != nil {
		t.Fatal("cleanup replay changed outcome", err)
	}
	if err = m.ReturnReadCall(ctx, request, "absent-service", call); err == nil {
		t.Fatal("foreign service cleanup admitted")
	}
	if err = m.ReturnReadCall(ctx, request, request.Targets[0].Service, [32]byte{}); err == nil {
		t.Fatal("zero call became whole-run cleanup")
	}
	if err = m.ReturnReadRun(ctx, request); err != nil {
		t.Fatal(err)
	}
	row, err = j.Read(request.Targets[0].TaskKey)
	if err != nil || len(row.Consumers) != 3 || row.Consumers[otherConsumer].Generation != 0 {
		t.Fatal("whole-run cleanup lost unrelated pins", err, row.Consumers)
	}
	sibling, err = j.Read(second.TaskKey)
	if err != nil || len(sibling.Consumers) != 0 {
		t.Fatal("whole-run cleanup retained own sibling pin", err)
	}
}
