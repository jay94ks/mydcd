// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/workload"
)

// A surge publishes the next inputs generation while the original container
// still holds the original one: the original is parked, keeps its pin and
// files, and drains on its own once returned.
func TestProjectionStoreParksTheLentOriginalGeneration(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	m, err := OpenProjections(filepath.Join(t.TempDir(), "inputs"), f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	consumer, key := projectionConsumer(t, f, b)
	lease, err := m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}

	n := b.d.Needs
	n.Generation++
	next := f.reserve(n).Bindings[0]
	nextStage, err := next.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer nextStage.Destroy()
	nextRef, err := m.Publish(ctx, next, nextStage, 2, 2)
	if err != nil {
		t.Fatal("next generation blocked by the lent original", err)
	}
	if _, err = m.journal.Read(workload.ParkedKey(ref.Key, ref.Generation)); err != nil {
		t.Fatal("original not parked", err)
	}
	if ready, err := m.Ready(ctx, nextRef); err != nil || !ready {
		t.Fatal("next generation not ready", err)
	}
	if ready, err := m.Ready(ctx, ref); err != nil || !ready {
		t.Fatal("parked original lost", err)
	}
	nextConsumer, _ := projectionConsumer(t, f, next)
	if _, err = m.AcquireInputs(ctx, nextRef, nextConsumer, key, nextRef.Generation); err != nil {
		t.Fatal("next generation not lent", err)
	}
	if held, err := m.InspectInputs(ctx, ref, consumer, key, ref.Generation); err != nil || held.Pin != lease.Pin || held.Files[0].Source != lease.Files[0].Source {
		t.Fatal("parked original pin moved", err)
	}
	if err = m.Drain(ctx, ref, 3); err == nil {
		t.Fatal("lent original drained")
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}
	if err = m.Drain(ctx, ref, 3); err != nil {
		t.Fatal("parked original drain", err)
	}
	if gone, err := m.Gone(ref); err != nil || !gone {
		t.Fatal("parked original not gone", err)
	}
	if ready, err := m.Ready(ctx, nextRef); err != nil || !ready {
		t.Fatal("draining the original touched its successor", err)
	}
}
