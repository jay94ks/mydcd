// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/reconcile"
)

func TestProjectionCombinedBindingRequiresSeparateVolumeClosure(t *testing.T) {
	f := makeFixture(t)
	needs := f.db()
	for i := range needs.Files {
		needs.Files[i].UID, needs.Files[i].GID = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	f.approveAll(needs)
	b := f.reserve(needs).Bindings[0]
	stage, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(needs), 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Destroy()
	ctx := context.Background()
	allowed := true
	gate := func(context.Context, Binding) error {
		if !allowed {
			return ErrInputs
		}
		return b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100)
	}
	path := filepath.Join(t.TempDir(), "inputs")
	m, err := OpenProjections(path, f.cluster, needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal("combined Secret/Volume binding publication", err)
	}
	consumer, key := projectionConsumer(t, f, b)
	first, err := m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Close()
	m, err = OpenProjections(path, f.cluster, needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	allowed = false
	if _, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("combined activation bypassed current binding gate")
	}
	got, err := m.InspectInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil || got.Pin != first.Pin {
		t.Fatal("current revoke discarded original combined pin", err)
	}
	if err = m.Drain(ctx, ref, 2); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("live native mount released files", err)
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}
	if err = m.Drain(ctx, ref, 2); err != nil {
		t.Fatal(err)
	}
	proof, err := m.SecretClosure(ref, f.nb)
	if err != nil || len(proof.Secrets) != len(b.Grants()) || len(proof.Volumes) != 0 {
		t.Fatal("projection falsely signed Volume closure", err)
	}
	if _, err = f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof); err == nil {
		t.Fatal("Secret-only proof released a combined Volume consumer")
	}
	if len(f.v[needs.Volumes[0].Key].Consumers()) != 1 || !f.bindings.Owns(b) {
		t.Fatal("partial closure published shared release")
	}
	if err = m.Forget(ref, f.bindings); err == nil {
		t.Fatal("partial closure erased original scope receipt")
	}
	// This signature is a pure-core fixture, not an actual native Volume fact.
	proof.Volumes = f.closure(b).Volumes
	complete, err := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof)
	if err != nil {
		t.Fatal("whole original closure", err)
	}
	if err = m.Forget(ref, complete.Inventory); err != nil {
		t.Fatal(err)
	}
}
