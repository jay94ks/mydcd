// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/workload"
)

func projectionFixture(t *testing.T) (*fixture, Binding, Stage, ProjectionGate) {
	return projectionFixtureCluster(t, [32]byte{9})
}
func projectionFixtureCluster(t *testing.T, cluster [32]byte, changes ...func(*Needs)) (*fixture, Binding, Stage, ProjectionGate) {
	t.Helper()
	f := makeFixtureCluster(t, cluster)
	n := f.web()
	for i := range n.Files {
		n.Files[i].UID = uint32(os.Geteuid())
		n.Files[i].GID = uint32(os.Getegid())
	}
	for _, change := range changes {
		change(&n)
	}
	f.approveAll(n)
	b := f.reserve(n).Bindings[0]
	stage, err := b.Materialize(f.bindings, f.c, f.trees, f.a, f.v, 100, f.values(n), 4096)
	if err != nil {
		t.Fatal(err)
	}
	gate := func(ctx context.Context, b Binding) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return b.Check(f.bindings, f.c, f.trees, f.a, f.v, 100)
	}
	return f, b, stage, gate
}
func projectionConsumer(t *testing.T, f *fixture, b Binding) (string, string) {
	t.Helper()
	key := projectionTask(b)
	id, err := (&engine.Client{Owner: desired.Owner(f.cluster, b.d.Needs.Use.NodeKey)}).Identity("container", key, reconcile.Resource{Generation: b.d.Needs.Generation, Present: true, Spec: "native-original"})
	if err != nil {
		t.Fatal(err)
	}
	return "workload/" + id.Name, key
}

func TestProjectionStoreDurableOriginalPinsDrainAndPrivateMaterial(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inputs")
	m, err := OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if duplicate, err := OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate); err == nil {
		_ = duplicate.Close()
		t.Fatal("second process owner admitted")
	}
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal("complete filesystem publication", err)
	}
	consumer, key := projectionConsumer(t, f, b)
	lease, err := m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil || len(lease.Files) != 2 {
		t.Fatal("synced native pin", err)
	}
	if _, err = m.SecretClosure(ref, f.na); err == nil {
		t.Fatal("live mount signed as Gone")
	}
	if _, err = json.Marshal(lease); err == nil || bytes.Contains([]byte(fmt.Sprintf("%+v", lease)), []byte(root)) {
		t.Fatal("private source paths logged")
	}
	data, err := os.ReadFile(lease.Files[0].Source)
	if err != nil || !bytes.Equal(data, stage.files[0].Data) {
		t.Fatal("private file bytes", err)
	}
	clear(data)
	info, err := os.Stat(lease.Files[0].Source)
	if err != nil || info.Mode().Perm() != 0400 {
		t.Fatal("projection mode", err)
	}
	journal, err := os.ReadFile(filepath.Join(root, "journal.db"))
	if err != nil || bytes.Contains(journal, []byte("private-db-value")) {
		t.Fatal("fetched value entered public journal", err)
	}
	if _, err = m.AcquireInputs(ctx, ref, consumer, key+"-foreign", ref.Generation); err == nil {
		t.Fatal("foreign native key borrowed inputs")
	}
	if _, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation+1); err == nil {
		t.Fatal("foreign native generation borrowed inputs")
	}
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	if wrong, err := OpenProjections(root, f.cluster, [32]byte{99}, 4096, gate); err == nil {
		_ = wrong.Close()
		t.Fatal("different node adopted source files")
	}
	m, err = OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := m.InspectInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil || recovered.Pin != lease.Pin || recovered.Files[0].Source != lease.Files[0].Source {
		t.Fatal("reopen changed original pin/path", err)
	}
	if err = m.Drain(ctx, ref, 2); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("live native consumer allowed removal", err)
	}
	if gone, err := m.Gone(ref); err != nil || gone {
		t.Fatal("live input mount reported Gone", err)
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("Drain reopened admission")
	}
	if err = m.Drain(ctx, ref, 2); err != nil {
		t.Fatal("final files retirement", err)
	}
	if gone, err := m.Gone(ref); err != nil || !gone {
		t.Fatal("positive local filesystem closure", err)
	}
	wrongRef := ref
	wrongRef.Binding[0] ^= 1
	if gone, err := m.Gone(wrongRef); err == nil || gone {
		t.Fatal("closure rebound to another recipe")
	}
	if err = m.Forget(ref, f.bindings); err == nil {
		t.Fatal("scope receipt dropped before shared usage release")
	}
	proof, err := m.SecretClosure(ref, f.na)
	if err != nil {
		t.Fatal("original filesystem/usage closure signature", err)
	}
	released, err := f.bindings.Release(f.bindings.Revision(), b, f.a, f.v, proof)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Forget(ref, released.Inventory); err != nil {
		t.Fatal("confirmed shared release cleanup", err)
	}
	if _, err = os.Stat(lease.Files[0].Source); !os.IsNotExist(err) {
		t.Fatal("secret source file retained after closure", err)
	}
}

func TestProjectionStoreTamperSymlinkAndMissingAppliedStayClosed(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "inputs")
	m, err := OpenProjections(root, f.cluster, b.d.Needs.Use.NodeKey, 4096, gate)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	consumer, key := projectionConsumer(t, f, b)
	lease, err := m.AcquireInputs(ctx, ref, consumer, key, ref.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(lease.Files[0].Source, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = m.InspectInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("public file mode accepted")
	}
	if err = os.Chmod(lease.Files[0].Source, 0400); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(lease.Files[0].Source)
	if err = os.Rename(dir, dir+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Base(dir)+".original", dir); err != nil {
		t.Fatal(err)
	}
	if _, err = m.InspectInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("internal source directory symlink followed")
	}
	if err = os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(dir+".original", dir); err != nil {
		t.Fatal(err)
	}
	changed := stage.Files()
	changed[0].Data[0] ^= 1
	if _, err = m.Publish(ctx, b, Stage{binding: stage.binding, files: changed}, 1, 2); err == nil {
		t.Fatal("same generation replaced fetched bytes")
	}
	for _, f := range changed {
		clear(f.Data)
	}
	if err = os.Remove(lease.Files[0].Source); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Publish(ctx, b, stage, 1, 2); err == nil {
		t.Fatal("Applied file absence recreated original material")
	}
	if _, err = os.Stat(lease.Files[0].Source); !os.IsNotExist(err) {
		t.Fatal("missing file recreated", err)
	}
	if err = m.ReturnInputs(ref, consumer, key, ref.Generation); err != nil {
		t.Fatal(err)
	}
	if err = m.Drain(ctx, ref, 2); err == nil {
		t.Fatal("missing Applied material erased uncertainty")
	}
	r, err := m.journal.Read(ref.Key)
	if err != nil || r.State.Pending == nil || r.State.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("original removal not retained", err)
	}
	if gone, err := m.Gone(ref); err != nil || gone {
		t.Fatal("uncertain files reported Gone", err)
	}
}

func TestProjectionStoreFinalGateFailureHasNoNativeAdmission(t *testing.T) {
	f, b, stage, gate := projectionFixture(t)
	defer stage.Destroy()
	ctx := context.Background()
	checks := 0
	unavailable := true
	current := func(ctx context.Context, b Binding) error {
		checks++
		if unavailable && checks >= 2 {
			return ErrProjectionStore
		}
		return gate(ctx, b)
	}
	m, err := OpenProjections(filepath.Join(t.TempDir(), "inputs"), f.cluster, b.d.Needs.Use.NodeKey, 4096, current)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ref, err := m.Publish(ctx, b, stage, 1, 2)
	if err == nil {
		t.Fatal("post-sync gate failure became Ready")
	}
	consumer, key := projectionConsumer(t, f, b)
	if _, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("unconfirmed publication borrowed")
	}
	r, err := m.journal.Read(ref.Key)
	if err != nil || r.State.Applied.Present || r.State.Pending != nil || r.State.LastID != 0 {
		t.Fatal("unadmitted preparation dispatched native work", err)
	}
	unavailable = false
	if _, err = m.Publish(ctx, b, stage, 1, 2); err != nil {
		t.Fatal("same synced preparation could not resume", err)
	}
	r, err = m.journal.Read(ref.Key)
	if err != nil || r.State.LastID != 1 {
		t.Fatal("new operation substituted for prepared generation", err)
	}
	unavailable = true
	if _, err = m.AcquireInputs(ctx, ref, consumer, key, ref.Generation); err == nil {
		t.Fatal("current activation gate bypass")
	}
	if err = m.Drain(ctx, ref, 2); err != nil {
		t.Fatal("cleanup depended on restored permissions", err)
	}
}

var _ workload.InputProvider = (*ProjectionStore)(nil)
