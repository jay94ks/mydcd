// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func testSpec(id string, writable bool) Spec {
	return Spec{
		Scope:    volumes.Scope{Cluster: [32]byte{1}, Tenant: "t", App: "a", ID: "data", Generation: 3},
		Consumer: volumes.Consumer{ID: id, Generation: 1, Writable: writable, Runner: "node-b", RunnerKey: "00"},
		Home:     [32]byte{9},
	}
}

type fakeAttach struct {
	attached, detached int
	fail               error
}

func (f *fakeAttach) attach(_ context.Context, s Spec) (Attached, error) {
	f.attached++
	return Attached{Dir: "/run/test/" + s.Name(), Detach: func() error {
		if f.fail != nil {
			return f.fail
		}
		f.detached++
		return nil
	}}, nil
}

// Hold mounts once per consumer; only the bound container's Mount is
// answered, holds follow mount_id, and Release unmounts even with holds a
// gone container left.
func TestMountsFollowTheTask(t *testing.T) {
	f := &fakeAttach{}
	m := New(f.attach)
	ctx := context.Background()
	spec := testSpec("task-1", true)
	name, err := m.Hold(ctx, spec)
	if err != nil || name != spec.Name() {
		t.Fatal(name, err)
	}
	if again, err := m.Hold(ctx, spec); err != nil || again != name || f.attached != 1 {
		t.Fatal("second hold mounted again", err, f.attached)
	}
	other := spec
	other.Home = [32]byte{8}
	if _, err := m.Hold(ctx, other); !errors.Is(err, ErrHeld) {
		t.Fatal("held with another home", err)
	}
	local := spec
	local.Consumer.Runner, local.Consumer.RunnerKey = "", ""
	if _, err := m.Hold(ctx, local); !errors.Is(err, ErrUnknown) {
		t.Fatal("local consumer held", err)
	}

	if _, _, found, err := m.EngineMountDir(ctx, name, "m1", "c1"); !found || !errors.Is(err, ErrNotBound) {
		t.Fatal("mount before bind", found, err)
	}
	if err := m.Bind(name, "c1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Bind(name, "c2"); !errors.Is(err, ErrNotBound) {
		t.Fatal("rebound to another container", err)
	}
	if _, _, found, err := m.EngineMountDir(ctx, name, "m1", "c2"); !found || err == nil {
		t.Fatal("other container mounted", err)
	}
	if _, _, found, _ := m.EngineMountDir(ctx, "sfc-remote-unknown", "m1", "c1"); found {
		t.Fatal("unknown name found")
	}
	dir, ro, found, err := m.EngineMountDir(ctx, name, "m1", "c1")
	if err != nil || !found || ro || dir != "/run/test/"+name {
		t.Fatal(dir, ro, found, err)
	}
	_, _, _, _ = m.EngineMountDir(ctx, name, "m1", "c1")
	_, _, _, _ = m.EngineMountDir(ctx, name, "m2", "c1")
	if _, holds := m.Held(name); holds != 2 {
		t.Fatal("holds", holds)
	}
	m.EngineUnmounted(name, "m1")
	if _, holds := m.Held(name); holds != 1 {
		t.Fatal("holds after unmount", holds)
	}
	if names := m.EngineVolumeNames(); len(names) != 1 || names[0] != name {
		t.Fatal(names)
	}

	f.fail = errors.New("busy")
	if err := m.Release(name); err == nil {
		t.Fatal("release reported done after a failed detach")
	}
	if held, _ := m.Held(name); !held {
		t.Fatal("failed release forgot the mount")
	}
	f.fail = nil
	if err := m.Release(name); err != nil || f.detached != 1 {
		t.Fatal(err, f.detached)
	}
	if held, _ := m.Held(name); held || len(m.EngineVolumeNames()) != 0 {
		t.Fatal("released mount still listed")
	}
	if err := m.Release(name); err != nil {
		t.Fatal("second release", err)
	}
	if _, err := m.Hold(ctx, spec); !errors.Is(err, ErrNotReleased) {
		t.Fatal("hold after release", err)
	}
}

// A reader's engine answer is read-only; names differ per consumer and
// generation.
func TestMountNamesAndReaders(t *testing.T) {
	m := New((&fakeAttach{}).attach)
	ctx := context.Background()
	reader := testSpec("task-r", false)
	name, err := m.Hold(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = m.Bind(name, "c")
	if _, ro, _, err := m.EngineMountDir(ctx, name, "m", "c"); err != nil || !ro {
		t.Fatal("reader mount writable", err)
	}
	next := reader
	next.Scope.Generation++
	if next.Name() == reader.Name() || testSpec("task-w", false).Name() == reader.Name() {
		t.Fatal("names collide")
	}
	ref, err := ParseMountRef(reader.Ref().String())
	if err != nil || ref != reader.Ref() {
		t.Fatal(ref, err)
	}
	for _, bad := range []string{"", "{}", `{"Scope":{},"Consumer":"x"}`, reader.Ref().String() + " "} {
		if _, err := ParseMountRef(bad); err == nil {
			t.Fatalf("parsed %q", bad)
		}
	}
}

// One writer Start at a time on this server; an unknown outcome keeps the
// next writer waiting; readers never wait; Gone needs Release and the
// runner's own key; a restarted sfcd keeps all of it.
func TestMountsJournal(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "remote.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	key := private.Public().(ed25519.PublicKey)
	spec := func(id string, writable bool) Spec {
		s := testSpec(id, writable)
		s.Consumer.RunnerKey = hex.EncodeToString(key)
		return s
	}
	f := &fakeAttach{}
	m, err := Open(db, f.attach)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	names := map[string]string{}
	for _, id := range []string{"w1", "w2", "r1"} {
		names[id], err = m.Hold(ctx, spec(id, id[0] == 'w'))
		if err != nil {
			t.Fatal(err)
		}
		if err := m.BeginStart(names[id]); !errors.Is(err, ErrUnknown) {
			t.Fatal("start before bind", err)
		}
		_ = m.Bind(names[id], "c-"+id)
	}
	if err := m.BeginStart(names["w1"]); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginStart(names["w2"]); !errors.Is(err, ErrStarting) {
		t.Fatal("second writer started", err)
	}
	if err := m.BeginStart(names["r1"]); err != nil {
		t.Fatal("reader waited", err)
	}

	// Restart with w1's Start unsettled: the record says so.
	m, err = Open(db, f.attach)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.BeginStart(names["w2"]); !errors.Is(err, ErrStarting) {
		t.Fatal("restart forgot the unknown start", err)
	}
	if len(m.EngineVolumeNames()) != 3 {
		t.Fatal(m.EngineVolumeNames())
	}
	// The engine asks again after the restart: attached on demand.
	if dir, _, found, err := m.EngineMountDir(ctx, names["w1"], "m", "c-w1"); err != nil || !found || dir == "" {
		t.Fatal("reattach", err)
	}
	if _, err := m.Gone(spec("w1", true).Scope, spec("w1", true).Consumer, private); !errors.Is(err, ErrNotReleased) {
		t.Fatal("gone before release", err)
	}
	if err := m.EndStart(names["w1"]); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginStart(names["w2"]); err != nil {
		t.Fatal("settled start still blocks", err)
	}
	if err := m.Release(names["w1"]); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Hold(ctx, spec("w1", true)); !errors.Is(err, ErrNotReleased) {
		t.Fatal("released consumer mounted again", err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	if _, err := m.Gone(spec("w1", true).Scope, spec("w1", true).Consumer, other); err == nil {
		t.Fatal("gone signed by another key")
	}
	g, err := m.Gone(spec("w1", true).Scope, spec("w1", true).Consumer, private)
	if err != nil || !g.Stopped || !g.MountsGone || !ed25519.Verify(key, volumes.GoneBytes(g), g.Signature) {
		t.Fatal("gone", err)
	}
	m, err = Open(db, f.attach)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Gone(g.Scope, g.Consumer, private); err != nil {
		t.Fatal("gone after restart", err)
	}
	if n := m.ForgetGone(func(Spec) bool { return false }); n != 0 {
		t.Fatal("forgot a consumer Raft still has", n)
	}
	if n := m.ForgetGone(func(s Spec) bool { return true }); n != 1 || m.Forget(names["w2"]) == nil {
		t.Fatal("forget gone", n)
	}
	if m, err = Open(db, f.attach); err != nil || len(m.EngineVolumeNames()) != 2 || len(m.Released()) != 0 {
		t.Fatal("after forget", err)
	}
}
