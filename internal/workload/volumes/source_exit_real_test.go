// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/tests/enginefixture"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

func TestRealBoundaryVolumeWriterExitDurability(t *testing.T) {
	testRealVolumeWriterExit(t, false)
}

func TestRealBoundaryVolumeMoveFencedArchive(t *testing.T) {
	testRealVolumeWriterExit(t, true)
}

func testRealVolumeWriterExit(t *testing.T, move bool) {
	if os.Getenv("MYDC_DOCKER_TEST_BACKEND") == "" {
		t.Skip("requires user-prebuilt backend and owned Docker rollback prestate")
	}
	ctx, docker, spec := realNativeVolume(t)
	fixture := enginefixture.OpenPrepared(t, ctx, docker.Owner, os.Getenv("MYDC_DOCKER_TEST_OWNER"), []string{`USER 10001:10001`}, os.Getenv("MYDC_DOCKER_TEST_BACKEND"))
	m, err := OpenNative(filepath.Join(t.TempDir(), "native.db"), docker)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	key, err := m.Desired(spec, 1, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	ready, err := m.Ready(ctx, key, makeFixture(t).a)
	if err != nil {
		t.Fatal(err)
	}
	disk, err := docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	catalog := makeFixture(t).c
	core, err := New(catalog, "admin", spec.Scope, ready.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "activations.db")
	authority := func(_ctx context.Context, request StartRequest) (Permit, error) {
		return core.PermitStart(catalog, "admin", request)
	}
	s, err := OpenActivations(path, m, docker, spec.Scope.Cluster, spec.NodeKey, authority)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err = s.ColdSource(ctx, ready); err == nil {
		t.Fatal("fresh source claimed a clean writer")
	}
	modes := []string{"clean", "137"}
	if move {
		modes = modes[:1]
	}
	for index, mode := range modes {
		generation := uint64(index + 1)
		var consumer Consumer
		core, consumer, err = core.Acquire(catalog, "admin", core.Revision(), "database", generation, true)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(struct {
			Schema      uint8
			Image, Mode string
		}{1, fixture.Image, mode})
		ref := Activation{Scope: spec.Scope, Consumer: consumer, NativeKey: key, NativeGeneration: 1, TaskKey: "workload/task/tenant/app/database", Task: reconcile.Resource{Present: true, Generation: generation, Spec: string(raw)}, Operation: generation}
		if err = s.Plan(ctx, ref); err != nil {
			t.Fatal(err)
		}
		id, err := docker.Identity("container", ref.TaskKey, ref.Task)
		if err != nil {
			t.Fatal(err)
		}
		created, err := docker.API.ContainerCreate(ctx, client.ContainerCreateOptions{Name: id.Name, Config: &container.Config{Image: fixture.Image, User: "10001:10001", Cmd: []string{"/backend", "--volume-exit=" + mode}, Labels: id.Labels}, HostConfig: &container.HostConfig{NetworkMode: "none", Mounts: []mount.Mount{{Type: mount.TypeVolume, Source: ready.Owner.Native, Target: "/data", VolumeOptions: &mount.VolumeOptions{NoCopy: true}}}}})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Activate(ctx, ref); err != nil {
			t.Fatal(err)
		}
		for {
			marker, e := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "exit-marker"))
			if e == nil && string(marker) == "--volume-exit="+mode {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("actual writer not initialized", ctx.Err())
			case <-time.After(20 * time.Millisecond):
			}
		}
		if _, err = s.ColdSource(ctx, ready); err == nil {
			t.Fatal("active writer permitted backup")
		}
		if err = s.Retire(ctx, ref); err != nil {
			t.Fatal(err)
		}
		gone, err := s.Gone(ctx, ref, makeFixture(t).a)
		if err != nil {
			t.Fatal(err)
		}
		core, err = core.Release(gone)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = OpenActivations(path, m, docker, spec.Scope.Cluster, spec.NodeKey, authority)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := s.ColdSource(ctx, ready)
		if mode == "clean" {
			if err != nil || proof.Writer != ref || proof.NativeID != created.ID || !proof.Exit.Clean() {
				t.Fatal("actual clean source lost after original Remove/same DB", proof, err)
			}
		} else if err == nil {
			t.Fatal("latest exit137 reused previous clean exit")
		}
		row := s.entries[ready.Owner.Native].disk
		binding := row.Bindings[bindingIndex(row, ref)]
		if binding.Exit == nil || binding.Exit.Code != map[string]int{"clean": 0, "137": 137}[mode] || !binding.Closed || !binding.Released {
			t.Fatal("actual exit fact/closure not durable", binding.Exit)
		}
	}
	if move {
		fixture := makeFixture(t)
		_, ownerRevision := core.Owner()
		core, err = core.Prepare(catalog, "admin", core.Revision(), ownerRevision, "move", fixture.target, [32]byte{1}, 128<<10)
		if err != nil {
			t.Fatal(err)
		}
		job, _ := core.Move("move")
		authorize := func(ctx context.Context, b Binding) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			current, ok := core.Move(b.ID)
			if !ok || current.Binding != b || current.Phase != Prepared {
				return ErrVolume
			}
			return nil
		}
		fence, err := s.FenceSource(ctx, ready, job.Binding, authorize, fixture.a)
		if err != nil {
			t.Fatal("real clean writer/local gate did not produce source fence", err)
		}
		core, err = core.RecordFence(fence)
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		s, err = OpenActivations(path, m, docker, spec.Scope.Cluster, spec.NodeKey, authority)
		if err != nil {
			t.Fatal(err)
		}
		cold, err := s.ColdSource(ctx, ready)
		if err != nil {
			t.Fatal(err)
		}
		gate, err := s.Checkpoint(cold.Writer)
		if err != nil || gate.FenceThrough != ownerRevision {
			t.Fatal("same DB lost source fence", err)
		}
		if _, _, err = s.entries[ready.Owner.Native].gate.Request(cold.Writer.Consumer, [32]byte{99}); err == nil {
			t.Fatal("old writer can restart")
		}
		var reader Consumer
		core, reader, err = core.AcquireMoveReader(catalog, "admin", core.Revision(), job.Binding)
		if err != nil {
			t.Fatal(err)
		}
		readerAuthority := func(ctx context.Context, got NativeReady, c Consumer) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if got.Owner != ready.Owner || got.Spec != ready.Spec {
				return ErrVolume
			}
			return core.CheckMoveReader(job.Binding, c)
		}
		o := ArchiveOptions{MaxBytes: job.Binding.MaxBytes, MaxEntries: 16, MaxDepth: 8, UID: spec.UID, GID: spec.GID, RootMode: spec.Mode}
		artifact, err := os.OpenFile(filepath.Join(t.TempDir(), "move.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer artifact.Close()
		receipt, err := s.ExportMoveCold(ctx, ready, fence, reader, readerAuthority, artifact, o)
		if err != nil || receipt.Entries != 2 {
			t.Fatal("real fenced source archive", receipt, err)
		}
		archive, err := os.ReadFile(artifact.Name())
		if err != nil || uint64(len(archive)) != receipt.Bytes || sha256.Sum256(archive) != receipt.Digest {
			t.Fatal("real artifact bytes/digest", err)
		}
		// Publication is deliberately not asserted: this boundary syncs the
		// private file only. The durable job owner must publish its own receipt.
		row, err := m.View(key)
		if err != nil || len(row.Consumers) != 0 || len(core.Consumers()) != 1 {
			t.Fatal("native reader returned or shared pin lost", err)
		}
		// Revoke during a real export: no usable receipt despite partial bytes;
		// the original shared pin and gate remain for explicit settlement.
		partial, err := os.OpenFile(filepath.Join(t.TempDir(), "unknown.tar"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer partial.Close()
		calls := 0
		revoked := func(ctx context.Context, ready NativeReady, c Consumer) error {
			calls++
			if calls == 3 {
				return ErrVolume
			}
			return readerAuthority(ctx, ready, c)
		}
		if failed, err := s.ExportMoveCold(ctx, ready, fence, reader, revoked, partial, o); err == nil || failed != (ArchiveReceipt{}) || len(core.Consumers()) != 1 {
			t.Fatal("revoked export published receipt/erased original pin", err)
		}
		closed := Gone{Scope: core.Scope(), Consumer: reader, Stopped: true, MountsGone: true}
		closed.Signature = ed25519.Sign(fixture.a, GoneBytes(closed))
		core, err = core.Release(closed)
		if err != nil {
			t.Fatal(err)
		}
		t.Log("actual clean writer/Remove -> synced original owner fence -> same activation DB/boot change -> exact readonly move pin -> real ExportCold artifact bytes/file sync/native reader return; revoked post-copy authorization yields no receipt and preserves shared pin. Authority/owner transition is product-core fixture, not Raft/MYDCP/SQL or published move completion")
	}
	if err = m.DeleteDesired(key, 2, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	if gone, e := m.Gone(ctx, key, 2, 1); e != nil || !gone {
		t.Fatal("original source cleanup", e)
	}
	if !move {
		t.Log("actual owned writer exits0 then137 on same retained Volume; exact exit synced before Remove, same activation DB/native ID proof, latest unclean writer cannot reuse prior clean proof; no Raft/MySQL/full automatic backup claim")
	}
}
