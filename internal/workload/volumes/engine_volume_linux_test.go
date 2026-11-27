// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"golang.org/x/sys/unix"
)

func TestEngineMountRefusesWhatSfcdDidNotPlace(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if e := s.Plan(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	f.http.mu.Lock()
	f.http.exists = true
	f.http.mu.Unlock()
	if e := s.Activate(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	volume := f.ref.Consumer.Owner.Native
	for name, c := range map[string][2]string{
		"bad container id": {volume, "not-a-container"},
		"unknown volume":   {"sfc-fixed-unknown", strings.Repeat("a", 64)},
		"other container":  {volume, strings.Repeat("b", 64)},
		// Docker-managed app volumes never go through the engine driver.
		"app volume": {volume, strings.Repeat("a", 64)},
	} {
		if _, h, e := s.EngineMount(ctx, c[0], c[1]); !errors.Is(e, ErrEngineNotOwner) || h != nil {
			t.Fatal(name, e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	if _, _, e := s.EngineMount(ctx, volume, strings.Repeat("a", 64)); !errors.Is(e, ErrEngineNotReady) {
		t.Fatal("closed store", e)
	}
}

func TestEngineVolumeOps(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	ctx := context.Background()
	if e := s.Plan(ctx, f.ref); e != nil {
		t.Fatal(e)
	}
	app := f.ref.Consumer.Owner.Native // a Docker-managed app volume, never an engine volume
	c := strings.Repeat("a", 64)
	reason := func(e error) string {
		var r *engineops.Refusal
		if errors.As(e, &r) {
			return r.Reason
		}
		if e != nil {
			return "error"
		}
		return ""
	}
	check := func(name string, e error, want string) {
		t.Helper()
		if got := reason(e); got != want {
			t.Fatal(name, got, e)
		}
	}
	_, fs, e := s.EngineVolumeMount(ctx, VolumeMountQ{Name: app, MountID: "m", ContainerID: c})
	check("mount app", e, engineops.NotOwner)
	if fs != nil {
		t.Fatal("refused mount returned files")
	}
	_, _, e = s.EngineVolumeMount(ctx, VolumeMountQ{Name: app, ContainerID: c})
	check("mount without id", e, engineops.Invalid)
	_, _, e = s.EngineVolumeCreate(ctx, VolumeCreateQ{Name: "sfc-fixed-nope", Opts: map[string]string{}})
	check("create foreign", e, engineops.NotOwner)
	_, _, e = s.EngineVolumeCreate(ctx, VolumeCreateQ{Name: "sfc-fixed-nope"})
	check("create null opts", e, engineops.Invalid)
	_, _, e = s.EngineVolumeGet(ctx, VolumeGetQ{Name: app})
	check("get app", e, engineops.NotFound)
	_, _, e = s.EngineVolumeRemove(ctx, VolumeRemoveQ{Name: "sfc-fixed-nope"})
	check("remove foreign", e, engineops.NotFound)
	_, _, e = s.EngineVolumeUnmount(ctx, VolumeUnmountQ{Name: app, MountID: "m"})
	check("unmount", e, "")
	l, _, e := s.EngineVolumeList(ctx, VolumeListQ{})
	check("list", e, "")
	if l.Volumes == nil || len(l.Volumes) != 0 {
		t.Fatal("list must be [] without app volumes", l.Volumes)
	}
}

// The real fixed source needs the privileged S1 fixture; this pins the
// answer to whatever directory the opener returns, so the rest of the path
// (binding lookup, read-only, dev/ino) runs everywhere.
func TestEngineMountAnswersTheHeldDirectory(t *testing.T) {
	f := activationTest(t)
	s := f.open(t)
	defer func() { _ = s.Close() }()
	dir := t.TempDir()
	var asked []NativeLease
	s.engineSource = func(_ context.Context, l NativeLease) (*nodestorage.DirectoryHandle, error) {
		asked = append(asked, l)
		return nodestorage.OpenDirectory(dir)
	}
	scope := f.ref.Scope
	scope.App = ""
	owner := f.ref.Consumer.Owner
	owner.Native = "sfc-fixed-test"
	container := strings.Repeat("c", 64)
	binding := func(id string, writable bool, token uint64) activationBinding {
		r := f.ref
		r.Scope, r.Consumer.Owner, r.Consumer.Writable, r.Consumer.ID = scope, owner, writable, id
		return activationBinding{Ref: r, NativeID: container, Lease: NativeLease{Key: "k", Consumer: "activation/" + id, Owner: owner, Scope: scope, Pin: reconcile.Lease{Generation: 1, Token: token}}}
	}
	put := func(bs ...activationBinding) {
		s.mu.Lock()
		s.entries[owner.Native] = &activationEntry{store: s, scope: scope, owner: owner, disk: activationRecord{Schema: 1, Scope: scope, Owner: owner, Bindings: bs}}
		s.mu.Unlock()
	}
	var st unix.Stat_t
	if e := unix.Stat(dir, &st); e != nil {
		t.Fatal(e)
	}
	for _, writable := range []bool{true, false} {
		put(binding("c1", writable, 7))
		m, h, e := s.EngineMount(context.Background(), owner.Native, container)
		if e != nil {
			t.Fatal(e)
		}
		id := h.Identity()
		if m.ReadOnly == writable || m.Ino != st.Ino || m.Dev != uint64(st.Dev) || m.Ino != id.Inode || m.Dev != unix.Mkdev(id.DeviceMajor, id.DeviceMinor) {
			t.Fatal("answer does not match the held directory", m, st.Dev, st.Ino)
		}
		_ = h.Close()
		if l := asked[len(asked)-1]; l.Pin.Token != 7 || l.Consumer != "activation/c1" {
			t.Fatal("opener got another lease", l)
		}
		got, fs, e := s.EngineVolumeMount(context.Background(), VolumeMountQ{Name: owner.Native, MountID: "m", ContainerID: container})
		if e != nil || len(fs) != 1 || got.ReadOnly == writable || got.Ino != st.Ino {
			t.Fatal("mount op", got, e)
		}
		_ = fs[0].Close()
		if got, _, e := s.EngineVolumeGet(context.Background(), VolumeGetQ{Name: owner.Native}); e != nil || got.Status != "ready" || got.Name != owner.Native {
			t.Fatal("get op", got, e)
		}
		if got, _, e := s.EngineVolumeRemove(context.Background(), VolumeRemoveQ{Name: owner.Native}); !strings.Contains(fmt.Sprint(e), engineops.Refused) {
			t.Fatal("remove op", got, e)
		}
		if got, _, _ := s.EngineVolumeList(context.Background(), VolumeListQ{}); len(got.Volumes) != 1 || got.Volumes[0] != owner.Native {
			t.Fatal("list op", got)
		}
	}
	calls := len(asked)
	put(binding("c1", true, 7), binding("c2", true, 8))
	if _, h, e := s.EngineMount(context.Background(), owner.Native, container); !errors.Is(e, ErrEngineNotOwner) || h != nil {
		t.Fatal("two live bindings for one container", e)
	}
	closed := binding("c1", true, 7)
	closed.Closed = true
	put(closed)
	if _, _, e := s.EngineMount(context.Background(), owner.Native, container); !errors.Is(e, ErrEngineNotOwner) {
		t.Fatal("closed binding", e)
	}
	if len(asked) != calls {
		t.Fatal("refused mounts opened the source")
	}
	s.engineSource = func(context.Context, NativeLease) (*nodestorage.DirectoryHandle, error) { return nil, ErrNativeVolume }
	put(binding("c1", true, 7))
	if _, fs, e := s.EngineVolumeMount(context.Background(), VolumeMountQ{Name: owner.Native, MountID: "m", ContainerID: container}); !strings.Contains(fmt.Sprint(e), engineops.NotReady) || fs != nil {
		t.Fatal("moving volume", e)
	}
}
