// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"golang.org/x/sys/unix"
)

type fakeRemoteVolumes struct {
	dir       string
	err       error
	unmounted []string
}

func (f *fakeRemoteVolumes) EngineMountDir(_ context.Context, name, mountID, container string) (string, bool, bool, error) {
	if name != "sfc-share-a" || container != "c1" {
		return "", false, false, nil
	}
	return f.dir, true, true, f.err
}
func (f *fakeRemoteVolumes) EngineUnmounted(name, mountID string) {
	f.unmounted = append(f.unmounted, name+"/"+mountID)
}
func (f *fakeRemoteVolumes) EngineVolumeNames() []string { return []string{"sfc-share-a"} }

func reasonOf(err error) string {
	var r *engineops.Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	if err != nil {
		return "error"
	}
	return ""
}

func TestRemoteVolumeEngineOps(t *testing.T) {
	remote := &fakeRemoteVolumes{dir: t.TempDir()}
	r := &Runtime{remoteVolumes: remote}
	ctx := context.Background()
	var st unix.Stat_t
	if err := unix.Stat(remote.dir, &st); err != nil {
		t.Fatal(err)
	}
	a, files, err := r.engineVolumeMount(ctx, volumes.VolumeMountQ{Name: "sfc-share-a", MountID: "m1", ContainerID: "c1"})
	if err != nil || len(files) != 1 || !a.ReadOnly || a.Ino != st.Ino || a.Dev != uint64(st.Dev) {
		t.Fatal("remote mount", a, err)
	}
	var fst unix.Stat_t
	if err = unix.Fstat(int(files[0].Fd()), &fst); err != nil || fst.Ino != st.Ino {
		t.Fatal("handed fd is not the mount root", err)
	}
	_ = files[0].Close()
	if _, files, err = r.engineVolumeMount(ctx, volumes.VolumeMountQ{Name: "sfc-share-a", MountID: "m1", ContainerID: "other"}); reasonOf(err) != engineops.NotReady || files != nil {
		// No local store yet, and not a consumer of the remote volume.
		t.Fatal("foreign container before start", err)
	}
	remote.err = errors.New("peer gone")
	if _, _, err = r.engineVolumeMount(ctx, volumes.VolumeMountQ{Name: "sfc-share-a", MountID: "m1", ContainerID: "c1"}); reasonOf(err) != engineops.NotReady {
		t.Fatal("unreachable remote", err)
	}
	remote.err = nil
	remote.dir = remote.dir + "/missing" // RootFD fails after the hold: it must be released
	if _, _, err = r.engineVolumeMount(ctx, volumes.VolumeMountQ{Name: "sfc-share-a", MountID: "m2", ContainerID: "c1"}); reasonOf(err) != engineops.NotReady || len(remote.unmounted) != 1 || remote.unmounted[0] != "sfc-share-a/m2" {
		t.Fatal("hold not released after RootFD failure", err, remote.unmounted)
	}
	remote.unmounted = nil
	if g, _, err := r.engineVolumeGet(ctx, volumes.VolumeGetQ{Name: "sfc-share-a"}); err != nil || g.Status != "ready" {
		t.Fatal("get", g, err)
	}
	if c, _, err := r.engineVolumeCreate(ctx, volumes.VolumeCreateQ{Name: "sfc-share-a", Opts: map[string]string{}}); err != nil || c.Name != "sfc-share-a" {
		t.Fatal("create", c, err)
	}
	if _, _, err := r.engineVolumeRemove(ctx, volumes.VolumeRemoveQ{Name: "sfc-share-a"}); reasonOf(err) != engineops.Refused {
		t.Fatal("remove", err)
	}
	if l, _, err := r.engineVolumeList(ctx, volumes.VolumeListQ{}); err != nil || len(l.Volumes) != 1 {
		t.Fatal("list", l, err)
	}
	if _, _, err := r.engineVolumeUnmount(ctx, volumes.VolumeUnmountQ{Name: "sfc-share-a", MountID: "m1"}); err != nil || len(remote.unmounted) != 1 || remote.unmounted[0] != "sfc-share-a/m1" {
		t.Fatal("unmount", err, remote.unmounted)
	}
}
