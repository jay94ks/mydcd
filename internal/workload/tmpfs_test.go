// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestTmpfsBudgetAndTargetConflicts(t *testing.T) {
	good := Tmpfs{Target: "/scratch", SizeBytes: 4 << 20, Mode: 0700, UID: 10001, GID: 10001}
	if err := ValidateTmpfs([]Tmpfs{good}, 32<<20, nil); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Tmpfs){func(v *Tmpfs) { v.Target = "/" }, func(v *Tmpfs) { v.Target = "/proc/data" }, func(v *Tmpfs) { v.Target = "/scratch/../other" }, func(v *Tmpfs) { v.SizeBytes = 0 }, func(v *Tmpfs) { v.SizeBytes = -1 }, func(v *Tmpfs) { v.SizeBytes = math.MaxInt64 }, func(v *Tmpfs) { v.Mode = 010000 }} {
		bad := good
		mutate(&bad)
		if ValidateTmpfs([]Tmpfs{bad}, 32<<20, nil) == nil {
			t.Fatal("invalid tmpfs admitted", bad)
		}
	}
	child := good
	child.Target = "/scratch/child"
	if ValidateTmpfs([]Tmpfs{good, child}, 32<<20, nil) == nil || ValidateTmpfs([]Tmpfs{good, good}, 32<<20, nil) == nil || ValidateTmpfs([]Tmpfs{good}, 32<<20, []string{"/scratch/secret"}) == nil {
		t.Fatal("overlapping mount admitted")
	}
	second := good
	second.Target = "/other"
	second.SizeBytes = 30 << 20
	if ValidateTmpfs([]Tmpfs{good, second}, 32<<20, nil) == nil {
		t.Fatal("aggregate tmpfs exceeded task memory")
	}
	var tooMany []Tmpfs
	for i := 0; i < 65; i++ {
		v := good
		v.Target = fmt.Sprintf("/scratch-%d", i)
		v.SizeBytes = 1
		tooMany = append(tooMany, v)
	}
	if ValidateTmpfs(tooMany, 32<<20, nil) == nil {
		t.Fatal("mount-count budget bypass")
	}
}

func TestTmpfsSDKOptionsAndForeignMounts(t *testing.T) {
	v := []Tmpfs{{Target: "/scratch", SizeBytes: 4 << 20, Mode: 0700, UID: 10001, GID: 10002}}
	options := tmpfsMounts(v)
	if options["/scratch"] != "rw,nosuid,nodev,noexec,size=4194304,mode=700,uid=10001,gid=10002" {
		t.Fatal("SDK recipe lost security/ownership/size")
	}
	got := container.InspectResponse{HostConfig: &container.HostConfig{Tmpfs: options}}
	if !matchTmpfs(got, v) || !matchInputMounts(got, nil) {
		t.Fatal("original typed recipe rejected")
	}
	got.HostConfig.Tmpfs["/scratch"] += ",exec"
	if matchTmpfs(got, v) {
		t.Fatal("unexpected options accepted")
	}
	got.HostConfig.Tmpfs = tmpfsMounts(v)
	got.HostConfig.Tmpfs["/foreign"] = "size=4096"
	if matchTmpfs(got, v) {
		t.Fatal("unapproved tmpfs accepted")
	}
	got.HostConfig.Tmpfs = tmpfsMounts(v)
	got.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeTmpfs, Target: "/foreign"}}
	if matchInputMounts(got, nil) {
		t.Fatal("unapproved alternate mount API accepted")
	}
	if MountTarget(`/scratch\..\proc`) {
		t.Fatal("Engine backslash normalization escaped approved target")
	}
}

func TestImageVolumeNeedsExactExplicitMount(t *testing.T) {
	image := &container.Config{User: "10001:10001", Cmd: []string{"/backend"}, Volumes: map[string]struct{}{"/scratch/data": {}}}
	id := "sha256:" + strings.Repeat("a", 64)
	for _, targets := range [][]string{nil, {"/scratch"}, {"/other"}} {
		if _, err := ResolveProcess(id, image, ProcessOverrides{MountTargets: targets}); err == nil {
			t.Fatal("missing/substituted image VOLUME accepted")
		}
	}
	process, err := ResolveProcess(id, image, ProcessOverrides{MountTargets: []string{"/scratch/data"}})
	if err != nil {
		t.Fatal("exact admitted mount rejected", err)
	}
	config, err := process.ContainerConfig(nil)
	if err != nil || len(config.Volumes) != 0 || len(image.Volumes) != 1 {
		t.Fatal("anonymous volume declaration leaked or caller metadata mutated", err)
	}
}
