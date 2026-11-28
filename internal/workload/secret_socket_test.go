// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

func TestSecretSocketDirIsMadeOncePerContainerAndRemoved(t *testing.T) {
	root := filepath.Join(t.TempDir(), "sfev")
	s := &SecretSockets{Root: root}
	for _, bad := range []string{"", ".", "..", "a/b", "a\x00"} {
		if _, err := s.Dir(bad, true); err == nil {
			t.Fatalf("name %q accepted", bad)
		}
	}
	dir, err := s.Dir("sfc-task", false)
	if err != nil || dir != filepath.Join(root, "sfc-task") {
		t.Fatal(dir, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("name-only lookup made the directory")
	}
	for range 2 {
		if _, err = s.Dir("sfc-task", true); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != socketDirMode {
		t.Fatal("directory", info, err)
	}
	if err = os.WriteFile(filepath.Join(dir, "sfev.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = s.Remove("sfc-task"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("directory left after Remove")
	}
	if err = s.Remove("sfc-task"); err != nil {
		t.Fatal("second Remove:", err)
	}
	// A symlink in the container's place is never followed.
	if err = os.Symlink(t.TempDir(), filepath.Join(root, "sfc-link")); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Dir("sfc-link", true); err == nil {
		t.Fatal("symlink accepted as socket directory")
	}
}

func TestSecretSocketLeaseAddsOneReadOnlyDirectoryMount(t *testing.T) {
	d := &DockerDriver{Sockets: &SecretSockets{Root: filepath.Join(t.TempDir(), "sfev")}}
	plain, err := d.secretSocketLease(InputLease{}, ContainerSpec{}, "sfc-task", "acquire")
	if err != nil || len(plain.Files) != 0 {
		t.Fatal("socket added without the spec asking", plain.Files, err)
	}
	s := ContainerSpec{SecretSocket: true}
	file := InputFile{Source: "/state/inputs/f", Target: "/run/secrets/db", Mode: 0400}
	l, err := d.secretSocketLease(InputLease{Files: []InputFile{file}}, s, "sfc-task", "acquire")
	if err != nil || len(l.Files) != 2 || l.Files[1].Kind != "socket" || l.Files[1].Target != SecretSocketTarget {
		t.Fatal("lease", l.Files, err)
	}
	if len(secretValueFiles(l.Files)) != 1 || validInputDelivery(l.Files[1]) {
		t.Fatal("socket directory treated as a value")
	}
	mounts := inputMounts(l.Files)
	if len(mounts) != 2 || mounts[1].Source != l.Files[1].Source || mounts[1].Target != SecretSocketTarget || !mounts[1].ReadOnly || mounts[1].Type != mount.TypeBind {
		t.Fatal("mounts", mounts)
	}
	got := container.InspectResponse{HostConfig: &container.HostConfig{Mounts: mounts}}
	for _, m := range mounts {
		got.Mounts = append(got.Mounts, container.MountPoint{Type: m.Type, Source: m.Source, Destination: m.Target})
	}
	if !matchInputMounts(got, l.Files) {
		t.Fatal("container with the socket directory did not match")
	}
	if matchInputMounts(got, l.Files[:1]) {
		t.Fatal("socket directory not counted")
	}
	// Retirement names the directory but does not make it again.
	gone := &DockerDriver{Sockets: &SecretSockets{Root: filepath.Join(t.TempDir(), "sfev")}}
	r, err := gone.secretSocketLease(InputLease{}, s, "sfc-task", "retire")
	if err != nil || len(r.Files) != 1 {
		t.Fatal(r.Files, err)
	}
	if _, err := os.Lstat(r.Files[0].Source); !os.IsNotExist(err) {
		t.Fatal("retirement made the directory")
	}
	// Nothing else may be mounted at or over the socket directory.
	over := InputFile{Source: "/state/inputs/f", Target: SecretSocketTarget + "/x", Mode: 0400}
	if _, err = d.secretSocketLease(InputLease{Files: []InputFile{over}}, s, "sfc-task", "acquire"); err == nil {
		t.Fatal("file over the socket directory accepted")
	}
	if _, err = (&DockerDriver{}).secretSocketLease(InputLease{}, s, "sfc-task", "acquire"); err == nil {
		t.Fatal("driver without socket root accepted a socket")
	}
}

func TestSecretSocketSpecNeedsTheProcessEnvironment(t *testing.T) {
	f := makeStartFixture(t)
	s := f.spec
	s.SecretSocket = true
	raw, _ := json.Marshal(s)
	if _, err := DecodeContainer(string(raw)); err == nil {
		t.Fatal("secret socket without a resolved process accepted")
	}
}
