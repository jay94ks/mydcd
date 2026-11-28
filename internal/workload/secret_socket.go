// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/moby/moby/client"
)

// sfev.sock place (design: devel/proposals/sfev-sock.md). A container whose
// spec asks for a secret socket gets its own host directory, bound read-only
// at SecretSocketTarget. The directory lives on sfcd's inputs tmpfs and is
// made before Create and again before every Start (a reboot empties the
// tmpfs); the socket inside it is the sfev endpoint's, opened after the
// container runs. Binding the directory rather than the socket keeps the
// container's path alive when sfcd restarts and opens the socket again.
const (
	// SecretSocketTarget is the directory in the container.
	SecretSocketTarget = "/run/sfc"
	// SecretSocketEnv names the socket in the container.
	SecretSocketEnv = "SFC_SECRET_SOCKET"
	// SecretSocketPath is the socket in the container.
	SecretSocketPath = SecretSocketTarget + "/sfev.sock"

	socketDirMode = 0o711
)

// ErrSecretSocket: the container's socket directory is unavailable.
var ErrSecretSocket = errors.New("secret socket directory unavailable")

// SecretSockets owns the per-container socket directories under Root.
type SecretSockets struct {
	Root string
}

// Dir is the host directory of container name. With create it makes Root and
// the directory (0711, sfcd-owned) when missing; an existing entry that is
// not a plain directory is refused.
func (s *SecretSockets) Dir(name string, create bool) (string, error) {
	if s == nil || !filepath.IsAbs(s.Root) || filepath.Clean(s.Root) != s.Root || !socketDirName(name) {
		return "", ErrSecretSocket
	}
	dir := filepath.Join(s.Root, name)
	if create {
		if err := plainDir(s.Root, true); err != nil {
			return "", err
		}
		if err := plainDir(dir, true); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// Remove deletes container name's directory and the socket in it.
func (s *SecretSockets) Remove(name string) error {
	dir, err := s.Dir(name, false)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil || !info.IsDir() {
		return ErrSecretSocket
	}
	return os.RemoveAll(dir)
}

func plainDir(path string, create bool) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && create {
		if err = os.Mkdir(path, socketDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return ErrSecretSocket
		}
		if err = os.Chmod(path, socketDirMode); err != nil {
			return ErrSecretSocket
		}
		info, err = os.Lstat(path)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrSecretSocket
	}
	return nil
}

// socketDirName is an engine container name: one path element.
func socketDirName(name string) bool {
	return name != "" && len(name) <= 255 && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00\r\n")
}

// socketInput is the socket directory as a mounted input of the lease.
func socketInput(dir string) InputFile {
	return InputFile{Source: dir, Target: SecretSocketTarget, Mode: socketDirMode, Kind: "socket"}
}

// secretSocketLease adds container name's socket directory to l when s asks
// for one. Retirement only names the directory; it never makes one.
func (d *DockerDriver) secretSocketLease(l InputLease, s ContainerSpec, name, mode string) (InputLease, error) {
	if !s.SecretSocket {
		return l, nil
	}
	dir, err := d.Sockets.Dir(name, mode != "retire")
	if err != nil {
		return InputLease{}, err
	}
	for _, f := range l.Files {
		if f.Kind != "env" && OverlappingMounts(f.Target, SecretSocketTarget) {
			return InputLease{}, ErrInputMount
		}
	}
	l.Files = append(l.Files, socketInput(dir))
	return l, nil
}

// secretValueFiles are the lease files that carry values (not the socket
// directory).
func secretValueFiles(files []InputFile) []InputFile {
	var result []InputFile
	for _, f := range files {
		if f.Kind != "socket" {
			result = append(result, f)
		}
	}
	return result
}

// SecretSocketAnchor is the running container of key whose spec asks for a
// secret socket: its native ID, init PID and socket directory. The caller
// pins the PID (pidfd) and asks again to prove it did not change meanwhile.
type SecretSocketAnchor struct {
	Name, NativeID string
	PID            int
	Dir            string
	Generation     uint64
}

// SecretSocketAnchor reads key's Applied container. ok is false when the
// spec has no socket or the container is not running.
func (m *Manager) SecretSocketAnchor(ctx context.Context, key string) (SecretSocketAnchor, bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return SecretSocketAnchor{}, false, err
	}
	if r.State.Pending != nil || !r.State.Applied.Present {
		return SecretSocketAnchor{}, false, nil
	}
	op := reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied}
	s, id, err := m.driver.parameters(key, op)
	if err != nil || !s.SecretSocket {
		return SecretSocketAnchor{}, false, err
	}
	dir, err := m.driver.Sockets.Dir(id.Name, false)
	if err != nil {
		return SecretSocketAnchor{}, false, err
	}
	got, err := m.driver.Engine.API.ContainerInspect(ctx, id.Name, client.ContainerInspectOptions{})
	if err != nil {
		return SecretSocketAnchor{}, false, err
	}
	c := got.Container
	if c.Config == nil || c.State == nil || !id.Matches(c.Name, c.Config.Labels) || c.ID == "" {
		return SecretSocketAnchor{}, false, engine.ErrOwnership
	}
	if !containerProcessReady(c.State) || c.State.Pid <= 0 {
		return SecretSocketAnchor{}, false, nil
	}
	return SecretSocketAnchor{Name: id.Name, NativeID: c.ID, PID: c.State.Pid, Dir: dir, Generation: r.State.Applied.Generation}, true, nil
}
