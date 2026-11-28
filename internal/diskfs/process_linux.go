// SPDX-License-Identifier: Apache-2.0

package diskfs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Unit is the systemd unit a bundle's server runs in.
func Unit(bundle string) string { return "sfc-diskfs-" + bundle }

// Running reports whether bundle's virtual disk is served now: the FUSE
// file answers with size want (0: any size).
func Running(bundle string, want uint64) bool {
	st, err := os.Stat(DiskFile(bundle))
	return err == nil && st.Mode().IsRegular() && (want == 0 || uint64(st.Size()) == want)
}

// Start runs `exe diskfs serve specPath` apart from sfcd, so a restart of
// sfcd keeps the disk served: as a transient systemd unit when systemd is
// there, else in its own session. It waits until the disk file answers.
// A mount left by a server that died (ENOTCONN) is detached first.
func Start(ctx context.Context, bundle, specPath, exe string) error {
	if Running(bundle, 0) {
		return nil
	}
	if _, err := os.Stat(DiskFile(bundle)); err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = unix.Unmount(MountDir(bundle), unix.MNT_DETACH)
	}
	_ = os.Remove(StatusFile(bundle))
	started := false
	if path, err := exec.LookPath("systemd-run"); err == nil && systemdRunning() {
		_ = exec.CommandContext(ctx, "systemctl", "reset-failed", Unit(bundle)+".service").Run()
		cmd := exec.CommandContext(ctx, path, "--unit", Unit(bundle), "--collect", "--quiet", "-p", "KillMode=mixed", "-p", "TimeoutStopSec=60", exe, "diskfs", "serve", specPath)
		if out, err := cmd.CombinedOutput(); err == nil {
			started = true
		} else if len(out) > 0 {
			err = fmt.Errorf("%w: %s", err, trim(out))
			return err
		}
	}
	if !started {
		cmd := exec.Command(exe, "diskfs", "serve", specPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if Running(bundle, 0) {
			return nil
		}
		if s, ok := ReadStatus(bundle); ok && s.State == "missing" {
			return errors.New("diskfs: the bundle's chunk files could not be opened")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("diskfs: the bundle's disk did not appear")
}

// Stop unmounts the FUSE file, which ends its server (it syncs first).
// The caller detaches the loop device before.
func Stop(bundle string) error {
	err := unix.Unmount(MountDir(bundle), 0)
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		err = nil // not mounted
	}
	if errors.Is(err, unix.EBUSY) {
		return errors.New("diskfs: the bundle's disk is still in use")
	}
	for range 100 {
		if _, ok := ReadStatus(bundle); !ok { // the server removes it on exit
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return err
}

func systemdRunning() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

func trim(b []byte) string {
	if len(b) > 512 {
		b = b[:512]
	}
	return string(b)
}
