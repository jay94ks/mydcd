// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/secrets"
	"golang.org/x/sys/unix"
)

func TestComposeGroupHiddenTTYChild(t *testing.T) {
	if os.Getenv("SFC_GROUP_TTY_CHILD") != "1" {
		t.Skip("owned PTY helper")
	}
	value, err := readGroupPassword(composeOptions{}, secrets.Target{Realm: "tenant", Group: "alpha", App: "app", Deployment: "deploy"}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(value)
	if string(value) != "hidden-group-input" {
		t.Fatal("different protected input")
	}
	fmt.Fprintln(os.Stdout, "accepted hidden input")
}

func TestComposeGroupHiddenTTYDoesNotEcho(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "owned-group-pty")
	defer master.Close()
	if err = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slave.Close()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, self, "-test.run=^TestComposeGroupHiddenTTYChild$")
	child.Env = append(os.Environ(), "SFC_GROUP_TTY_CHILD=1")
	child.Stdin, child.Stdout, child.Stderr = slave, slave, slave
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	_ = slave.Close()
	stop := context.AfterFunc(ctx, func() { _ = master.Close() })
	defer stop()
	var output bytes.Buffer
	done := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(done) }()
	for {
		state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if state.Lflag&unix.ECHO == 0 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	if _, err = master.Write([]byte("hidden-group-input\n")); err != nil {
		t.Fatal(err)
	}
	if err = child.Wait(); err != nil {
		t.Fatal("PTY input child", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if !bytes.Contains(output.Bytes(), []byte("Password:")) || !bytes.Contains(output.Bytes(), []byte("accepted hidden input")) || bytes.Contains(output.Bytes(), []byte("hidden-group-input")) {
		t.Fatal("hidden TTY output contract")
	}
	t.Log("owned controlling PTY: same product Group password reader disables echo; private input absent from output; child and PTY released")
}
