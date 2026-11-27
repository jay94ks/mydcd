// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// openPTY returns a new pseudo-terminal pair (master, slave).
func openPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skip("no /dev/ptmx", err)
	}
	if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetUint32(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slave, err := os.OpenFile("/dev/pts/"+itoa(int(n)), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	return master, slave
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// A prompt for a password must never wait when nobody can answer: not with
// stdin from a file, and not as a background job on a real terminal (a read
// there would stop the process with SIGTTIN, forever).
func TestHiddenPromptFailsAtOnceWithoutForegroundTerminal(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	binary := filepath.Join(root, "sfcli")
	build := exec.CommandContext(ctx, "go", "build", "-p", "2", "-o", binary, "./cmd/sfcli")
	build.Dir = repo
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatal("CLI build", err, string(b))
	}
	home := filepath.Join(root, "home")
	if err = os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	env := []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}

	quick := func(name string, cmd *exec.Cmd) string {
		t.Helper()
		done := make(chan error, 1)
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(name, err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal(name, "prompt without a terminal succeeded", out.String())
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal(name, "waited for a password nobody can type", out.String())
		}
		return out.String()
	}

	// stdin is not a terminal.
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	piped := exec.CommandContext(ctx, binary, "key", "create", "k1")
	piped.Env, piped.Stdin = env, null
	if out := quick("piped", piped); !strings.Contains(out, "terminal") {
		t.Fatal("piped: unclear error", out)
	}

	// In the foreground of a terminal the prompt still works.
	{
		master, slave := openPTY(t)
		cmd := exec.CommandContext(ctx, binary, "key", "create", "k1")
		cmd.Env, cmd.Stdin = env, slave
		var out strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &out
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		go func() {
			buf := make([]byte, 256)
			for {
				if _, err := master.Read(buf); err != nil {
					return
				}
			}
		}()
		for _, line := range []string{"fixture-password\n", "fixture-password\n"} {
			time.Sleep(300 * time.Millisecond)
			_, _ = master.Write([]byte(line))
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("foreground prompt", err, out.String())
			}
		case <-time.After(20 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("foreground prompt never finished", out.String())
		}
		_ = slave.Close()
		_ = master.Close()
		if err := os.RemoveAll(filepath.Join(home, ".sfc")); err != nil {
			t.Fatal(err)
		}
	}

	// SFC_NONINTERACTIVE=1 never prompts, even on a terminal.
	{
		master, slave := openPTY(t)
		env := append(env, "SFC_NONINTERACTIVE=1")
		shell := exec.CommandContext(ctx, binary, "key", "create", "k1")
		shell.Env, shell.Stdin = env, slave
		shell.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
		quick("SFC_NONINTERACTIVE", shell)
		_ = master.Close()
		_ = slave.Close()
	}

	// A background job (its own process group) on a real terminal.
	master, slave := openPTY(t)
	defer master.Close()
	defer slave.Close()
	shell := exec.CommandContext(ctx, "sh", "-c", `set -m; "$1" key create k1 </dev/tty & wait $!`, "sh", binary)
	shell.Env = env
	shell.Stdin = slave
	shell.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	quick("background", shell)
}
