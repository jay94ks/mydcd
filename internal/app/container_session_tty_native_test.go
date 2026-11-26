// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/containerops"
	"golang.org/x/sys/unix"
)

type sessionCLIOutput struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *sessionCLIOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}
func (b *sessionCLIOutput) contains(s string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Contains(b.b.Bytes(), []byte(s))
}
func (b *sessionCLIOutput) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// This is the real prebuilt CLI against the current managed app, not a child
// helper invoking terminal functions in isolation. Only owned PTYs are changed.
func verifyManagedSessionCLITerminal(t *testing.T, parent context.Context, root string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(parent, 20*time.Second)
	defer cancel()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "owned-container-session-pty")
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
	original, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || original.Lflag&unix.ECHO == 0 || original.Lflag&unix.ICANON == 0 {
		t.Fatal("owned PTY original state", err)
	}
	if err = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}); err != nil {
		t.Fatal(err)
	}
	password, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer password.Close()
	_, err = io.WriteString(writer, "private-fixture-wallet-passphrase\n")
	_ = writer.Close()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, os.Getenv("MYDC_TEST_CLI"), "--config", filepath.Join(root, "cli.yaml"), "--wallet-password-fd", "3", "--no-input", "--tenant", "tenant", "compose", "exec", "-p", "app", "--operation", "cli-tty-original", "-it", "web", "--", "/backend", "--exec-io-fixture")
	child.Env = append(os.Environ(), "HOME="+filepath.Join(root, "cli-home"))
	child.ExtraFiles = []*os.File{password}
	child.Stdin, child.Stdout, child.Stderr = slave, slave, slave
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	// Keep the slave open here to inspect restoration after the child exits.
	// Closing our master unblocks and joins the sole output-reader goroutine.
	var output sessionCLIOutput
	readerDone := make(chan struct{})
	go func() { _, _ = io.Copy(&output, master); close(readerDone) }()
	childDone := make(chan error, 1)
	go func() { childDone <- child.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			<-childDone
		}
		_ = master.Close()
		<-readerDone
	}()
	await := func(label string, ready func() bool) {
		t.Helper()
		for !ready() {
			select {
			case err := <-childDone:
				waited = true
				t.Fatal("CLI exited before", label, err, output.text())
			case <-ctx.Done():
				t.Fatal("CLI PTY", label, ctx.Err(), output.text())
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	await("native ready/raw mode", func() bool { return output.contains("exec-io-ready") })
	raw, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || raw.Lflag&(unix.ECHO|unix.ICANON|unix.ISIG) != 0 {
		t.Fatal("CLI did not enter raw terminal", err)
	}
	if err = unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 37, Col: 91}); err != nil {
		t.Fatal(err)
	}
	if err = child.Process.Signal(syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	// Query the actual native TTY until the asynchronous resize is observed.
	// Repeated stdin queries are not repeated exec/Create/Attach operations.
	for !output.contains("SIZE 37 91") {
		if _, err = master.Write([]byte("size\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ctx.Done():
			t.Fatal("CLI native resize", ctx.Err(), output.text())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if _, err = master.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-childDone:
		waited = true
	case <-ctx.Done():
		t.Fatal("CLI interrupt/restore", ctx.Err(), output.text())
	}
	exited, ok := err.(interface{ ExitCode() int })
	if !ok || exited.ExitCode() != 130 {
		t.Fatal("CLI Ctrl-C did not reach native process", err, output.text())
	}
	restored, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *restored != *original {
		t.Fatal("CLI did not restore original terminal", err)
	}
	if output.contains("private-fixture-wallet-passphrase") {
		t.Fatal("private wallet input leaked into terminal")
	}
	t.Log("actual CLI raw/resize/Ctrl-C/exit130/full termios restoration; owned child and PTY joined")
}

func verifyManagedSessionCLIWatch(t *testing.T, parent context.Context, root string) {
	t.Helper()
	for _, kind := range []string{"logs", "top", "stats"} {
		func() {
			ctx, cancel := context.WithTimeout(parent, 20*time.Second)
			defer cancel()
			password, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer password.Close()
			_, err = io.WriteString(writer, "private-fixture-wallet-passphrase\n")
			_ = writer.Close()
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"--config", filepath.Join(root, "cli.yaml"), "--wallet-password-fd", "3", "--no-input", "--tenant", "tenant", "compose", kind, "-p", "app", "web"}
			if kind == "logs" {
				args = append(args, "--follow", "--tail", "1")
			} else {
				args = append(args, "--watch", "--interval", "1s", "--json")
			}
			child := exec.CommandContext(ctx, os.Getenv("MYDC_TEST_CLI"), args...)
			child.Env = append(os.Environ(), "HOME="+filepath.Join(root, "cli-home"))
			child.ExtraFiles = []*os.File{password}
			var output, diagnostic sessionCLIOutput
			child.Stdout, child.Stderr = &output, &diagnostic
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			waited := false
			defer func() {
				if !waited {
					_ = child.Process.Kill()
					<-done
				}
			}()
			ready := func() bool {
				if kind == "logs" {
					return output.contains("rv5-follow-new-031:")
				}
				decoder := json.NewDecoder(strings.NewReader(output.text()))
				count := 0
				for {
					var sample containerops.Result
					if decoder.Decode(&sample) != nil {
						return count >= 2
					}
					if sample.Schema == 1 && sample.Kind == kind && !sample.ObservedAt.IsZero() {
						count++
					}
				}
			}
			for !ready() {
				select {
				case err = <-done:
					waited = true
					t.Fatal("CLI continuous observation ended early", kind, err, diagnostic.text(), output.text())
				case <-ctx.Done():
					t.Fatal("CLI continuous observation", kind, ctx.Err(), diagnostic.text(), output.text())
				case <-time.After(20 * time.Millisecond):
				}
			}
			if err = child.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			select {
			case err = <-done:
				waited = true
			case <-time.After(5 * time.Second):
				t.Fatal("CLI did not reclaim continuous session on cancellation", kind)
			}
			if exited, ok := err.(interface{ ExitCode() int }); !ok || exited.ExitCode() != 4 {
				t.Fatal("CLI cancelled session exit", kind, err, diagnostic.text())
			}
			t.Log("actual CLI continuous/cancel", kind)
		}()
	}
}
