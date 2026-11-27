// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestE4OwnedDaemonSocketChild(t *testing.T) {
	path := os.Getenv("SFC_E4_OWNED_SOCKET_CHILD")
	if path == "" {
		t.Skip("owned child only")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdout.WriteString("OWNED_SOCKET_READY\n")
	_, _ = os.Stdin.Read(make([]byte, 1))
	t.Fatal("child must exit by owned SIGKILL")
}

func TestE4ExplicitKilledDaemonSocketRecovery(t *testing.T) {
	for _, name := range []string{"original", "live", "foreign-file", "foreign-socket", "symlink", "wrong-peer"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			root := t.TempDir()
			path := filepath.Join(root, "node.sock")
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestE4OwnedDaemonSocketChild$", "-test.v")
			cmd.Env = append(os.Environ(), "SFC_E4_OWNED_SOCKET_CHILD="+path)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			scanner := bufio.NewScanner(stdout)
			ready := false
			for scanner.Scan() {
				if scanner.Text() == "OWNED_SOCKET_READY" {
					ready = true
					break
				}
			}
			if !ready {
				t.Fatal("owned socket child startup", scanner.Err(), stderr.String())
			}
			original, err := captureOwnedDaemonSocket(path, cmd.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			defer original.close()
			if name == "wrong-peer" {
				if _, err := captureOwnedDaemonSocket(path, cmd.Process.Pid+1); err == nil {
					t.Fatal("different peer PID accepted")
				}
			}
			if name == "live" {
				if err := original.removeAfterKill(cmd); err == nil {
					t.Fatal("live process socket removed")
				}
				info, err := os.Lstat(path)
				if err != nil || !os.SameFile(info, original.info) {
					t.Fatal("live socket changed", err)
				}
			}
			if err = cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			if err == nil {
				t.Fatal("child exited cleanly")
			}
			var foreign os.FileInfo
			if name == "foreign-file" || name == "foreign-socket" || name == "symlink" {
				if err = os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "foreign-file":
					err = os.WriteFile(path, []byte("preserve"), 0600)
				case "foreign-socket":
					var listener *net.UnixListener
					listener, err = net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
					if err == nil {
						listener.SetUnlinkOnClose(false)
						defer listener.Close()
						err = os.Chmod(path, 0600)
					}
				case "symlink":
					target := filepath.Join(root, "target")
					if err = os.WriteFile(target, []byte("preserve"), 0600); err == nil {
						err = os.Symlink(target, path)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				foreign, err = os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			err = original.removeAfterKill(cmd)
			if foreign != nil {
				if err == nil {
					t.Fatal("foreign entry removed")
				}
				current, e := os.Lstat(path)
				if e != nil || !os.SameFile(current, foreign) {
					t.Fatal("foreign inode changed", e)
				}
				if name != "foreign-socket" {
					raw, e := os.ReadFile(path)
					if e != nil || string(raw) != "preserve" {
						t.Fatal("foreign data changed", e)
					}
				}
			} else {
				if err != nil {
					t.Fatal("explicit original recovery", err)
				}
				if _, err = os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("original stale socket still exists", err)
				}
			}
		})
	}
}
