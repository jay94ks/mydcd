// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshfake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The server runs a shell as sfc-shell on a PTY and reports its exit code.
func TestShell(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := user.Lookup(Account); err == nil {
		t.Skip("sfc-shell exists")
	}
	dir, _ := os.MkdirTemp("", "sshfake-")
	_ = os.Chmod(dir, 0o755)
	defer os.RemoveAll(dir)
	home := filepath.Join(dir, "home")
	if out, err := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", home, "--shell", "/bin/sh", Account).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	defer exec.Command("userdel", "-f", Account).Run()
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(private)
	_ = os.MkdirAll(filepath.Join(home, ".ssh"), 0o755)
	_ = os.Chmod(home, 0o755)
	_ = os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), append([]byte(`from="127.0.0.1" `), ssh.MarshalAuthorizedKey(signer.PublicKey())...), 0o644)
	s, err := Start(filepath.Join(dir, "host.pub"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	client, err := ssh.Dial("tcp", s.Endpoint(), &ssh.ClientConfig{User: Account, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	session.Stdout = &out
	in, _ := session.StdinPipe()
	if err = session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatal("pty", err)
	}
	if err = session.Start("exec /bin/sh -l"); err != nil {
		t.Fatal("start", err)
	}
	_, _ = in.Write([]byte("whoami; stty size; exit 3\r"))
	err = session.Wait()
	var exit *ssh.ExitError
	if !strings.Contains(out.String(), Account) || !strings.Contains(out.String(), "24 80") {
		t.Fatalf("output %q (%v)", out.String(), err)
	}
	if e, ok := err.(*ssh.ExitError); !ok || e.ExitStatus() != 3 {
		t.Fatalf("exit: %v %v", err, exit)
	}
}
