// SPDX-License-Identifier: Apache-2.0

//go:build linux

package clusterfixture

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/tests/sshfake"
)

// NodeShell points node's shell at a test SSH server (tests/sshfake). The
// node's mydcd creates the real mydc-shell account with useradd when its
// shell is turned on; the test removes it at the end. It skips the test
// unless it runs as root on a machine without a mydc-shell account.
func NodeShell(t *testing.T, node string) Option {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("node shell needs root (useradd, running as mydc-shell)")
	}
	if _, err := user.Lookup(sshfake.Account); err == nil {
		t.Skip("a mydc-shell account already exists here")
	}
	if _, err := exec.LookPath("useradd"); err != nil {
		t.Skip("no useradd")
	}
	// The home's parents must let mydc-shell in, unlike t.TempDir.
	dir, err := os.MkdirTemp("", "mydc-shell-")
	if err == nil {
		err = os.Chmod(dir, 0o755)
	}
	if err != nil {
		t.Fatal(err)
	}
	server, err := sshfake.Start(filepath.Join(dir, "host_ed25519.pub"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Close()
		if _, err := user.Lookup(sshfake.Account); err == nil {
			_ = exec.Command("pkill", "-KILL", "-u", sshfake.Account).Run()
			if out, err := exec.Command("userdel", "-f", sshfake.Account).CombinedOutput(); err != nil {
				t.Errorf("userdel %s: %v %s", sshfake.Account, err, out)
			}
		}
		_ = os.RemoveAll(dir)
	})
	return func(n *Node) {
		if n.ID != node {
			return
		}
		n.Config.NodeShell.SSHEndpoint = server.Endpoint()
		n.Config.NodeShell.HostPublicKey = filepath.Join(dir, "host_ed25519.pub")
		n.Config.NodeShell.Home = filepath.Join(dir, "home")
		n.Config.NodeShell.SudoersDir = filepath.Join(dir, "sudoers.d")
	}
}
