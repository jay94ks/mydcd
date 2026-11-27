// SPDX-License-Identifier: Apache-2.0

package fdstore

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Store sends FDSTORE with the descriptor attached; Remove names it.
func TestStoreSendsRights(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify")
	l, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	t.Setenv("NOTIFY_SOCKET", path)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	if err := Store("sfc-test", int(w.Fd())); err != nil {
		t.Fatal(err)
	}
	buf, oob := make([]byte, 256), make([]byte, 64)
	n, oobn, _, _, err := l.ReadMsgUnix(buf, oob)
	if err != nil || string(buf[:n]) != "FDSTORE=1\nFDNAME=sfc-test\n" {
		t.Fatalf("%q %v", buf[:n], err)
	}
	msgs, _ := unix.ParseSocketControlMessage(oob[:oobn])
	fds, err := unix.ParseUnixRights(&msgs[0])
	if err != nil || len(fds) != 1 {
		t.Fatal(fds, err)
	}
	unix.Close(fds[0])
	if err := Remove("sfc-test"); err != nil {
		t.Fatal(err)
	}
	n, _, _, _, _ = l.ReadMsgUnix(buf, oob)
	if !strings.HasPrefix(string(buf[:n]), "FDSTOREREMOVE=1\n") {
		t.Fatalf("%q", buf[:n])
	}
	if Store("bad:name", int(w.Fd())) == nil || Store("", 0) == nil {
		t.Fatal("bad names accepted")
	}
	t.Setenv("NOTIFY_SOCKET", "")
	if Available() || Store("x", int(w.Fd())) != ErrUnavailable {
		t.Fatal("stored without a socket")
	}
}
