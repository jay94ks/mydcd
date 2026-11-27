// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// ownedUID is a UID this test may hand a socket to: any UID as root,
// otherwise only our own.
func ownedUID() uint32 {
	if os.Geteuid() == 0 {
		return 10001
	}
	return uint32(os.Geteuid())
}

func TestUnixOwnedSocketAdmitsSameLoginAndClosesWithHost(t *testing.T) {
	server, client, peer, path := u0UnixPair(t)
	if err := server.OnManagement(User, func(ctx context.Context, s *Session, stream Stream, f Frame) error {
		f.Kind = 2
		return WriteFrame(stream, f)
	}); err != nil {
		t.Fatal(err)
	}
	// The client's pinned endpoint is path, so the cluster app socket takes it
	// and the host socket sits next to it.
	owned := path
	host := filepath.Join(filepath.Dir(path), "host.sock")
	if err := server.ListenUnixOwned(owned, 0); err == nil {
		t.Fatal("root-owned cluster app socket accepted")
	}
	if err := server.ListenUnix(host); err != nil {
		t.Fatal(err)
	}
	uid := ownedUID()
	if err := server.ListenUnixOwned(owned, uid); err != nil {
		t.Fatal(err)
	}
	if err := server.ListenUnixOwned(owned, uid); err == nil {
		t.Fatal("same socket path opened twice")
	}
	if err := server.ListenUnix(filepath.Join(filepath.Dir(path), "other.sock")); err == nil {
		t.Fatal("second host socket opened")
	}
	info, err := os.Lstat(owned)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uid {
		t.Fatal("owned socket file", info, err)
	}
	if got := server.ManagementAddr(); got == nil || got.String() != host {
		t.Fatal("management address is not the host socket", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	s, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := s.OpenManagement(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := u0UserFrame(2, []byte("login"))
	if err = WriteFrame(stream, f); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	reply, err := ReadFrame(stream, MaxBody)
	if err != nil || reply.Request != f.Request || !bytes.Equal(reply.Fields[0].Value, []byte("login")) {
		t.Fatal("login over cluster app socket", err)
	}
	if err = server.CloseUnix(); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{host, owned} {
		if _, err = os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("socket remained after CloseUnix", p, err)
		}
	}
}

func TestUnixOwnedSocketReplacesItsOwnersStaleSocket(t *testing.T) {
	server, _, _, path := u0UnixPair(t)
	crashed, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	crashed.SetUnlinkOnClose(false)
	if err = crashed.Close(); err != nil {
		t.Fatal(err)
	}
	uid := ownedUID()
	if err = os.Lchown(path, int(uid), -1); err != nil {
		t.Fatal(err)
	}
	if err = server.ListenUnixOwned(path, uid); err != nil {
		t.Fatal("owner's stale socket blocked startup", err)
	}
	if err = server.Close(); err != nil {
		t.Fatal(err)
	}
}
