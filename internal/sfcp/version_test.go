// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/buildinfo"
	"github.com/jay94ks/seafield/internal/identity"
)

func TestHelloVersion(t *testing.T) {
	for _, c := range []struct {
		value, want string
	}{
		{"0.1.3", "0.1.3"},
		{"0.1.0-dev", "0.1.0-dev"},
		{"", ""},
		{"0.1.3\n", ""},
		{"0.1.3 ", ""},
		{string(make([]byte, maxVersion+1)), ""},
	} {
		if got := helloVersion(Frame{Fields: []Field{versionField(c.value)}}); got != c.want {
			t.Errorf("%q: %q", c.value, got)
		}
	}
	if helloVersion(Frame{}) != "" {
		t.Fatal("missing extension")
	}
	for _, c := range []struct {
		v     string
		major int
		ok    bool
	}{{"0.1.3", 0, true}, {"12.0.0-dev", 12, true}, {"01.0.0", 0, false}, {"x.1.0", 0, false}, {"1", 0, false}, {".1", 0, false}} {
		if m, ok := versionMajor(c.v); m != c.major || ok != c.ok {
			t.Errorf("%q: %d %v", c.v, m, ok)
		}
	}
	if m, ok := versionMajor(buildinfo.Version()); !ok || m != buildinfo.Major {
		t.Fatal("own version", buildinfo.Version())
	}
}

// A peer of another major is refused on both ends after the handshake; one
// of the same major with another build connects and its version is kept on
// the session; a peer that announces no version is not checked.
func TestHandshakeRefusesAnotherMajor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[Identity]Peer{Identity(a.Public): {ID: "sender", Policy: Policy{Key: Identity(a.Public), Member: true, Report: true}}, Identity(b.Public): {ID: "receiver", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}}}
	var mu sync.RWMutex
	lookup := func(key Identity) (Peer, bool) { mu.RLock(); defer mu.RUnlock(); p, ok := peers[key]; return p, ok }
	receiver, err := NewTransport(b, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiver.version = "0.1.4"
	if err = receiver.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	target := peers[Identity(b.Public)]
	target.Endpoint = receiver.Addr().String()
	peers[target.Key] = target
	mu.Unlock()
	dial := func(version string) (*Session, error) {
		sender, err := NewTransport(a, [32]byte{1}, lookup)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sender.Close() })
		sender.version = version
		return sender.Dial(ctx, target)
	}

	if _, err := dial("1.0.0"); !errors.Is(err, ErrMajor) {
		t.Fatal("another major connected", err)
	}
	if _, live := receiver.PeerFeatures(Identity(a.Public)); live {
		t.Fatal("receiver kept a session to another major")
	}
	s, err := dial("0.1.7")
	if err != nil || s.PeerVersion() != "0.1.4" {
		t.Fatal("same major", err)
	}
	waitFor(t, func() bool { _, live := receiver.PeerFeatures(Identity(a.Public)); return live })
	if s, err := dial(""); err != nil || s.PeerVersion() != "0.1.4" {
		t.Fatal("no version announced", err)
	}
}
