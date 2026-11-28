// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"crypto/ed25519"
	"testing"
)

// Under a share record a consumer may run on another server. single-writer
// keeps one writer (local and remote together) beside readers; shared lets
// writers in together. The remote consumer's Gone is signed by its runner,
// and the Volume keeps the pin (blocking delete) until that Gone arrives.
func TestSharedVolumeConsumers(t *testing.T) {
	f := makeFixture(t)
	runner := Owner{Node: "node-b", Key: public(f.b)}
	home := Owner{Node: "node-a", Key: public(f.a)}
	shared := func(id string, gen uint64, writable bool, mode string, at Owner) (Consumer, error) {
		s, p, err := f.s.AcquireShared(f.c, "admin", f.s.Revision(), id, gen, writable, mode, at)
		if err == nil {
			f.s = s
			if _, err := Decode(mustEncode(t, s)); err != nil {
				t.Fatal("state with shared consumers does not decode", err)
			}
		}
		return p, err
	}

	w, err := shared("writer", 1, true, ShareSingleWriter, home)
	if err != nil || w.Remote() {
		t.Fatal("local writer", err)
	}
	r, err := shared("reader", 1, false, ShareSingleWriter, runner)
	if err != nil || !r.Remote() || r.Runner != "node-b" || r.Owner != f.source {
		t.Fatalf("remote reader %+v %v", r, err)
	}
	if _, err := shared("second-writer", 1, true, ShareSingleWriter, runner); err == nil {
		t.Fatal("single-writer took a second (remote) writer")
	}
	if _, err := shared("bad-runner", 1, false, ShareSingleWriter, Owner{Node: "node-a", Key: public(f.b)}); err == nil {
		t.Fatal("owner node with another key accepted")
	}
	if _, err := shared("no-mode", 1, false, "", runner); err == nil {
		t.Fatal("remote consumer without a share mode")
	}
	if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "plain", 1, false); err == nil {
		t.Fatal("plain Acquire ignored the existing writer")
	}
	if _, err := shared("shared-writer", 1, true, ShareShared, runner); err != nil {
		t.Fatal("shared mode refused a second writer", err)
	}

	// Gone: the runner signs a remote consumer's, never the owner.
	sign := func(p Consumer, k ed25519.PrivateKey) Gone {
		g := Gone{Scope: f.s.Scope(), Consumer: p, Stopped: true, MountsGone: true}
		g.Signature = ed25519.Sign(k, GoneBytes(g))
		return g
	}
	if _, err := f.s.Release(sign(r, f.a)); err == nil {
		t.Fatal("owner-signed Gone released a remote consumer")
	}
	if _, err := f.s.BeginDelete(f.c, "admin", f.s.Revision()); err == nil {
		t.Fatal("delete went ahead with a remote pin left")
	}
	s, err := f.s.Release(sign(r, f.b))
	if err != nil {
		t.Fatal("runner-signed Gone refused", err)
	}
	f.s = s
	forged := r
	forged.Runner = "node-a"
	if _, ok := forged.GoneKey(); ok {
		t.Fatal("runner equal to owner accepted")
	}
}

func mustEncode(t *testing.T, s State) []byte {
	t.Helper()
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A remote consumer whose runner is gone for good is released by the home's
// fence, signed by the Volume owner; a local consumer never is, and the
// freed writer slot takes a new writer.
func TestRemoteFenceReleasesTheConsumer(t *testing.T) {
	f := makeFixture(t)
	runner := Owner{Node: "node-b", Key: public(f.b)}
	home := Owner{Node: "node-a", Key: public(f.a)}
	acquire := func(id string, at Owner) Consumer {
		s, p, err := f.s.AcquireShared(f.c, "admin", f.s.Revision(), id, 1, true, ShareSingleWriter, at)
		if err != nil {
			t.Fatal(id, err)
		}
		f.s = s
		return p
	}
	w := acquire("writer", runner)
	fence := func(c Consumer, k ed25519.PrivateKey) RemoteFence {
		x := RemoteFence{Schema: 1, Scope: f.s.Scope(), Consumer: c}
		x.Signature = ed25519.Sign(k, RemoteFenceBytes(x))
		return x
	}
	if _, err := f.s.ReleaseFenced(fence(w, f.b)); err == nil {
		t.Fatal("runner-signed fence accepted")
	}
	bad := fence(w, f.a)
	bad.Schema = 2
	if _, err := f.s.ReleaseFenced(bad); err == nil {
		t.Fatal("unknown schema accepted")
	}
	if _, _, err := f.s.AcquireShared(f.c, "admin", f.s.Revision(), "next", 1, true, ShareSingleWriter, home); err == nil {
		t.Fatal("second writer before the fence")
	}
	s, err := f.s.ReleaseFenced(fence(w, f.a))
	if err != nil || len(s.Consumers()) != 0 {
		t.Fatal("owner fence refused", err)
	}
	if _, err := s.ReleaseFenced(fence(w, f.a)); err == nil {
		t.Fatal("fenced twice")
	}
	f.s = s
	local := acquire("next", home)
	if _, err := f.s.ReleaseFenced(fence(local, f.a)); err == nil {
		t.Fatal("fence released a local consumer")
	}
}
