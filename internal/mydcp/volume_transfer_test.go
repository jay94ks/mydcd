// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
)

type volumeWireSink struct {
	data     []byte
	failAt   int
	calls    int
	expected [32]byte
	finished bool
}

func (w *volumeWireSink) WriteChunk(ctx context.Context, offset uint64, data []byte) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	w.calls++
	if w.failAt == w.calls {
		return 0, errors.New("receiver sync outcome not acknowledged")
	}
	if offset != uint64(len(w.data)) {
		return 0, ErrFrame
	}
	w.data = append(w.data, data...)
	return uint64(len(w.data)), nil
}
func (w *volumeWireSink) Finish(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if sha256.Sum256(w.data) != w.expected {
		return ErrFrame
	}
	w.finished = true
	return nil
}
func TestVolumeTransferWireOriginalOffsetResumeAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(a.Private)
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(b.Private)
	peers := map[Identity]Peer{Identity(a.Public): {ID: "a", Policy: Policy{Key: Identity(a.Public), Member: true, Respond: true}}, Identity(b.Public): {ID: "b", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}}}
	lookup := func(k Identity) (Peer, bool) { p, ok := peers[k]; return p, ok }
	server, err := NewTransport(b, [32]byte{71}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	data := bytes.Repeat([]byte("bounded original artifact\x00"), 16384)
	// The wire scope uses512-byte aligned immutable bytes; archive/profile and
	// actual file/offset durability belong to the concrete receiver adapter.
	data = data[:len(data)/512*512]
	digest := sha256.Sum256(data)
	var authorized atomic.Bool
	authorized.Store(true)
	ended := make(chan error, 8)
	if err = server.OnVolumeTransfer(func(_ context.Context, _ *Session, r VolumeTransferRequest) (VolumeSource, error) {
		if r.Artifact != digest || r.Bytes != uint64(len(data)) || !bytes.Equal(r.Metadata, []byte("original-move")) {
			return VolumeSource{}, ErrAdmission
		}
		return VolumeSource{Authorize: func(context.Context) error {
			if !authorized.Load() {
				return ErrAdmission
			}
			return nil
		}, WithFile: func(_ context.Context, read func(io.ReadSeeker) error) error {
			err := read(bytes.NewReader(data))
			ended <- err
			return err
		}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(a, [32]byte{71}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	peer := peers[Identity(b.Public)]
	peer.Endpoint = server.Addr().String()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	r := VolumeTransferRequest{Schema: 1, Metadata: []byte("original-move"), Artifact: digest, Bytes: uint64(len(data)), Prefix: sha256.Sum256(nil), ExpiresAt: time.Now().Unix() + 8}
	sink := &volumeWireSink{failAt: 2, expected: digest}
	if err = session.PullVolume(ctx, r, sink); err == nil || len(sink.data) != VolumeChunkSize || sink.finished {
		t.Fatal("failed receiver sync was acknowledged", err, len(sink.data))
	}
	select {
	case err = <-ended:
		if err == nil {
			t.Fatal("source accepted incomplete ACK")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r.Offset = uint64(len(sink.data))
	r.Prefix = sha256.Sum256(sink.data)
	sink.failAt = 0
	if err = session.PullVolume(ctx, r, sink); err != nil || !sink.finished || !bytes.Equal(sink.data, data) {
		t.Fatal("original offset resume", err)
	}
	select {
	case err = <-ended:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// A wrong positive checkpoint cannot skip unseen source bytes.
	r.Offset = VolumeChunkSize
	r.Prefix = [32]byte{1}
	bad := &volumeWireSink{expected: digest}
	if err = session.PullVolume(ctx, r, bad); err == nil || bad.calls != 0 {
		t.Fatal("wrong checkpoint prefix accepted", err)
	}
	select {
	case err = <-ended:
		if err == nil {
			t.Fatal("source accepted wrong prefix")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	authorized.Store(false)
	r.Offset = 0
	r.Prefix = sha256.Sum256(nil)
	if err = session.PullVolume(ctx, r, bad); err == nil || bad.calls != 0 {
		t.Fatal("revoked source read accepted", err)
	}
	select {
	case err = <-ended:
		if err == nil {
			t.Fatal("revoked source completed")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestVolumeTransferPurposeIsBoundedCurrentMemberOnly(t *testing.T) {
	if volumePacing(16<<30) != 2048*time.Second || volumePacing(1<<40) != 131072*time.Second {
		t.Fatal("large original transfer pacing overflow")
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := Identity(pub)
	cluster, challenge := [32]byte{81}, [32]byte{82}
	g, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err = g.Authenticate(Binding{Key: id, TLSKey: id, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(id, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	f := Frame{Purpose: VolumeTransfer, Kind: 2, Request: 1, Fields: []Field{{1, true, make([]byte, 8)}, {2, true, make([]byte, VolumeChunkSize)}, {3, true, make([]byte, 32)}}}
	if _, err = Encode(f); err != nil {
		t.Fatal(err)
	}
	if err = g.Admit(f, Policy{Key: id, Member: true}, false, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Policy{{Key: id, Replicate: true}, {Key: id, Read: true, Respond: true}, {Key: id, Manage: true}, {Key: id, UserAuth: true}} {
		if g.Admit(f, p, false, false) == nil {
			t.Fatal("nonmember read permitted")
		}
	}
	if g.AdmitOn(Snapshot, f, Policy{Key: id, Member: true, Snapshot: true}, false, false) == nil || g.Admit(f, Policy{Key: id, Member: true}, false, true) == nil || g.Admit(f, Policy{Key: id, Member: true}, true, false) == nil {
		t.Fatal("purpose/early/datagram bypass")
	}
	f.Fields[1].Value = make([]byte, VolumeChunkSize+1)
	if _, err = Encode(f); err == nil {
		t.Fatal("oversized chunk admitted")
	}
}
