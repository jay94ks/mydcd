// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/identity"
)

func TestCheckerArtifactActualQUICStoreBeforeReceiptAndLostFinalAck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	peers := map[Identity]Peer{Identity(a.Public): {ID: "consumer", Policy: Policy{Key: Identity(a.Public), Member: true, Respond: true}}, Identity(b.Public): {ID: "provider", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}}}
	lookup := func(k Identity) (Peer, bool) { p, ok := peers[k]; return p, ok }
	server, err := NewTransport(b, [32]byte{91}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	data := append([]byte("package checker\n"), bytes.Repeat([]byte("// original exact source\n"), 8000)...)
	digest := sha256.Sum256(data)
	var allowed atomic.Bool
	allowed.Store(true)
	var reads atomic.Int32
	if err := server.OnCheckerArtifact(func(_ context.Context, _ *Session, q CheckerArtifactRequest) (CheckerArtifactSource, error) {
		if q.Digest != digest || q.Bytes != uint64(len(data)) || !bytes.Equal(q.Metadata, []byte("fixed accepted use")) {
			return CheckerArtifactSource{}, ErrAdmission
		}
		return CheckerArtifactSource{Data: bytes.Clone(data), Metadata: []byte("signed exact provider metadata"), Authorize: func(context.Context) error {
			reads.Add(1)
			if !allowed.Load() {
				return ErrAdmission
			}
			return nil
		}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(a, [32]byte{91}, lookup)
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
	q := CheckerArtifactRequest{Schema: 1, Metadata: []byte("fixed accepted use"), Digest: digest, Bytes: uint64(len(data)), ExpiresAt: time.Now().Unix() + 12}
	// Actual borrowed bbolt cache at the receiver. The wire authority callback
	// is simulated here; Runtime's full parent/quorum contract is separate.
	db, err := storage.Open(filepath.Join(t.TempDir(), "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cache, err := checker.OpenSources(db, [32]byte{91}, a.Private)
	if err != nil {
		t.Fatal(err)
	}
	defer cache.Close()
	descriptor := checker.SourceDescriptor{Tenant: "tenant", SDK: 1, Digest: digest, Length: uint64(len(data))}
	policy := checker.TenantPolicy{Tenant: "tenant", Revision: 1, Enabled: true, Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 1000, NanoCPU: 1, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}}, Resolver: checker.ResolverPolicy{SourceCacheBytes: 1 << 20}}
	stored := 0
	sink := CheckerArtifactSink{Metadata: func(meta []byte) error {
		if !bytes.Equal(meta, []byte("signed exact provider metadata")) {
			return ErrAdmission
		}
		return nil
	}, Store: func(_ context.Context, body []byte) error {
		if !bytes.Equal(body, data) {
			return ErrFrame
		}
		if _, err := cache.Stage(ctx, descriptor, body, policy); err != nil {
			return err
		}
		stored++
		return nil
	}}
	if err := session.PullCheckerArtifact(ctx, q, sink); err != nil || stored != 1 || reads.Load() < 4 {
		t.Fatal("actual source/body/sync-before-ACK path", stored, err)
	}
	sink.Store = func(_ context.Context, body []byte) error {
		if !bytes.Equal(body, data) {
			return ErrFrame
		}
		if _, err := cache.Stage(ctx, descriptor, body, policy); err != nil {
			return err
		}
		stored++
		allowed.Store(false)
		return nil
	}
	if err := session.PullCheckerArtifact(ctx, q, sink); !errors.Is(err, ErrCheckerArtifactUncertain) || stored != 2 {
		t.Fatal("lost final authority/ACK erased stored outcome", stored, err)
	}
	if recovered, err := cache.Recover(ctx, descriptor); err != nil || recovered.Verify() != nil {
		t.Fatal("lost network receipt erased actual synced cache", err)
	}
	// A rejected request before end-of-body must never call Store or retry it.
	if err := session.PullCheckerArtifact(ctx, q, sink); err == nil || stored != 2 {
		t.Fatal("revoked source still stored/retried", stored, err)
	}
}

func TestCheckerArtifactPurposeRequiresCurrentMemberAndBoundedFrames(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := Identity(pub)
	cluster, challenge := [32]byte{92}, [32]byte{93}
	gate, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.Authenticate(Binding{Key: id, TLSKey: id, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(id, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	f := Frame{Purpose: CheckerArtifact, Kind: 3, Request: 1, Fields: []Field{{1, true, make([]byte, 8)}, {2, true, make([]byte, checkerArtifactChunk)}, {3, true, make([]byte, 32)}}}
	if _, err := Encode(f); err != nil {
		t.Fatal(err)
	}
	if err := gate.Admit(f, Policy{Key: id, Member: true}, false, false); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []Policy{{Key: id, Replicate: true}, {Key: id, UserAuth: true, Respond: true}, {Key: id, Read: true, Manage: true, Respond: true}} {
		if err := gate.Admit(f, policy, false, false); err == nil {
			t.Fatal("non-member reached checker source")
		}
	}
	if gate.Admit(f, Policy{Key: id, Member: true}, true, false) == nil || gate.Admit(f, Policy{Key: id, Member: true}, false, true) == nil {
		t.Fatal("early/datagram checker data accepted")
	}
	f.Fields[1].Value = append(f.Fields[1].Value, 0)
	if _, err := Encode(f); err == nil {
		t.Fatal("oversized checker chunk encoded")
	}
}
