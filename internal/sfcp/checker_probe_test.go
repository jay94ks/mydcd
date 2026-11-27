// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
)

// Real member QUIC and private DB below; the provider's native/quorum callback
// is simulated. These tests do not prove Runtime's durable effect ownership.
func checkerProbeWirePair(t *testing.T, register func(*Transport) error) (*Session, *Transport) {
	t.Helper()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(a.Private); clear(b.Private) })
	peers := map[Identity]Peer{
		Identity(a.Public): {ID: "consumer", Policy: Policy{Key: Identity(a.Public), Member: true, Respond: true}},
		Identity(b.Public): {ID: "provider", Policy: Policy{Key: Identity(b.Public), Member: true, Respond: true}},
	}
	lookup := func(key Identity) (Peer, bool) { p, ok := peers[key]; return p, ok }
	server, err := NewTransport(b, [32]byte{94}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if err = register(server); err != nil {
		t.Fatal(err)
	}
	if cap(server.limits[CheckerProbe]) != 2 {
		t.Fatal("missing finite checker call slots")
	}
	if err = server.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	client, err := NewTransport(a, [32]byte{94}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	peer := peers[Identity(b.Public)]
	peer.Endpoint = server.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := client.Dial(ctx, peer)
	if err != nil {
		t.Fatal(err)
	}
	return session, server
}

func checkerProbeWireRequest(payload []byte) CheckerProbeRequest {
	return CheckerProbeRequest{Schema: 1, Action: "run", Metadata: []byte("original accepted Task/run/call"), Digest: sha256.Sum256(payload), Bytes: uint32(len(payload)), ExpiresAt: time.Now().Add(10 * time.Second).UnixMilli()}
}

func TestCheckerProbeActualQUICClosureBeforeAckAndOriginalRecovery(t *testing.T) {
	payload := bytes.Repeat([]byte("private typed argument "), 5000)
	response := bytes.Repeat([]byte("private bounded response "), 14000)
	var effects atomic.Int32
	session, _ := checkerProbeWirePair(t, func(server *Transport) error {
		return server.OnCheckerProbe(func(_ context.Context, _ *Session, q CheckerProbeRequest) (CheckerProbeHandler, error) {
			if q.Digest != sha256.Sum256(payload) || !bytes.Equal(q.Metadata, []byte("original accepted Task/run/call")) && !bytes.Equal(q.Metadata, []byte("first successful call")) {
				return CheckerProbeHandler{}, ErrAdmission
			}
			return CheckerProbeHandler{Execute: func(_ context.Context, body []byte) (CheckerProbeResult, error) {
				if q.Action == "recover" {
					if len(body) != 0 {
						return CheckerProbeResult{}, ErrFrame
					}
					return CheckerProbeResult{Closed: true}, nil
				}
				if !bytes.Equal(body, payload) {
					return CheckerProbeResult{}, ErrFrame
				}
				effects.Add(1)
				return CheckerProbeResult{Closed: true, Data: bytes.Clone(response)}, nil
			}}, nil
		})
	})
	path := filepath.Join(t.TempDir(), "observations.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	var stores int
	store := func(_ context.Context, closed bool, data []byte) error {
		if !closed || !bytes.Equal(data, response) {
			return ErrFrame
		}
		stores++
		digest := sha256.Sum256(data)
		return db.Write(map[string][]byte{"checker/test-closure": digest[:]})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	q := checkerProbeWireRequest(payload)
	q.Metadata = []byte("first successful call")
	result, err := session.CallCheckerProbe(ctx, q, payload, store)
	if err != nil || !result.Closed || !bytes.Equal(result.Data, response) || stores != 1 || effects.Load() != 1 {
		t.Fatal("finite body/closure/ACK", err, stores, effects.Load())
	}
	clear(result.Data)
	// Cancellation AFTER synchronous storage loses the final ACK. The wire
	// returns no private result and never retries the effect or Store callback.
	lost, stop := context.WithCancel(ctx)
	q.Metadata = []byte("original accepted Task/run/call")
	result, err = session.CallCheckerProbe(lost, q, payload, func(ctx context.Context, closed bool, data []byte) error {
		if err := store(ctx, closed, data); err != nil {
			return err
		}
		stop()
		return nil
	})
	if !errors.Is(err, ErrCheckerProbeUncertain) || result.Data != nil || stores != 2 || effects.Load() != 2 {
		t.Fatal("lost final ACK retried/erased uncertainty", err, stores, effects.Load())
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	db, err = storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(response)
	stored, err := db.GetBounded("checker/test-closure", 32)
	if err != nil || !bytes.Equal(stored, want[:]) {
		t.Fatal("closure not durable before ACK", err)
	}
	// Recovery sends NO body but keeps the ORIGINAL payload digest. It cannot
	// use SHA256(empty) as a replacement identity or require a fresh run ID.
	q.Action = "recover"
	q.Bytes = 0
	q.ExpiresAt = time.Now().Add(5 * time.Second).UnixMilli()
	recovered := 0
	result, err = session.CallCheckerProbe(ctx, q, nil, func(_ context.Context, closed bool, data []byte) error {
		if !closed || len(data) != 0 {
			return ErrFrame
		}
		recovered++
		return nil
	})
	if err != nil || !result.Closed || len(result.Data) != 0 || recovered != 1 || effects.Load() != 2 {
		t.Fatal("original closure lookup became new native call", err, recovered, effects.Load())
	}
}

func TestCheckerProbeStoreFailureAndPendingDoNotFabricateClosure(t *testing.T) {
	var effects atomic.Int32
	session, _ := checkerProbeWirePair(t, func(server *Transport) error {
		return server.OnCheckerProbe(func(_ context.Context, _ *Session, q CheckerProbeRequest) (CheckerProbeHandler, error) {
			return CheckerProbeHandler{Execute: func(context.Context, []byte) (CheckerProbeResult, error) {
				if q.Action == "run" {
					effects.Add(1)
					return CheckerProbeResult{Closed: true, Data: []byte("private result")}, nil
				}
				return CheckerProbeResult{Closed: false}, nil
			}}, nil
		})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	q := checkerProbeWireRequest([]byte("arg"))
	failed := errors.New("synchronous closure save failed")
	stores := 0
	result, err := session.CallCheckerProbe(ctx, q, []byte("arg"), func(context.Context, bool, []byte) error { stores++; return failed })
	if !errors.Is(err, ErrCheckerProbeUncertain) || !errors.Is(err, failed) || stores != 1 || effects.Load() != 1 || result.Data != nil {
		t.Fatal("failed storage became receipt/retry", err, stores, effects.Load())
	}
	q.Action = "recover"
	q.Bytes = 0
	result, err = session.CallCheckerProbe(ctx, q, nil, func(_ context.Context, closed bool, data []byte) error {
		if closed || len(data) != 0 {
			return ErrFrame
		}
		return nil
	})
	if err != nil || result.Closed || len(result.Data) != 0 || effects.Load() != 1 {
		t.Fatal("pending became closed/new run", err, effects.Load())
	}
}

func TestCheckerProbeRejectsTamperedBodiesBeforeExecute(t *testing.T) {
	var executions atomic.Int32
	session, _ := checkerProbeWirePair(t, func(server *Transport) error {
		return server.OnCheckerProbe(func(context.Context, *Session, CheckerProbeRequest) (CheckerProbeHandler, error) {
			return CheckerProbeHandler{Execute: func(context.Context, []byte) (CheckerProbeResult, error) {
				executions.Add(1)
				return CheckerProbeResult{Closed: true}, nil
			}}, nil
		})
	})
	for _, change := range []string{"offset", "header-binding", "payload-hash", "early-end"} {
		t.Run(change, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			payload := []byte("original payload")
			q := checkerProbeWireRequest(payload)
			raw, _ := json.Marshal(q)
			binding := sha256.Sum256(raw)
			id := session.transport.NextRequest()
			stream, err := session.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			defer stream.CancelRead(0)
			if err = checkerProbeWrite(ctx, session, stream, Frame{Purpose: CheckerProbe, Kind: 1, Request: id, Fields: []Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: binding[:]}}}); err != nil {
				t.Fatal(err)
			}
			if change != "early-end" {
				var index [8]byte
				partBinding := binding
				if change == "offset" {
					binary.LittleEndian.PutUint64(index[:], 1)
				}
				if change == "header-binding" {
					partBinding[0] ^= 1
				}
				if change == "payload-hash" {
					payload[0] ^= 1
				}
				err = checkerProbeWrite(ctx, session, stream, Frame{Purpose: CheckerProbe, Kind: KindChunk, Request: id, Fields: []Field{{Tag: 1, Required: true, Value: index[:]}, {Tag: 2, Required: true, Value: payload}, {Tag: 3, Required: true, Value: partBinding[:]}}})
				if err != nil {
					t.Fatal(err)
				}
			}
			// The server may reject the chunk before this marker is written.
			_ = checkerProbeWrite(ctx, session, stream, checkerProbeMarker(KindEnd, id, q.Digest, binding))
			if _, err = checkerProbeRead(ctx, session, stream, id); err == nil {
				t.Fatal("tampered request got a response")
			}
			if executions.Load() != 0 {
				t.Fatal("tampered payload reached native callback")
			}
		})
	}
}

func TestCheckerProbeAdmissionAndEnvelopeBounds(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	id := Identity(pub)
	cluster, challenge := [32]byte{95}, [32]byte{96}
	gate, err := NewGate(cluster, challenge)
	if err != nil {
		t.Fatal(err)
	}
	if err = gate.Authenticate(Binding{Key: id, TLSKey: id, Cluster: cluster, Challenge: challenge, Signature: ed25519.Sign(key, ProofBytes(id, cluster, challenge))}, true); err != nil {
		t.Fatal(err)
	}
	frame := Frame{Purpose: CheckerProbe, Kind: KindChunk, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: make([]byte, 8)}, {Tag: 2, Required: true, Value: make([]byte, checkerProbeChunk)}, {Tag: 3, Required: true, Value: make([]byte, 32)}}}
	if _, err = Encode(frame); err != nil {
		t.Fatal(err)
	}
	if err = gate.Admit(frame, Policy{Key: id, Member: true}, false, false); err != nil {
		t.Fatal(err)
	}
	for _, policy := range []Policy{{Key: id, Replicate: true}, {Key: id, Read: true, Manage: true, Respond: true}, {Key: id, UserAuth: true, Respond: true}} {
		if gate.Admit(frame, policy, false, false) == nil {
			t.Fatal("nonmember reached native checker stream")
		}
	}
	if gate.Admit(frame, Policy{Key: id, Member: true}, true, false) == nil || gate.Admit(frame, Policy{Key: id, Member: true}, false, true) == nil || localPurpose(CheckerProbe) {
		t.Fatal("early/datagram/Unix probe allowed")
	}
	frame.Fields[1].Value = append(frame.Fields[1].Value, 0)
	if _, err = Encode(frame); err == nil {
		t.Fatal("oversized chunk encoded")
	}
	q := checkerProbeWireRequest([]byte("arg"))
	for _, change := range []func(*CheckerProbeRequest){
		func(q *CheckerProbeRequest) { q.Schema = 2 }, func(q *CheckerProbeRequest) { q.Action = "retry" },
		func(q *CheckerProbeRequest) { q.Bytes = 0 }, func(q *CheckerProbeRequest) { q.Bytes = CheckerProbeMaxBytes + 1 },
		func(q *CheckerProbeRequest) { q.Action = "recover" }, func(q *CheckerProbeRequest) { q.Metadata = nil },
		func(q *CheckerProbeRequest) { q.Metadata = make([]byte, (68<<10)+1) }, func(q *CheckerProbeRequest) { q.Digest = [32]byte{} },
	} {
		candidate := q
		change(&candidate)
		if candidate.valid() {
			t.Fatal("invalid envelope admitted")
		}
	}
	// Even the largest allowed metadata is below the EXISTING frame budget
	// after JSON base64 and envelope overhead. No Management cap is raised.
	q.Metadata = make([]byte, 68<<10)
	raw, _ := json.Marshal(q)
	binding := sha256.Sum256(raw)
	if _, err = Encode(Frame{Purpose: CheckerProbe, Kind: 1, Request: 1, Fields: []Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: binding[:]}}}); err != nil {
		t.Fatal("compact metadata exceeds header", err)
	}
	if MaxBody != 256<<10 {
		t.Fatal("general wire body budget changed")
	}
}
