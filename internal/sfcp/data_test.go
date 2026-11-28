// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"context"
	"errors"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestRealBoundaryReportsDatagramsAndRevocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	b, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	peers := map[Identity]Peer{Identity(a.Public): {ID: "sender", Policy: Policy{Key: Identity(a.Public), Report: true, Tunnel: true}}, Identity(b.Public): {ID: "receiver", Policy: Policy{Key: Identity(b.Public), Respond: true}}}
	var mu sync.RWMutex
	lookup := func(key Identity) (Peer, bool) { mu.RLock(); defer mu.RUnlock(); p, ok := peers[key]; return p, ok }
	db, err := storage.Open(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	receiver, err := NewTransport(b, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = receiver.OnReport(func(_ context.Context, s *Session, kind uint8, payload []byte) error {
		if string(payload) == "refuse" {
			return errors.New("refused item")
		}
		return db.Write(map[string][]byte{s.Peer().ID: payload})
	}); err != nil {
		t.Fatal(err)
	}
	packets := make(chan Frame, 1)
	var rejection atomic.Int32
	if err = receiver.OnPacket(func(_ *Session, f Frame) error {
		switch rejection.Load() {
		case 1:
			return ErrBudget
		case 2:
			return ErrAdmission
		case 3:
			return errors.New("private handler detail must not be retained")
		}
		select {
		case packets <- f:
			return nil
		default:
			return errors.New("packet consumer full")
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err = receiver.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	target := peers[Identity(b.Public)]
	target.Endpoint = receiver.Addr().String()
	peers[target.Key] = target
	mu.Unlock()
	sender, err := NewTransport(a, [32]byte{1}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	session, err := sender.Dial(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("authenticated local observation")
	if err = session.Report(ctx, KindWorkloadReport, payload); err != nil {
		t.Fatal(err)
	}
	stored, err := db.Get("sender")
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatal("report ACK preceded owner storage", err)
	}
	// One frame of three items: the refused one is dropped alone.
	accepted, err := session.ReportBatch(ctx, KindEventBatch, [][]byte{[]byte("one"), []byte("refuse"), payload})
	if err != nil || len(accepted) != 3 || !accepted[0] || accepted[1] || !accepted[2] {
		t.Fatal("batch receipt", accepted, err)
	}
	if err = session.Report(ctx, KindWorkloadReport, []byte("refuse")); !errors.Is(err, ErrReportRefused) {
		t.Fatal("refused single report", err)
	}
	// Items that do not fit one frame go in the next.
	big := bytes.Repeat([]byte("x"), 40<<10)
	if accepted, err = session.ReportBatch(ctx, KindEventBatch, [][]byte{big, big, big}); err != nil || !accepted[0] || !accepted[1] || !accepted[2] {
		t.Fatal("split batch", accepted, err)
	}
	if err = session.Report(ctx, KindWorkloadReport, payload); err != nil {
		t.Fatal(err)
	}
	ip := []byte{0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0x66, 0xce, 10, 0, 0, 1, 10, 0, 0, 2, 0x12, 0x34, 0x56, 0x78, 0, 8, 0, 0}
	frame := Frame{Purpose: Packet, Kind: 1, Fields: []Field{{Tag: 1, Required: true, Value: a.Public[:]}, {Tag: 2, Required: true, Value: append([]byte{1}, make([]byte, 15)...)}, {Tag: 3, Required: true, Value: append([]byte{2}, make([]byte, 15)...)}, {Tag: 4, Required: true, Value: ip}}}
	for _, kind := range []uint8{1, 2} {
		frame.Kind = kind
		if err = session.SendPacket(ctx, frame); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-packets:
			if got.Kind != kind || !bytes.Equal(got.Fields[2].Value, frame.Fields[2].Value) || !bytes.Equal(got.Fields[3].Value, ip) {
				t.Fatal("DATAGRAM kind/identity/payload changed")
			}
		case <-ctx.Done():
			t.Fatal("real DATAGRAM not delivered")
		}
	}
	frame.Fields[3].Value = make([]byte, 65000)
	var tooLarge *quic.DatagramTooLargeError
	if err = session.SendPacket(ctx, frame); !errors.As(err, &tooLarge) {
		t.Fatal("native path DATAGRAM limit bypassed", err)
	}
	frame.Fields[3].Value = ip
	frame.Fields[0].Value = b.Public[:]
	if err = session.SendPacket(ctx, frame); !errors.Is(err, ErrAdmission) {
		t.Fatal("foreign packet owner accepted", err)
	}
	frame.Fields[0].Value = a.Public[:]
	for mode := int32(1); mode <= 3; mode++ {
		rejection.Store(mode)
		_, previous := receiver.PacketCounts()
		if err := session.SendPacket(ctx, frame); err != nil {
			t.Fatal(err)
		}
		for {
			_, drops := receiver.PacketCounts()
			if drops > previous {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("missing classified handler drop", ctx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	rejection.Store(0)
	if got := receiver.PacketDropCounts(); got.HandlerBudget != 1 || got.HandlerAdmission != 1 || got.HandlerOther != 1 || got.Admission != 0 {
		t.Fatal("handler drop reason conflated", got)
	}
	mu.Lock()
	revoked := peers[Identity(a.Public)]
	revoked.Report = false
	revoked.Tunnel = false
	peers[revoked.Key] = revoked
	mu.Unlock()
	if err = session.Report(ctx, KindWorkloadReport, []byte("must not replace")); err == nil {
		t.Fatal("current report permission not checked")
	}
	stored, err = db.Get("sender")
	if err != nil || !bytes.Equal(stored, payload) {
		t.Fatal("denied report changed owner storage", err)
	}
	_, before := receiver.PacketCounts()
	if err = session.SendPacket(ctx, frame); err != nil {
		t.Fatal(err)
	}
	for {
		delivered, dropped := receiver.PacketCounts()
		if dropped > before {
			if delivered != 2 {
				t.Fatal("revoked packet delivered", delivered)
			}
			if receiver.PacketDropCounts().Admission != 1 {
				t.Fatal("current grant revocation not classified")
			}
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("no observation of revoked DATAGRAM")
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Logf("current admitted DATAGRAM=%d; authenticated report sync/ACK; ordinary and route packets delivered and revoked packet dropped", tooLarge.MaxDatagramPayloadSize)
}
