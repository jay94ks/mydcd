// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/engineevents"
	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/pkg/sfcp/enginemux"
	"github.com/jay94ks/seafield/pkg/sfcp/wire"
	"github.com/moby/moby/api/types/events"
)

// fakeEngineCodec frames engine purposes from the engine's side of the socket.
var fakeEngineCodec = wire.Rules(func(_ wire.Purpose, kind uint8) (wire.Rule, bool) {
	if kind == 4 {
		return wire.Rule{Fields: []int{8, -1, 32}, Budget: 8 + 32 + sfcp.ChunkSize + 64}, true
	}
	return wire.Rule{Fields: []int{-1}, Budget: 8 + 128<<10}, true
})

func fakeEngineFrame(t *testing.T, st *enginemux.Stream, p sfcp.Purpose, kind uint8, v any) wire.Frame {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return wire.Frame{Purpose: p, Kind: kind, Request: st.ID(), Fields: []wire.Field{{Tag: 1, Required: true, Value: raw}}}
}

type mountQ struct {
	engineops.Request
	Name string
}

type mountA struct {
	engineops.Reply
	ReadOnly bool
}

// A Seafield engine connects to sfcd's engine socket: sfcd subscribes to its
// events from the saved cursor, a stopped container of this node wakes a
// reconciliation pass, and an engine request gets its answer with a
// descriptor (R18 E1, E5).
func TestEngineSessionSubscribesAndAnswers(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the engine socket admits only uid 0")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	self, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr, err := sfcp.NewTransport(self, [32]byte{3}, func(sfcp.Identity) (sfcp.Peer, bool) { return sfcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil || tr.AllowEnginePeer(exe) != nil {
		t.Fatal("allow test engine", err)
	}
	dir := t.TempDir()
	mounted, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	exported := bytes.Repeat([]byte("seafield"), sfcp.ChunkSize/4) // two full chunks
	exported = append(exported, "tail"...)
	table, err := engineops.NewTable(engineops.Op(engineops.Volume, "mount", func(_ context.Context, q mountQ) (mountA, []*os.File, error) {
		return mountA{ReadOnly: q.Name == "ro"}, []*os.File{mounted}, nil
	}), engineops.StreamOp(engineops.Image, "export", func(_ context.Context, q mountQ) (mountA, io.ReadCloser, error) {
		return mountA{}, io.NopCloser(bytes.NewReader(exported)), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Mesh: tr, ctx: ctx, owner: "node-a", moduleWake: make(chan struct{}, 1)}
	socket := filepath.Join(dir, "sfcd.sock")
	if err = r.listenEngine(socket, table); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	engine := enginemux.Client(c)
	defer engine.Close()

	// sfcd opens the subscription.
	st, err := engine.Accept()
	if err != nil {
		t.Fatal(err)
	}
	f, err := fakeEngineCodec.ReadFrame(st, 64<<10)
	if err != nil || f.Purpose != sfcp.EngineEvents || f.Kind != 1 {
		t.Fatalf("subscribe frame %+v %v", f, err)
	}
	var sub engineevents.Subscribe
	if err = json.Unmarshal(f.Fields[0].Value, &sub); err != nil || sub.Op != "subscribe" || sub.After != 0 {
		t.Fatalf("subscribe %+v %v", sub, err)
	}
	if err = fakeEngineCodec.WriteFrame(st, fakeEngineFrame(t, st, sfcp.EngineEvents, 2, engineevents.Subscribed{Reply: engineops.Reply{Schema: 1, OpID: sub.OpID, Result: engineops.Applied}, Boot: "b1"})); err != nil {
		t.Fatal(err)
	}
	waitWake := func(what string) {
		t.Helper()
		select {
		case <-r.moduleWake:
		case <-ctx.Done():
			t.Fatalf("%s did not wake a pass", what)
		}
	}
	waitWake("a new engine boot")
	die := events.Message{Type: events.ContainerEventType, Action: events.ActionDie, Actor: events.Actor{ID: "c1", Attributes: map[string]string{"org.sfc.owner": "node-a"}}}
	if err = fakeEngineCodec.WriteFrame(st, fakeEngineFrame(t, st, sfcp.EngineEvents, 16, engineevents.Batch{Boot: "b1", Records: []engineevents.Record{{Seq: 1, Boot: "b1", Event: die}}})); err != nil {
		t.Fatal(err)
	}
	waitWake("a dead container")
	deadline := time.Now().Add(5 * time.Second)
	for r.engineEvents.After() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.engineEvents.After() != 1 {
		t.Fatal("cursor did not move to the applied event")
	}

	// The engine asks a volume op and gets a descriptor.
	q, err := engine.Open()
	if err != nil {
		t.Fatal(err)
	}
	req := mountQ{Request: engineops.Request{Schema: 1, Op: "mount", OpID: "op7", BootID: "boot1"}, Name: "ro"}
	if err = fakeEngineCodec.WriteFrame(q, fakeEngineFrame(t, q, sfcp.EngineVolume, 1, req)); err != nil {
		t.Fatal(err)
	}
	f, err = fakeEngineCodec.ReadFrame(q, 128<<10)
	if err != nil || f.Kind != 2 {
		t.Fatalf("mount answer %+v %v", f, err)
	}
	var a mountA
	if err = json.Unmarshal(f.Fields[0].Value, &a); err != nil || a.Result != engineops.Applied || !a.ReadOnly || len(a.Fds) != 1 {
		t.Fatalf("mount answer %s %v", f.Fields[0].Value, err)
	}
	fds := q.TakeFDs()
	if len(fds) != 1 {
		t.Fatalf("descriptors %v", fds)
	}
	var got, want syscall.Stat_t
	if syscall.Fstat(fds[0], &got) != nil || syscall.Stat(dir, &want) != nil || got.Ino != want.Ino {
		t.Fatal("descriptor is not the mounted directory")
	}
	_ = syscall.Close(fds[0])

	// An image op answers first, then streams kind 4 chunks on the engine
	// codec: offsets from 0, the request digest as header, then FIN.
	x, err := engine.Open()
	if err != nil {
		t.Fatal(err)
	}
	ask := fakeEngineFrame(t, x, sfcp.EngineImage, 1, mountQ{Request: engineops.Request{Schema: 1, Op: "export", OpID: "op8", BootID: "boot1"}})
	if err = fakeEngineCodec.WriteFrame(x, ask); err != nil {
		t.Fatal(err)
	}
	if f, err = fakeEngineCodec.ReadFrame(x, 128<<10); err != nil || f.Kind != 2 {
		t.Fatalf("export answer %+v %v", f, err)
	}
	header := sha256.Sum256(ask.Fields[0].Value)
	var streamed []byte
	for {
		f, err = fakeEngineCodec.ReadFrame(x, 128<<10)
		if err == io.EOF {
			break
		}
		if err != nil || f.Kind != 4 || binary.LittleEndian.Uint64(f.Fields[0].Value) != uint64(len(streamed)) || !bytes.Equal(f.Fields[2].Value, header[:]) || len(f.Fields[1].Value) > sfcp.ChunkSize {
			t.Fatalf("export chunk %+v %v", f, err)
		}
		streamed = append(streamed, f.Fields[1].Value...)
	}
	if !bytes.Equal(streamed, exported) {
		t.Fatal("streamed bytes differ", len(streamed), len(exported))
	}
}
