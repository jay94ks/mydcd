// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/sfcp"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	raft "github.com/hashicorp/raft"
	quic "github.com/quic-go/quic-go"
)

type rpcEnvelope struct {
	Schema uint8
	Type   uint8
	Body   json.RawMessage
	Error  string
}
type PeerResolver func(raft.ServerID, raft.ServerAddress) (sfcp.Peer, bool)
type raftTransport struct {
	replication                        map[string]ReplicationObservation
	acks                               map[raft.ServerID]appendAck
	mesh                               *sfcp.Transport
	address                            raft.ServerAddress
	resolve                            PeerResolver
	consumer                           chan raft.RPC
	ctx                                context.Context
	cancel                             context.CancelFunc
	mu                                 sync.Mutex
	heartbeat                          func(raft.RPC)
	staging                            string
	incomingSnapshot, outgoingSnapshot chan struct{}
	active                             sync.WaitGroup
	closed                             bool
}

func newRaftTransport(mesh *sfcp.Transport, address raft.ServerAddress, resolve PeerResolver, staging string) (*raftTransport, error) {
	if err := os.MkdirAll(staging, 0700); err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(staging, ".sfc-snapshot-*"))
	if err != nil {
		return nil, err
	}
	for _, name := range files {
		if err = os.Remove(name); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &raftTransport{mesh: mesh, address: address, resolve: resolve, consumer: make(chan raft.RPC, 32), ctx: ctx, cancel: cancel, staging: staging, incomingSnapshot: make(chan struct{}, 1), outgoingSnapshot: make(chan struct{}, 1)}
	if err := mesh.On(sfcp.Raft, t.incoming); err != nil {
		cancel()
		return nil, err
	}
	if err := mesh.On(sfcp.Snapshot, t.snapshot); err != nil {
		cancel()
		return nil, err
	}
	return t, nil
}
func (t *raftTransport) Consumer() <-chan raft.RPC     { return t.consumer }
func (t *raftTransport) LocalAddr() raft.ServerAddress { return t.address }
func (t *raftTransport) EncodePeer(_ raft.ServerID, addr raft.ServerAddress) []byte {
	return []byte(addr)
}
func (t *raftTransport) DecodePeer(b []byte) raft.ServerAddress { return raft.ServerAddress(b) }
func (t *raftTransport) SetHeartbeatHandler(cb func(raft.RPC)) {
	t.mu.Lock()
	t.heartbeat = cb
	t.mu.Unlock()
}
func (t *raftTransport) begin() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("Raft transport closed")
	}
	t.active.Add(1)
	return nil
}
func (t *raftTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.cancel()
	t.mu.Unlock()
	t.active.Wait()
	return nil
}
func (t *raftTransport) AppendEntriesPipeline(raft.ServerID, raft.ServerAddress) (raft.AppendPipeline, error) {
	return nil, raft.ErrPipelineReplicationNotSupported
}
func (t *raftTransport) AppendEntries(id raft.ServerID, addr raft.ServerAddress, a *raft.AppendEntriesRequest, r *raft.AppendEntriesResponse) error {
	started := time.Now()
	err := t.call(id, addr, 1, a, r)
	t.observeAppend(id, a, r, time.Since(started), err)
	if err == nil && r.Success && r.Term == a.Term {
		t.mu.Lock()
		if t.acks == nil {
			t.acks = map[raft.ServerID]appendAck{}
		}
		if old := t.acks[id]; a.Term > old.term || a.Term == old.term && started.After(old.sent) {
			t.acks[id] = appendAck{term: a.Term, sent: started}
		}
		t.mu.Unlock()
	}
	return err
}

// appendAck is the newest AppendEntries a follower accepted in a leader term,
// stamped with when the request was sent. The follower processed it after
// that time, so it vouches for leadership no earlier than sent.
type appendAck struct {
	term uint64
	sent time.Time
}

// ackedSince reports whether id accepted an AppendEntries of term that was
// sent at or after since.
func (t *raftTransport) ackedSince(id raft.ServerID, term uint64, since time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	a, ok := t.acks[id]
	return ok && a.term == term && !a.sent.Before(since)
}
func (t *raftTransport) RequestVote(id raft.ServerID, addr raft.ServerAddress, a *raft.RequestVoteRequest, r *raft.RequestVoteResponse) error {
	return t.call(id, addr, 2, a, r)
}
func (t *raftTransport) RequestPreVote(id raft.ServerID, addr raft.ServerAddress, a *raft.RequestPreVoteRequest, r *raft.RequestPreVoteResponse) error {
	return t.call(id, addr, 3, a, r)
}
func (t *raftTransport) TimeoutNow(id raft.ServerID, addr raft.ServerAddress, a *raft.TimeoutNowRequest, r *raft.TimeoutNowResponse) error {
	return t.call(id, addr, 4, a, r)
}
func rpcBytes(kind uint8, value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rpcEnvelope{Schema: 1, Type: kind, Body: body})
}
func parseRPC(b []byte) (rpcEnvelope, error) {
	var e rpcEnvelope
	err := json.Unmarshal(b, &e)
	if err == nil && (e.Schema != 1 || len(e.Body) == 0) {
		err = errors.New("invalid Raft payload schema")
	}
	return e, err
}
func rpcFrame(kind uint8, request uint64, b []byte) sfcp.Frame {
	return sfcp.Frame{Purpose: sfcp.Raft, Kind: kind, Request: request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: b}}}
}
func (t *raftTransport) call(id raft.ServerID, addr raft.ServerAddress, kind uint8, args, response any) error {
	// Preserve the first cause of a slow heartbeat: membership lookup and
	// stream work happen before the SDK can refresh its last-contact lease.
	// Log timings only, never RPC bodies, identities' private bytes or grants.
	var started time.Time
	var stages [5]time.Duration
	var request uint64
	if heartbeat, ok := args.(*raft.AppendEntriesRequest); ok && kind == 1 && len(heartbeat.Entries) == 0 && heartbeat.LeaderCommitIndex == 0 {
		started = time.Now()
		cpuStart := processCPUTime()
		defer func() {
			if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
				log.Printf("raft heartbeat slow: peer=%s request=%d elapsed=%s process_cpu=%s cumulative_resolve=%s dial=%s open=%s send=%s receive=%s", id, request, elapsed, processCPUUsed(cpuStart), stages[0], stages[1], stages[2], stages[3], stages[4])
			}
		}()
	}
	if err := t.begin(); err != nil {
		return err
	}
	defer t.active.Done()
	ctx, cancel := context.WithTimeout(t.ctx, 5*time.Second)
	defer cancel()
	peer, ok := t.resolve(id, addr)
	if !started.IsZero() {
		stages[0] = time.Since(started)
	}
	if !ok || !(peer.Member || peer.Replicate) {
		return sfcp.ErrAdmission
	}
	s, err := t.mesh.Dial(ctx, peer)
	if !started.IsZero() {
		stages[1] = time.Since(started)
	}
	if err != nil {
		return err
	}
	stream, err := s.Open(ctx)
	if !started.IsZero() {
		stages[2] = time.Since(started)
	}
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	b, err := rpcBytes(kind, args)
	if err != nil {
		return err
	}
	request = t.mesh.NextRequest()
	if err = sfcp.WriteFrame(stream, rpcFrame(sfcp.KindRequest, request, b)); err != nil {
		return err
	}
	if !started.IsZero() {
		stages[3] = time.Since(started)
	}
	f, err := sfcp.ReadFrame(stream, sfcp.MaxBody)
	if !started.IsZero() {
		stages[4] = time.Since(started)
	}
	if err != nil {
		return err
	}
	if f.Request != request || f.Purpose != sfcp.Raft || f.Kind != sfcp.KindResponse || s.Admit(f, sfcp.Raft, false) != nil {
		return sfcp.ErrAdmission
	}
	e, err := parseRPC(f.Fields[0].Value)
	if err != nil {
		return err
	}
	if e.Type != 0 || e.Error != "" {
		return fmt.Errorf("remote Raft RPC: %s", e.Error)
	}
	if err = json.Unmarshal(e.Body, response); err != nil {
		return err
	}
	h, ok := response.(interface{ GetRPCHeader() raft.RPCHeader })
	if !ok || !rpcResponseHeader(kind, h.GetRPCHeader(), peer.ID) {
		return sfcp.ErrAdmission
	}
	return nil
}

func rpcResponseHeader(kind uint8, header raft.RPCHeader, peer string) bool {
	if peer == "" {
		return false
	}
	if string(header.ID) == peer {
		return true
	}
	// HashiCorp Raft v1.8.0 timeoutNow intentionally responds with an empty
	// TimeoutNowResponse. Its ACK is already bound above to the authenticated
	// SFCP peer/session, purpose and exact request. No other empty/foreign
	// header is a valid Raft response.
	return kind == 4 && peer != "" && header.ProtocolVersion == 0 && len(header.ID) == 0 && len(header.Addr) == 0
}
func (t *raftTransport) deliver(ctx context.Context, command any, reader io.Reader) (raft.RPCResponse, error) {
	channel := make(chan raft.RPCResponse, 1)
	rpc := raft.RPC{Command: command, Reader: reader, RespChan: channel}
	fast := false
	if a, ok := command.(*raft.AppendEntriesRequest); ok && len(a.Entries) == 0 && a.LeaderCommitIndex == 0 {
		t.mu.Lock()
		cb := t.heartbeat
		t.mu.Unlock()
		if cb != nil {
			cb(rpc)
			fast = true
		}
	}
	if !fast {
		select {
		case t.consumer <- rpc:
		case <-ctx.Done():
			return raft.RPCResponse{}, ctx.Err()
		case <-t.ctx.Done():
			return raft.RPCResponse{}, t.ctx.Err()
		}
	}
	if reader != nil {
		// Once native owns the file, a remote timeout cannot close it underneath the
		// install. Close cancels this only after native background owners have exited.
		select {
		case result := <-channel:
			return result, nil
		case <-t.ctx.Done():
			return raft.RPCResponse{}, t.ctx.Err()
		}
	}

	select {
	case result := <-channel:
		return result, nil
	case <-ctx.Done():
		return raft.RPCResponse{}, ctx.Err()
	case <-t.ctx.Done():
		return raft.RPCResponse{}, t.ctx.Err()
	}
}

// A TLS session authenticates a key; its first peer display name can predate
// publication of the durable managed directory. Bind each RPC to the current
// resolver's exact ID/address/key, without reviving bootstrap seed authority.
// The resolver accepts only an address the directory names for that ID (its
// endpoint, or the new one of an endpoint change being installed), so the
// address is checked there: the returned peer carries the recorded endpoint.
func (t *raftTransport) requestPeer(header raft.RPCHeader, key sfcp.Identity) bool {
	peer, ok := t.resolve(raft.ServerID(header.ID), raft.ServerAddress(header.Addr))
	return ok && peer.Key == key && peer.ID == string(header.ID) && (peer.Member || peer.Replicate)
}

func (t *raftTransport) incoming(ctx context.Context, s *sfcp.Session, stream *quic.Stream, f sfcp.Frame) error {
	received := time.Now()
	if err := t.begin(); err != nil {
		return err
	}
	defer t.active.Done()
	if f.Kind != sfcp.KindRequest {
		return sfcp.ErrFrame
	}
	e, err := parseRPC(f.Fields[0].Value)
	if err != nil {
		return err
	}
	var command any
	switch e.Type {
	case 1:
		command = new(raft.AppendEntriesRequest)
	case 2:
		command = new(raft.RequestVoteRequest)
	case 3:
		command = new(raft.RequestPreVoteRequest)
	case 4:
		command = new(raft.TimeoutNowRequest)
	default:
		return sfcp.ErrFrame
	}
	if err = json.Unmarshal(e.Body, command); err != nil {
		return err
	}
	var authorityTime, deliveryTime time.Duration
	var authorityCPU time.Duration
	heartbeatRPC := false
	var replyStarted time.Time
	phase := "authority"
	if heartbeat, ok := command.(*raft.AppendEntriesRequest); ok && len(heartbeat.Entries) == 0 && heartbeat.LeaderCommitIndex == 0 {
		heartbeatRPC = true
		parseTime := time.Since(received)
		defer func() {
			if elapsed := time.Since(received); elapsed >= 200*time.Millisecond {
				var replyTime time.Duration
				if !replyStarted.IsZero() {
					replyTime = time.Since(replyStarted)
				}
				log.Printf("raft heartbeat server slow: peer=%s request=%d elapsed=%s parse=%s authority=%s authority_process_cpu=%s deliver=%s reply=%s phase=%s", s.Peer().ID, f.Request, elapsed, parseTime, authorityTime, authorityCPU, deliveryTime, replyTime, phase)
			}
		}()
	}
	header := command.(interface{ GetRPCHeader() raft.RPCHeader }).GetRPCHeader()
	before := time.Now()
	var cpuStart time.Duration
	if heartbeatRPC {
		cpuStart = processCPUTime()
	}
	approved := t.requestPeer(header, s.Peer().Key)
	authorityTime = time.Since(before)
	if heartbeatRPC {
		authorityCPU = processCPUUsed(cpuStart)
	}
	if !approved {
		return sfcp.ErrAdmission
	}
	phase = "deliver"
	before = time.Now()
	result, err := t.deliver(ctx, command, nil)
	deliveryTime = time.Since(before)
	if err != nil {
		return err
	}
	phase = "reply"
	replyStarted = time.Now()
	body, err := json.Marshal(result.Response)
	if err != nil {
		return err
	}
	reply := rpcEnvelope{Schema: 1, Body: body}
	if result.Error != nil {
		reply.Error = result.Error.Error()
	}
	b, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	err = sfcp.WriteFrame(stream, rpcFrame(sfcp.KindResponse, f.Request, b))
	if err == nil {
		phase = "complete"
	}
	return err
}
func (t *raftTransport) InstallSnapshot(id raft.ServerID, addr raft.ServerAddress, args *raft.InstallSnapshotRequest, response *raft.InstallSnapshotResponse, source io.Reader) (err error) {
	started := time.Now()
	defer func() { t.observeSnapshot(id, args, response, time.Since(started), err) }()
	if err := t.begin(); err != nil {
		return err
	}
	defer t.active.Done()
	if args.Size <= 0 {
		return sfcp.ErrBudget
	}
	ctx, cancel := context.WithTimeout(t.ctx, 30*time.Second)
	defer cancel()
	select {
	case t.outgoingSnapshot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-t.outgoingSnapshot }()
	file, digest, err := t.spool(source, args.Size)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()

	peer, ok := t.resolve(id, addr)
	if !ok || !(peer.Member || peer.Replicate) {
		return sfcp.ErrAdmission
	}
	s, err := t.mesh.Dial(ctx, peer)
	if err != nil {
		return err
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	request := t.mesh.NextRequest()
	metadata, err := json.Marshal(args)
	if err != nil {
		return err
	}
	f := sfcp.Frame{Purpose: sfcp.Snapshot, Kind: sfcp.KindRequest, Request: request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: metadata}, {Tag: 2, Required: true, Value: digest[:]}}}
	if err = sfcp.WriteFrame(stream, f); err != nil {
		return err
	}
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < args.Size; {
		size := args.Size - offset
		if size > int64(len(buffer)) {
			size = int64(len(buffer))
		}
		n, err := io.ReadFull(file, buffer[:size])
		if err != nil {
			return err
		}
		f.Kind = sfcp.KindChunk
		// Every chunk has the common shape: offset, data, transfer digest.
		f.Fields = []sfcp.Field{{Tag: 1, Required: true, Value: binary.LittleEndian.AppendUint64(nil, uint64(offset))}, {Tag: 2, Required: true, Value: buffer[:n]}, {Tag: 3, Required: true, Value: digest[:]}}
		if err = sfcp.WriteFrame(stream, f); err != nil {
			return err
		}
		offset += int64(n)
	}

	ack, err := sfcp.ReadFrame(stream, 128)
	if err != nil {
		return err
	}
	if ack.Purpose != sfcp.Snapshot || ack.Kind != sfcp.KindDone || ack.Request != request || s.Admit(ack, sfcp.Snapshot, false) != nil || binary.LittleEndian.Uint64(ack.Fields[0].Value) != args.LastLogIndex || !bytes.Equal(ack.Fields[2].Value, digest[:]) {
		return sfcp.ErrAdmission
	}
	*response = raft.InstallSnapshotResponse{RPCHeader: raft.RPCHeader{ProtocolVersion: raft.ProtocolVersionMax, ID: []byte(peer.ID), Addr: []byte(addr)}, Term: binary.LittleEndian.Uint64(ack.Fields[1].Value), Success: true}
	return nil
}
func (t *raftTransport) snapshot(ctx context.Context, s *sfcp.Session, stream *quic.Stream, f sfcp.Frame) error {
	if err := t.begin(); err != nil {
		return err
	}
	defer t.active.Done()
	if f.Kind != sfcp.KindRequest {
		return sfcp.ErrFrame
	}
	var request raft.InstallSnapshotRequest
	if err := json.Unmarshal(f.Fields[0].Value, &request); err != nil {
		return err
	}
	if !t.requestPeer(request.RPCHeader, s.Peer().Key) || request.Size <= 0 {
		return sfcp.ErrAdmission
	}
	digest := append([]byte(nil), f.Fields[1].Value...)
	select {
	case t.incomingSnapshot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-t.ctx.Done():
		return t.ctx.Err()
	}
	defer func() { <-t.incomingSnapshot }()
	file, err := os.CreateTemp(t.staging, ".sfc-snapshot-*")
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	hash := sha256.New()
	for offset := int64(0); offset < request.Size; {
		chunk, err := sfcp.ReadFrame(stream, 128<<10+64)
		if err != nil {
			return err
		}
		if chunk.Purpose != sfcp.Snapshot || chunk.Kind != sfcp.KindChunk || chunk.Request != f.Request || s.Admit(chunk, sfcp.Snapshot, false) != nil || binary.LittleEndian.Uint64(chunk.Fields[0].Value) != uint64(offset) || len(chunk.Fields[1].Value) == 0 || int64(len(chunk.Fields[1].Value)) > request.Size-offset || !bytes.Equal(chunk.Fields[2].Value, digest) {
			return sfcp.ErrFrame
		}
		b := chunk.Fields[1].Value
		n, err := file.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		_, _ = hash.Write(b)
		offset += int64(n)
	}
	if !bytes.Equal(hash.Sum(nil), digest) {
		return sfcp.ErrFrame
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	result, err := t.deliver(ctx, &request, file)

	if err != nil {
		return err
	}
	response, ok := result.Response.(*raft.InstallSnapshotResponse)
	if result.Error != nil {
		return result.Error
	}
	if !ok || !response.Success {
		return errors.New("snapshot installation rejected")
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.Snapshot, Kind: sfcp.KindDone, Request: f.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: binary.LittleEndian.AppendUint64(nil, request.LastLogIndex)}, {Tag: 2, Required: true, Value: binary.LittleEndian.AppendUint64(nil, response.Term)}, {Tag: 3, Required: true, Value: digest}}})
}

// Stage immutable bytes on owned disk before sending a digest or handing them
// to native InstallSnapshot. No whole-artifact buffer or fixed DB-size cap.
func (t *raftTransport) spool(source io.Reader, size int64) (*os.File, [32]byte, error) {
	var digest [32]byte
	file, err := os.CreateTemp(t.staging, ".sfc-snapshot-*")
	if err != nil {
		return nil, digest, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = file.Close()
			_ = os.Remove(file.Name())
		}
	}()
	hash := sha256.New()
	limited := &io.LimitedReader{R: source, N: size}
	if _, err = io.CopyBuffer(io.MultiWriter(file, hash), limited, make([]byte, 128<<10)); err != nil {
		return nil, digest, err
	}
	if limited.N != 0 {
		return nil, digest, io.ErrUnexpectedEOF
	}
	var extra [1]byte
	n, err := source.Read(extra[:])
	if n != 0 || err != io.EOF {
		return nil, digest, errors.New("snapshot source length mismatch")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, digest, err
	}
	copy(digest[:], hash.Sum(nil))
	ok = true
	return file, digest, nil
}
