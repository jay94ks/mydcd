// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// The existing fixture supplies actual loopback SFCP transports, SDK Raft,
// bbolt and quorum authenticationView. Two real Services handle the shell;
// its third transport is only the fixture's existing Raft quorum member.
// Signed readiness/SSH observations and the PTY below are explicit model
// inputs, not evidence of account provisioning, sshd or OS shell execution.
func TestNodeShellActualServicesRelayOriginalToCurrentRemoteOwner(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers, access.NodeShell)
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))

	// Install node-b through the existing signed user operation/member reports.
	// Transport node-c deliberately remains absent from the committed Directory:
	// TLS membership alone must not authorize a shell relay.
	peer := config.Peer{ID: f.peers[1].ID, Key: hex.EncodeToString(f.nodes[1].Public[:]), Endpoint: f.peers[1].Endpoint}
	f.change("invite-node", 0, control.NodeInvitation{Peer: peer, JoinID: "shell-relay-b"})
	memberReport := func(action string, edit func(*control.MemberReport)) {
		t.Helper()
		v := f.read()
		d, err := f.policy.Members(v.State)
		if err != nil {
			t.Fatal(err)
		}
		entry, _ := d.Entry(peer.ID)
		r := control.MemberReport{Schema: 1, Cluster: f.policy.Cluster, Reporter: f.nodes[0].Public, Action: action, Node: peer.ID, Expected: entry.Revision, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.MembersKey).Revision, RequestID: fmt.Sprintf("shell-member-%s-%d", action, v.State.Index())}
		edit(&r)
		r.Signature = ed25519.Sign(f.nodes[0].Private, control.MemberReportBytes(r))
		cmd, err := r.Command()
		if err != nil {
			t.Fatal(err)
		}
		f.submit(cmd)
	}
	memberReport("dispatch", func(r *control.MemberReport) {
		d, _ := f.policy.Members(f.read().State)
		e, _ := d.Entry(peer.ID)
		r.JobID, r.ConfigurationIndex = e.Job.Pending.ID, f.read().RaftIndex
	})
	memberReport("observe", func(r *control.MemberReport) {
		d, _ := f.policy.Members(f.read().State)
		e, _ := d.Entry(peer.ID)
		r.JobID, r.ConfigurationIndex, r.Peer = e.Job.Pending.ID, f.read().RaftIndex, peer
	})
	memberReport("installed", func(r *control.MemberReport) {
		d, _ := f.policy.Members(f.read().State)
		e, _ := d.Entry(peer.ID)
		ack := membership.Ack{Schema: 1, Cluster: f.policy.Cluster, Node: peer.ID, JoinID: e.JoinID, Key: f.nodes[1].Public, ConfigurationIndex: e.NativeIndex, AppliedIndex: f.read().RaftIndex}
		ack.Signature = ed25519.Sign(f.nodes[1].Private, membership.AckBytes(ack))
		r.Ack = &ack
	})
	directory, err := f.policy.Members(f.read().State)
	if err != nil || !directory.WorkKey(f.nodes[0].Public) || !directory.WorkKey(f.nodes[1].Public) || directory.MemberKey(f.nodes[2].Public) {
		t.Fatal("current committed relay/owner membership", err)
	}
	book, err := f.policy.NodeShells(f.read().State)
	if err != nil {
		t.Fatal(err)
	}
	f.change("set-node-shell-node", book.Policy.Revision, control.NodeShellNodeChange{Node: peer.ID, Shell: "on"})
	report := func(r control.NodeShellReport) {
		t.Helper()
		v := f.read()
		b, e := f.policy.NodeShells(v.State)
		if e != nil {
			t.Fatal(e)
		}
		r.Schema, r.Cluster, r.Reporter, r.Node = 1, f.policy.Cluster, f.nodes[1].Public, peer.ID
		r.Epoch, r.RootRevision, r.PolicyRevision = v.State.ModuleEpoch(), v.State.Object(control.NodeShellKey).Revision, b.Policy.Revision
		r.RequestID = fmt.Sprintf("shell-owner-%s-%d", r.Kind, v.State.Index())
		r.Signature = ed25519.Sign(f.nodes[1].Private, control.NodeShellReportBytes(r))
		cmd, e := r.Command()
		if e != nil {
			t.Fatal(e)
		}
		f.submit(cmd)
	}
	now := time.Now().Unix()
	report(control.NodeShellReport{Kind: "ready", Ready: true, At: now, Sequence: 1})
	// Retain the exact accepted user command for replay; no second operation ID
	// is created by either Service while acquiring the original stream.
	changeBytes, err := control.ChangeBytes("open-node-shell", f.session.User, 0, control.NodeShellOpen{Node: peer.ID, Cols: 80, Rows: 24})
	if err != nil {
		t.Fatal(err)
	}
	change, err := schema.Decode[control.Change](changeBytes)
	if err != nil {
		t.Fatal(err)
	}
	v := f.read()
	op := control.UserOperation{Schema: 1, Session: f.session, At: now, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.NodeShellKey).Revision, RequestID: "shell-relay-original", Change: change}
	op.Signature = ed25519.Sign(f.user.Private, control.OperationBytes(op))
	original, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	f.submit(original)
	originalResult, found := f.read().State.LookupResult(original)
	if !found {
		t.Fatal("missing original shell receipt")
	}
	book, _ = f.policy.NodeShells(f.read().State)
	accepted, found := book.Record(op.RequestID)
	if !found || accepted.Owner != f.nodes[1].Public || accepted.Session.State != "queued" {
		t.Fatal("original intent was not queued at the remote owner")
	}
	originBytes, _ := json.Marshal(accepted.Origin)
	var calls atomic.Int32
	modeled := &nodeShellRelayPTY{output: make(chan []byte, 1), ended: make(chan control.NodeShellEnd, 1), half: make(chan struct{}), stopped: make(chan struct{})}
	defer modeled.Close()
	services := [2]Service{
		{Engine: f.engines[0], Mesh: f.meshes[0], Self: f.nodes[0], Policy: f.policy},
		{Engine: f.engines[1], Mesh: f.meshes[1], Self: f.nodes[1], Policy: f.policy},
	}
	services[0].NodeShellOpen = func(context.Context, string) (NodeShellStream, error) {
		return nil, errors.New("ingress attempted the remote native shell")
	}
	services[1].NodeShellOpen = func(_ context.Context, id string) (NodeShellStream, error) {
		if id != op.RequestID || calls.Add(1) != 1 {
			return nil, errors.New("remote owner recreated an original shell")
		}
		return modeled, nil
	}
	type observed struct {
		node      int
		kind      uint8
		envelope  Envelope
		challenge [32]byte
		bindErr   error
	}
	seen := make(chan observed, 16)
	finished := make(chan error, 16)
	for i := range services {
		svc := services[i]
		if err = f.meshes[i].OnManagement(sfcp.NodeShell, func(ctx context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
			envelope, decodeErr := schema.Decode[Envelope](frame.Fields[0].Value)
			if decodeErr != nil {
				return decodeErr
			}
			_, bindErr := svc.binding(conn, frame.Kind, envelope)
			seen <- observed{node: i, kind: frame.Kind, envelope: envelope, challenge: conn.Challenge(), bindErr: bindErr}
			result := svc.handleNodeShell(ctx, conn, stream, frame)
			finished <- result
			return result
		}); err != nil {
			t.Fatal(err)
		}
	}

	// All four requests still name the valid, queued original. Each malformed
	// relay is independently rejected before any modeled native acquisition.
	for _, mode := range []string{"wrong-owner", "wrong-target", "current-role", "changed-body"} {
		t.Run(mode, func(t *testing.T) {
			source := 0
			if mode == "current-role" {
				source = 2
			}
			c := Client{Mesh: f.meshes[source], Self: f.nodes[source], Cluster: f.policy.Cluster}
			q := NodeShellRequest{Schema: 1, SessionID: op.RequestID, Nonce: [32]byte{71}}
			channel, reply, e := c.nodeShellExchange(f.ctx, f.peers[1], q, f.session.ExpiresAt, 3, func(conn *sfcp.Session, body []byte) (Envelope, error) {
				challenge := [32]byte{72}
				envelope := Envelope{Body: body, Session: &f.session, Signature: ed25519.Sign(f.user.Private, access.RequestBytes(f.session, challenge, body))}
				relaySigner := f.nodes[source]
				if mode == "wrong-owner" {
					relaySigner = f.nodes[2]
				}
				envelope.Relay = &Relay{Node: relaySigner.Public, Target: f.nodes[1].Public, Caller: f.user.Public, Challenge: challenge, Connection: conn.PeerChallenge()}
				if mode == "wrong-target" {
					envelope.Relay.Target = f.nodes[0].Public
				}
				if mode == "changed-body" {
					q.Nonce[0]++
					envelope.Body, _ = json.Marshal(q)
				}
				envelope.Relay.Signature = ed25519.Sign(relaySigner.Private, RelayBytes(f.policy.Cluster, envelope))
				return envelope, nil
			})
			if channel != nil {
				_ = channel.Close()
			}
			var failure *Error
			if !errors.As(e, &failure) || failure.Code != "forbidden" || failure.Phase != sfcp.Completed || reply.Code != "forbidden" || calls.Load() != 0 {
				t.Fatal("invalid relay acquired original shell", reply.Code, e, calls.Load())
			}
			observation := <-seen
			if observation.node != 1 || (observation.bindErr == nil) != (mode == "current-role") {
				t.Fatal("refusal did not reach the intended binding/current-role gate", observation.node, observation.bindErr)
			}
		})
	}
	report(control.NodeShellReport{Kind: "opened", SessionID: op.RequestID, At: now, LastActivity: now, Sequence: 1})
	book, _ = f.policy.NodeShells(f.read().State)
	opened, _ := book.Record(op.RequestID)
	modeled.metadata = opened.Session
	channel, metadata, err := f.client.OpenNodeShell(f.ctx, f.peers[0], f.session, op.RequestID)
	if err != nil {
		t.Fatal("actual ingress -> remote owner acquisition", err)
	}
	defer channel.Close()
	if !reflect.DeepEqual(metadata, opened.Session) || calls.Load() != 1 {
		t.Fatal("relay changed original owner metadata or repeated native acquisition")
	}
	first, second := <-seen, <-seen
	q, qErr := schema.Decode[NodeShellRequest](first.envelope.Body)
	if first.node != 0 || first.kind != 1 || first.bindErr != nil || second.node != 1 || second.kind != 3 || second.bindErr != nil || qErr != nil || q.SessionID != op.RequestID || q.Nonce == ([32]byte{}) || !bytes.Equal(first.envelope.Body, second.envelope.Body) || !sameSession(*first.envelope.Session, *second.envelope.Session) || !bytes.Equal(first.envelope.Signature, second.envelope.Signature) {
		t.Fatal("real forwarding changed original user/session/nonce/body proof")
	}
	relay := second.envelope.Relay
	if first.envelope.Relay != nil || relay == nil || relay.Node != f.nodes[0].Public || relay.Target != f.nodes[1].Public || relay.Caller != f.user.Public || relay.Challenge != first.challenge || relay.Connection != second.challenge || !ed25519.Verify(f.nodes[0].Public[:], RelayBytes(f.policy.Cluster, second.envelope), relay.Signature) {
		t.Fatal("relay was not bound to the original ingress proof and destination connection")
	}
	for _, record := range []sfcp.NodeShellRecord{{Kind: "stdin", Data: []byte("private PTY input")}, {Kind: "resize", Cols: 120, Rows: 40}, {Kind: "half-close"}} {
		if err = channel.Send(record); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-modeled.half:
	case <-f.ctx.Done():
		t.Fatal("remote half-close was not delivered", f.ctx.Err())
	}
	modeled.mu.Lock()
	input, cols, rows := modeled.input.String(), modeled.cols, modeled.rows
	modeled.mu.Unlock()
	if input != "private PTY input" || cols != 120 || rows != 40 {
		t.Fatal("remote PTY stdin/resize changed", cols, rows)
	}
	f.change("close-node-shell", 0, control.NodeShellClose{SessionID: op.RequestID})
	report(control.NodeShellReport{Kind: "closed", SessionID: op.RequestID, At: time.Now().Unix(), LastActivity: now, Sequence: 2, Reason: "closed", BytesIn: uint64(len(input)), BytesOut: uint64(len("output after half-close"))})
	book, _ = f.policy.NodeShells(f.read().State)
	closed, _ := book.Record(op.RequestID)
	if closed.Session.State != "closed" || closed.Session.End == nil || closed.Session.End.ClosedBy == nil || closed.CloseOrigin == nil || closed.Session.End.ClosedBy.User != f.session.User || closed.CloseOrigin.Session.User != closed.Session.End.ClosedBy.User {
		t.Fatal("close actor did not come from the retained signed administrator operation")
	}
	modeled.ended <- *closed.Session.End
	modeled.output <- []byte("output after half-close")
	close(modeled.output)
	output, err := channel.Receive()
	if err != nil || output.Kind != "stdout" || string(output.Data) != "output after half-close" {
		t.Fatal("remote output after half-close", err)
	}
	end, err := channel.Receive()
	if err != nil || end.Kind != "end" || end.End == nil || end.End.Code != closed.Session.End.Code || end.End.Reason != closed.Session.End.Reason || end.End.ClosedBy == nil || end.End.ClosedBy.User != closed.Session.End.ClosedBy.User || end.End.ClosedBy.Username != closed.Session.End.ClosedBy.Username {
		t.Fatal("remote end lost the original signed close actor", err)
	}
	// End delivery joins both real handlers. Earlier denied calls also publish
	// completion; all six handlers must terminate, with no outstanding stream.
	for range 6 {
		select {
		case err = <-finished:
			if err != nil {
				t.Fatal("real handler did not finish", err)
			}
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		}
	}
	f.submit(original)
	after, _ := f.policy.NodeShells(f.read().State)
	retained, _ := after.Record(op.RequestID)
	retainedOrigin, _ := json.Marshal(retained.Origin)
	result, ok := f.read().State.LookupResult(original)
	if len(after.Records) != 1 || !ok || result != originalResult || !bytes.Equal(originBytes, retainedOrigin) || !reflect.DeepEqual(retained, closed) {
		t.Fatal("replay changed the original accepted shell/result/close state")
	}
	duplicate, _, err := f.client.OpenNodeShell(f.ctx, f.peers[0], f.session, op.RequestID)
	if duplicate != nil {
		_ = duplicate.Close()
	}
	var failure *Error
	if !errors.As(err, &failure) || failure.Code != "forbidden" || failure.Phase != sfcp.Completed || calls.Load() != 1 {
		t.Fatal("closed original was reopened/recreated", err, calls.Load())
	}
	for range 2 {
		select {
		case err = <-finished:
			if err != nil {
				t.Fatal("original reopen refusal did not finish", err)
			}
		case <-f.ctx.Done():
			t.Fatal(f.ctx.Err())
		}
	}
}

// Only the native PTY byte interface is modeled. No session authority, owner
// selection, forwarding, frame/record parser or control algorithm is replaced.
type nodeShellRelayPTY struct {
	metadata control.NodeShellSession
	mu       sync.Mutex
	input    bytes.Buffer
	cols     uint16
	rows     uint16
	output   chan []byte
	ended    chan control.NodeShellEnd
	half     chan struct{}
	stopped  chan struct{}
	once     sync.Once
}

func (p *nodeShellRelayPTY) Metadata() control.NodeShellSession { return p.metadata }
func (p *nodeShellRelayPTY) Read(data []byte) (int, error) {
	select {
	case out, ok := <-p.output:
		if !ok {
			return 0, io.EOF
		}
		if len(out) > len(data) {
			return 0, io.ErrShortBuffer
		}
		return copy(data, out), nil
	case <-p.stopped:
		return 0, io.ErrClosedPipe
	}
}
func (p *nodeShellRelayPTY) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.input.Write(data)
}
func (p *nodeShellRelayPTY) Resize(cols, rows uint16) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cols, p.rows = cols, rows
	return nil
}
func (p *nodeShellRelayPTY) CloseWrite() error { close(p.half); return nil }
func (p *nodeShellRelayPTY) Wait() (control.NodeShellEnd, error) {
	select {
	case end := <-p.ended:
		return end, nil
	case <-p.stopped:
		return control.NodeShellEnd{}, io.ErrClosedPipe
	}
}
func (p *nodeShellRelayPTY) Close() error { p.once.Do(func() { close(p.stopped) }); return nil }
