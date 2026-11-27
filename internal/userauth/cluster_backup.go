// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"runtime/debug"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ClusterBackupRequest asks for the backup of one recorded cluster-backup
// operation. It carries no secret; the master key goes only to the
// operation's own one-time recipient key.
type ClusterBackupRequest struct {
	Schema    uint8
	Operation string
	ExpiresAt int64
	Nonce     [32]byte
}

func (q ClusterBackupRequest) valid(now int64) bool {
	return q.Schema == 1 && q.Operation != "" && len(q.Operation) <= 64 && q.Nonce != ([32]byte{}) && q.ExpiresAt > now && q.ExpiresAt-now <= control.ClusterBackupWindow
}

// ClusterBackupReply is "ready" (with the signed manifest and the sealed
// master key) before the snapshot chunks, then "ok" after them; any other
// Code ends the stream.
type ClusterBackupReply struct {
	Schema    uint8
	Operation string
	Code      string
	Manifest  *clusterbackup.Manifest     `json:",omitempty"`
	Signature []byte                      `json:",omitempty"`
	Master    *clusterbackup.SealedMaster `json:",omitempty"`
}

func writeClusterBackupReply(stream sfcp.Stream, id uint64, header [32]byte, r ClusterBackupReply) error {
	r.Schema = 1
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.ClusterBackup, Kind: 2, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}})
}

func backupVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" && len(info.Main.Version) <= 64 {
		return info.Main.Version
	}
	v := localServerVersion()
	if len(v.Commit) >= 12 {
		return "devel+" + v.Commit[:12]
	}
	return "devel"
}

func backupMembers(d membership.Directory) []clusterbackup.Member {
	var out []clusterbackup.Member
	for _, e := range d.Entries {
		if !membership.FullMember(e) {
			continue
		}
		key, err := identity.ParseKey(e.CurrentPeer().Key)
		if err != nil {
			continue
		}
		out = append(out, clusterbackup.Member{ID: e.Peer.ID, Key: key, Voter: d.VoterKey(key)})
	}
	return out
}

// clusterBackupWork checks the recorded operation on a fresh quorum view and
// returns that view.
func (s Service) clusterBackupWork(ctx context.Context, session access.Session, operation string) (cluster.View, control.Policy, control.ClusterBackupRecord, error) {
	view, err := s.authenticationView(ctx)
	if err != nil {
		return view, control.Policy{}, control.ClusterBackupRecord{}, err
	}
	if s.Enabled != nil && !s.Enabled(view.State) {
		return view, control.Policy{}, control.ClusterBackupRecord{}, sfcp.ErrAdmission
	}
	policy, err := s.Policy.Current(view.State)
	if err != nil {
		return view, policy, control.ClusterBackupRecord{}, err
	}
	record, err := policy.ClusterBackupWork(view.State, session, operation, time.Now().Unix())
	return view, policy, record, err
}

func (s Service) handleClusterBackup(base context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
	if frame.Kind != 1 && frame.Kind != 3 {
		return sfcp.ErrFrame
	}
	header := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(header[:], frame.Fields[1].Value) {
		return sfcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	if err != nil {
		return sfcp.ErrFrame
	}
	q, decodeErr := schema.Decode[ClusterBackupRequest](envelope.Body)
	reply := func(code string) error {
		return writeClusterBackupReply(stream, frame.Request, header, ClusterBackupReply{Operation: q.Operation, Code: code})
	}
	if err := streamEOF(stream); err != nil {
		return err
	}
	if decodeErr != nil || !q.valid(time.Now().Unix()) || envelope.Session == nil || q.ExpiresAt > envelope.Session.ExpiresAt || envelope.Relay != nil && envelope.Relay.ServiceCall != nil {
		return reply("denied")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key {
		return reply("denied")
	}
	session := *envelope.Session
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	view, policy, record, err := s.clusterBackupWork(ctx, session, q.Operation)
	if err != nil {
		return reply("denied")
	}
	s.Policy = policy
	members, err := policy.Members(view.State)
	if err != nil {
		return reply("unavailable")
	}
	if !clusterBackupAdmits(s.Self.Public, members, envelope) {
		return reply("denied")
	}
	if !members.VoterKey(s.Self.Public) {
		// Only voters hold the master key. A relayed request must already be
		// at a voter; a non-voter hands the user's own request to the leader.
		if envelope.Relay != nil {
			return reply("target-changed")
		}
		return s.forwardClusterBackup(ctx, stream, frame, header, envelope, binding, q, members)
	}
	if s.ClusterBackupMaster == nil {
		return reply("unavailable")
	}
	// Re-check the record and this voter's standing during the transfer, so a
	// revoked session or a demotion stops it. A quorum read per 24 KiB chunk
	// would cost more than the transfer, so the full check runs at most
	// every two seconds; the connection is admitted for every chunk.
	var checked time.Time
	check := func() error {
		if err := conn.Admit(frame, sfcp.ClusterBackup, false); err != nil {
			return err
		}
		if time.Since(checked) < 2*time.Second {
			return nil
		}
		checked = time.Now()
		fresh, p, _, err := s.clusterBackupWork(ctx, session, q.Operation)
		if err != nil {
			return sfcp.ErrAdmission
		}
		d, err := p.Members(fresh.State)
		if err != nil || !d.VoterKey(s.Self.Public) {
			return sfcp.ErrAdmission
		}
		return nil
	}
	export, err := s.Engine.ExportSnapshot(view.RaftIndex)
	if err != nil {
		return reply("unavailable")
	}
	defer export.Release()
	master, err := s.ClusterBackupMaster()
	if err != nil {
		return reply("unavailable")
	}
	defer clear(master)
	self := ""
	for _, e := range members.Entries {
		if key, err := identity.ParseKey(e.CurrentPeer().Key); err == nil && key == s.Self.Public {
			self = e.Peer.ID
		}
	}
	point := export.Point
	m := clusterbackup.Manifest{Schema: 1, Cluster: policy.Cluster, Version: backupVersion(), Operation: record.Operation, User: record.Origin.Session.User, CreatedAt: time.Now().Unix(),
		RaftIndex: point.RaftIndex, Term: point.Term, Index: point.Index, SnapshotSize: point.Size, SnapshotDigest: point.Digest, StateDigest: point.StateDigest,
		Members: backupMembers(members), Voter: self, VoterKey: s.Self.Public, MasterCheck: clusterbackup.MasterCheck(policy.Cluster, master),
		Admin: policy.BootstrapKey, TrustRoot: policy.TrustRoot, Genesis: policy.Genesis}
	signature, err := clusterbackup.Sign(m, s.Self.Private)
	if err != nil {
		return reply("unavailable")
	}
	sealed, err := clusterbackup.SealMaster(record.Recipient, policy.Cluster, record.Operation, master)
	if err != nil {
		return reply("unavailable")
	}
	clear(master)
	checked = time.Time{}
	if err := check(); err != nil {
		return reply("denied")
	}
	if err := writeClusterBackupReply(stream, frame.Request, header, ClusterBackupReply{Operation: q.Operation, Code: "ready", Manifest: &m, Signature: signature, Master: &sealed}); err != nil {
		return err
	}
	w := &sfcp.ChunkWriter{Stream: stream, Purpose: sfcp.ClusterBackup, Request: frame.Request, Header: header, Check: check}
	if _, err := export.WriteTo(w); err != nil {
		return err
	}
	if w.Offset != point.Size {
		return sfcp.ErrFrame
	}
	return reply("ok")
}

// forwardClusterBackup hands the user's signed request to the leader and
// passes its frames back. Only sealed and public bytes cross this node.
func (s Service) forwardClusterBackup(ctx context.Context, stream sfcp.Stream, frame sfcp.Frame, header [32]byte, envelope Envelope, binding userBinding, q ClusterBackupRequest, members membership.Directory) error {
	peer, ok := s.Engine.LeaderPeer()
	if !ok || !members.VoterKey([32]byte(peer.Key)) {
		return writeClusterBackupReply(stream, frame.Request, header, ClusterBackupReply{Operation: q.Operation, Code: "unavailable"})
	}
	c := Client{Mesh: s.Mesh, Self: s.Self, Cluster: s.Policy.Cluster}
	out := &sfcp.ChunkWriter{Stream: stream, Purpose: sfcp.ClusterBackup, Request: frame.Request, Header: header}
	ready := false
	_, err := c.clusterBackupExchange(ctx, peer, q, 3, func(conn *sfcp.Session, body []byte) (Envelope, error) {
		relayed := envelope
		relayed.Relay = &Relay{Node: s.Self.Public, Target: [32]byte(peer.Key), Caller: binding.key, Challenge: binding.challenge, Connection: conn.PeerChallenge()}
		relayed.Relay.Signature = ed25519.Sign(s.Self.Private, RelayBytes(s.Policy.Cluster, relayed))
		return relayed, nil
	}, func(r ClusterBackupReply) error {
		ready = true
		return writeClusterBackupReply(stream, frame.Request, header, r)
	}, out)
	var completed *Error
	if err != nil && errors.As(err, &completed) && completed.Phase == sfcp.Completed && !ready {
		return writeClusterBackupReply(stream, frame.Request, header, ClusterBackupReply{Operation: q.Operation, Code: completed.Code})
	}
	if err != nil {
		return err
	}
	return writeClusterBackupReply(stream, frame.Request, header, ClusterBackupReply{Operation: q.Operation, Code: "ok"})
}

// clusterBackupAdmits is the backup stream's own member admission: this
// server is a member and a relayed request comes from a member. The voter,
// session and operation checks follow it in handleClusterBackup.
func clusterBackupAdmits(self [32]byte, members membership.Directory, envelope Envelope) bool {
	if !members.MemberKey(self) {
		return false
	}
	return envelope.Relay == nil || members.MemberKey(envelope.Relay.Node)
}

// ClusterBackup fetches the backup of a recorded cluster-backup operation.
// ready gets the signed manifest and the sealed master key before any
// snapshot byte; the snapshot then goes to to. The returned manifest's
// digest and size are already checked against the bytes received.
func (c Client) ClusterBackup(ctx context.Context, peer sfcp.Peer, session access.Session, operation string, ready func(ClusterBackupReply) error, to io.Writer) (ClusterBackupReply, error) {
	if c.Verify(session) != nil {
		return ClusterBackupReply{}, sfcp.ErrAdmission
	}
	q := ClusterBackupRequest{Schema: 1, Operation: operation, ExpiresAt: min(session.ExpiresAt, time.Now().Add(control.ClusterBackupWindow*time.Second).Unix())}
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return ClusterBackupReply{}, err
	}
	return c.clusterBackupExchange(ctx, peer, q, 1, func(conn *sfcp.Session, body []byte) (Envelope, error) {
		return Envelope{Session: &session, Body: body, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}, nil
	}, ready, to)
}

func (c Client) clusterBackupExchange(base context.Context, peer sfcp.Peer, q ClusterBackupRequest, kind uint8, envelopeFor func(*sfcp.Session, []byte) (Envelope, error), ready func(ClusterBackupReply) error, to io.Writer) (ClusterBackupReply, error) {
	if !q.valid(time.Now().Unix()) || to == nil || ready == nil {
		return ClusterBackupReply{}, sfcp.ErrAdmission
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(q.ExpiresAt, 0))
	defer cancel()
	conn, err := c.Mesh.Dial(ctx, peer)
	if err != nil {
		return ClusterBackupReply{}, err
	}
	body, _ := json.Marshal(q)
	envelope, err := envelopeFor(conn, body)
	if err != nil {
		return ClusterBackupReply{}, err
	}
	raw, _ := json.Marshal(envelope)
	header := sha256.Sum256(raw)
	stream, err := conn.OpenClusterBackupStream(ctx)
	if err != nil {
		return ClusterBackupReply{}, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.ClusterBackup, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return ClusterBackupReply{}, err
	}
	if err = stream.Close(); err != nil {
		return ClusterBackupReply{}, err
	}
	var first ClusterBackupReply
	var digest hash.Hash
	var offset uint64
	for {
		f, e := sfcp.ReadFrame(stream, 128<<10)
		if e != nil {
			return first, e
		}
		if f.Purpose != sfcp.ClusterBackup || f.Request != id || conn.Admit(f, sfcp.ClusterBackup, false) != nil {
			return first, sfcp.ErrFrame
		}
		if f.Kind == 4 {
			if digest == nil {
				return first, sfcp.ErrFrame
			}
			data, e := sfcp.Chunk(f, header, offset, first.Manifest.SnapshotSize-offset)
			if e != nil {
				return first, e
			}
			_, _ = digest.Write(data)
			if _, e := to.Write(data); e != nil {
				return first, e
			}
			offset += uint64(len(data))
			continue
		}
		if f.Kind != 2 || !bytes.Equal(f.Fields[1].Value, header[:]) {
			return first, sfcp.ErrFrame
		}
		r, e := schema.Decode[ClusterBackupReply](f.Fields[0].Value)
		if e != nil || r.Schema != 1 || r.Operation != q.Operation {
			return first, sfcp.ErrFrame
		}
		if digest == nil && r.Code == "ready" {
			if r.Manifest == nil || r.Master == nil || r.Manifest.Operation != q.Operation || r.Manifest.Cluster != c.Cluster || clusterbackup.VerifySignature(*r.Manifest, r.Signature) != nil {
				return first, sfcp.ErrFrame
			}
			first, digest = r, sha256.New()
			if e := ready(r); e != nil {
				return first, e
			}
			continue
		}
		if r.Manifest != nil || r.Master != nil || r.Signature != nil {
			return first, sfcp.ErrFrame
		}
		if err := streamEOF(stream); err != nil {
			return first, err
		}
		if r.Code != "ok" {
			return first, &Error{Code: r.Code, Phase: sfcp.Completed}
		}
		if digest == nil {
			return first, sfcp.ErrFrame
		}
		var got [32]byte
		copy(got[:], digest.Sum(nil))
		if offset != first.Manifest.SnapshotSize || got != first.Manifest.SnapshotDigest {
			return first, sfcp.ErrFrame
		}
		return first, nil
	}
}
