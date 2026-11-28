// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/quic-go/quic-go"
)

type MemberRequest struct {
	Schema               uint8
	Method, Node, JoinID string
	Ack                  *membership.Ack `json:",omitempty"`
	// Joiner is set only when a member that is not the leader relays a
	// joining node's request: the joining node's TLS key, as hex. The
	// leader checks it exactly as it checks a direct requester's key.
	Joiner string `json:",omitempty"`
}
type MemberReply struct {
	Schema  uint8
	Code    string
	Message string            `json:",omitempty"`
	Entry   *membership.Entry `json:",omitempty"`
	// Leader, with Code "unavailable", names the leader a member could not
	// relay to, so the joining node can ask it directly.
	Leader *MemberLeader `json:",omitempty"`
	// Members, on an "ok" join reply, lists the current full members, so
	// a joining node accepts replication from a leader that is not its
	// invitation's genesis or source. It arrives over the authenticated
	// session with the pinned source, which vouches for it as it would for
	// the replicated state itself.
	Members []config.Peer `json:",omitempty"`
}

// MemberLeader identifies the current leader for a joining node.
type MemberLeader struct {
	ID, Key, Endpoint string
}

func memberDecode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return sfcp.ErrFrame
	}
	b, err := json.Marshal(target)
	if err != nil || !bytes.Equal(b, raw) {
		return sfcp.ErrFrame
	}
	return nil
}
func (r *Runtime) serveMembership() error { return r.Mesh.On(sfcp.Membership, r.membershipRequest) }
func (r *Runtime) membershipRequest(ctx context.Context, session *sfcp.Session, stream *quic.Stream, f sfcp.Frame) error {
	if f.Kind != 1 {
		return sfcp.ErrFrame
	}
	digest := sha256.Sum256(f.Fields[0].Value)
	var req MemberRequest
	if !bytes.Equal(digest[:], f.Fields[1].Value) || memberDecode(f.Fields[0].Value, &req) != nil || req.Schema != 1 {
		return sfcp.ErrFrame
	}
	reply := MemberReply{Schema: 1, Code: "denied"}
	// requester is the joining node's TLS key: the session's own, or the
	// one a current full member relays.
	requester := session.Peer().Key
	relayed := req.Joiner != ""
	if relayed {
		relayer, ok := r.Mesh.Peer(session.Peer().Key)
		key, err := identity.ParseKey(req.Joiner)
		if !ok || !relayer.Member || err != nil || fmt.Sprintf("%x", key) != req.Joiner || sfcp.Identity(key) == session.Peer().Key {
			return r.writeMemberReply(stream, f, digest, reply)
		}
		requester = sfcp.Identity(key)
	}
	if engine := r.Engine(); engine != nil && !engine.IsLeader() {
		// Only the leader reads the latest state and changes membership.
		// The invitation source may have become a follower since it
		// signed the invitation, so pass the request on; a relayed request
		// is never relayed again.
		if relayed {
			reply.Code = "unavailable"
		} else {
			reply = r.relayMembership(ctx, requester, req)
		}
		return r.writeMemberReply(stream, f, digest, reply)
	}
	view, d, err := r.members(ctx, true)
	if err != nil {
		reply.Code = "unavailable"
	} else if entry, ok := d.Entry(req.Node); ok && entry.JoinID == req.JoinID && entry.Peer.Key == fmt.Sprintf("%x", requester) {
		// Only this joining TLS key can request its own approved operation.
		switch req.Method {
		case "join":
			if req.Ack == nil {
				if refused := joinFeatures(view, session, r.Mesh, requester, relayed); refused != nil {
					reply.Code, reply.Message = "version", refused.Error()
					return r.writeMemberReply(stream, f, digest, reply)
				}
				work, cancel := context.WithTimeout(r.ctx, 20*time.Second)
				err = r.advanceMember(work, req.Node, true)
				cancel()
				if err == nil {
					reply.Code = "ok"
				} else {
					reply.Code = "unknown"
					reply.Message = err.Error()
				}
			}
		case "install":
			if req.Ack != nil && req.Ack.Schema == 1 && req.Ack.Cluster == d.Cluster && req.Ack.Node == req.Node && req.Ack.JoinID == req.JoinID && req.Ack.Key == [32]byte(requester) && ed25519.Verify(ed25519.PublicKey(req.Ack.Key[:]), membership.AckBytes(*req.Ack), req.Ack.Signature) {
				if membership.FullMember(entry) {
					reply.Code = "ok"
				} else {
					err = r.reportInstalled(ctx, view, entry, req)
					if err == nil {
						reply.Code = "ok"
					} else {
						reply.Code = "unknown"
						reply.Message = err.Error()
					}
				}
			}
		case "status":
			if req.Ack == nil {
				reply.Code = "ok"
			}
		}
		if reply.Code == "ok" {
			if _, now, readErr := r.members(ctx, true); readErr == nil {
				if current, ok := now.Entry(req.Node); ok {
					reply.Entry = &current
				}
				if req.Method == "join" {
					for _, e := range now.Entries {
						if membership.FullMember(e) && e.Peer.ID != req.Node {
							reply.Members = append(reply.Members, e.CurrentPeer())
						}
					}
				}
			} else {
				reply.Code = "unavailable"
			}
		}
	}
	return r.writeMemberReply(stream, f, digest, reply)
}

// joinFeatures refuses a joining server that lacks a feature the cluster's
// entries have used (devel/design/upgrades.md 3-5): it could not apply them.
// The joiner's set is what it announced on this session, or, for a relayed
// request, what this node last saw from it (none when never seen).
func joinFeatures(view cluster.View, session *sfcp.Session, mesh *sfcp.Transport, requester sfcp.Identity, relayed bool) error {
	used, ok := view.State.FeaturesUsed()
	if !ok {
		return errors.New("this cluster's feature record is unreadable")
	}
	if used.Empty() {
		return nil
	}
	have := session.PeerFeatures()
	if relayed {
		have, _ = mesh.PeerFeatures(requester)
	}
	return cluster.MissingFeatures("this cluster", used, have, "the joining server")
}

func (r *Runtime) writeMemberReply(stream *quic.Stream, f sfcp.Frame, digest [32]byte, reply MemberReply) error {
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.Membership, Kind: 2, Request: f.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
}

// relayMembership passes a joining node's request to the leader and returns
// the leader's reply. A failure before the request reached the leader is
// "unavailable" with the leader named, so the joining node may ask it
// directly; a failure after it was sent is "unknown", as for a direct call.
func (r *Runtime) relayMembership(ctx context.Context, requester sfcp.Identity, req MemberRequest) MemberReply {
	reply := MemberReply{Schema: 1, Code: "unavailable"}
	leader, ok := r.Engine().LeaderPeer()
	if !ok {
		return reply
	}
	reply.Leader = &MemberLeader{ID: leader.ID, Key: fmt.Sprintf("%x", leader.Key), Endpoint: leader.Endpoint}
	if leader.Key == r.Mesh.LocalKey() {
		return reply
	}
	req.Joiner = fmt.Sprintf("%x", requester)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	relayed, err := CallMembership(ctx, r.Mesh, leader, req)
	switch {
	case err == nil || relayed.Code != "" && relayed.Code != "unknown":
		relayed.Leader = nil
		return relayed
	case errors.Is(err, cluster.ErrUnknown):
		return MemberReply{Schema: 1, Code: "unknown", Message: err.Error()}
	}
	return reply
}

// reportInstalled commits the joiner's signed ACK. Other nodes' reports
// (their configuration after the join, node proofs) move the directory's
// root revision at the same time, so a refused CAS is read again and the
// same ACK reported on the new revisions while the entry is still this join
// and not yet a full member. The ACK is immutable, so this never changes
// what is reported.
func (r *Runtime) reportInstalled(ctx context.Context, view cluster.View, entry membership.Entry, req MemberRequest) error {
	for attempt := 0; ; attempt++ {
		err := r.memberReport(ctx, view, control.MemberReport{Action: "installed", Node: req.Node, Expected: entry.Revision, Ack: req.Ack})
		if !errors.Is(err, errMemberReportStale) || attempt == 4 {
			return err
		}
		var d membership.Directory
		if view, d, err = r.members(ctx, true); err != nil {
			return err
		}
		current, ok := d.Entry(req.Node)
		if !ok || current.JoinID != req.JoinID || current.Peer.Key != entry.Peer.Key {
			return errMemberReportStale
		}
		if membership.FullMember(current) {
			return nil
		}
		entry = current
	}
}

// CallMembership sends once. Transport uncertainty never creates a new Join ID
// or silently resubmits a configuration change; the original shared A2 survives.
func CallMembership(ctx context.Context, mesh *sfcp.Transport, target sfcp.Peer, req MemberRequest) (MemberReply, error) {
	req.Schema = 1
	raw, err := json.Marshal(req)
	if err != nil {
		return MemberReply{}, err
	}
	digest := sha256.Sum256(raw)
	id := mesh.NextRequest()
	lifetime, _ := sfcp.NewRequest(fmt.Sprint(id), digest)
	// A joining node may be unable to reach its source (it sits on a private
	// network); the source then connects to it, and that session carries the
	// request (see meshLinks).
	conn, err := mesh.DialWait(ctx, target)
	if err != nil {
		return MemberReply{}, err
	}
	stream, err := conn.Open(ctx)
	if err != nil {
		return MemberReply{}, err
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	f := sfcp.Frame{Purpose: sfcp.Membership, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err = sfcp.Encode(f); err != nil {
		return MemberReply{}, err
	}
	if err = ctx.Err(); err != nil {
		return MemberReply{}, err
	}
	lifetime, _ = lifetime.BeginSend()
	if err = sfcp.WriteFrame(stream, f); err != nil {
		return MemberReply{}, fmt.Errorf("%w: %v", cluster.ErrUnknown, err)
	}
	response, err := sfcp.ReadFrame(stream, 128<<10)
	if err != nil {
		return MemberReply{}, fmt.Errorf("%w: %v", cluster.ErrUnknown, err)
	}
	var reply MemberReply
	if response.Purpose != sfcp.Membership || response.Kind != 2 || response.Request != id || conn.Admit(response, sfcp.Membership, false) != nil || !bytes.Equal(response.Fields[1].Value, digest[:]) || memberDecode(response.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
		return MemberReply{}, sfcp.ErrFrame
	}
	if reply.Code == "unknown" {
		return reply, fmt.Errorf("%w: %s", cluster.ErrUnknown, reply.Message)
	}
	lifetime, _ = lifetime.Reply(fmt.Sprint(id), digest)
	if reply.Code != "ok" {
		return reply, errors.New("membership request: " + reply.Code)
	}
	return reply, nil
}
