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

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/quic-go/quic-go"
)

type MemberRequest struct {
	Schema               uint8
	Method, Node, JoinID string
	Ack                  *membership.Ack `json:",omitempty"`
}
type MemberReply struct {
	Schema  uint8
	Code    string
	Message string            `json:",omitempty"`
	Entry   *membership.Entry `json:",omitempty"`
}

func memberDecode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return mydcp.ErrFrame
	}
	b, err := json.Marshal(target)
	if err != nil || !bytes.Equal(b, raw) {
		return mydcp.ErrFrame
	}
	return nil
}
func (r *Runtime) serveMembership() error { return r.Mesh.On(mydcp.Membership, r.membershipRequest) }
func (r *Runtime) membershipRequest(ctx context.Context, session *mydcp.Session, stream *quic.Stream, f mydcp.Frame) error {
	if f.Kind != 1 {
		return mydcp.ErrFrame
	}
	digest := sha256.Sum256(f.Fields[0].Value)
	var req MemberRequest
	if !bytes.Equal(digest[:], f.Fields[1].Value) || memberDecode(f.Fields[0].Value, &req) != nil || req.Schema != 1 {
		return mydcp.ErrFrame
	}
	reply := MemberReply{Schema: 1, Code: "denied"}
	view, d, err := r.members(ctx, true)
	if err != nil {
		reply.Code = "unavailable"
	} else if entry, ok := d.Entry(req.Node); ok && entry.JoinID == req.JoinID && entry.Peer.Key == fmt.Sprintf("%x", session.Peer().Key) {
		// Only this joining TLS key can request its own approved operation.
		switch req.Method {
		case "join":
			if req.Ack == nil {
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
			if req.Ack != nil && req.Ack.Schema == 1 && req.Ack.Cluster == d.Cluster && req.Ack.Node == req.Node && req.Ack.JoinID == req.JoinID && req.Ack.Key == [32]byte(session.Peer().Key) && ed25519.Verify(ed25519.PublicKey(req.Ack.Key[:]), membership.AckBytes(*req.Ack), req.Ack.Signature) {
				if membership.FullMember(entry) {
					reply.Code = "ok"
				} else {
					err = r.memberReport(ctx, view, control.MemberReport{Action: "installed", Node: req.Node, Expected: entry.Revision, Ack: req.Ack})
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
			} else {
				reply.Code = "unavailable"
			}
		}
	}
	raw, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.Membership, Kind: 2, Request: f.Request, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}})
}

// CallMembership sends once. Transport uncertainty never creates a new Join ID
// or silently resubmits a configuration change; the original shared A2 survives.
func CallMembership(ctx context.Context, mesh *mydcp.Transport, target mydcp.Peer, req MemberRequest) (MemberReply, error) {
	req.Schema = 1
	raw, err := json.Marshal(req)
	if err != nil {
		return MemberReply{}, err
	}
	digest := sha256.Sum256(raw)
	id := mesh.NextRequest()
	lifetime, _ := mydcp.NewRequest(fmt.Sprint(id), digest)
	conn, err := mesh.Dial(ctx, target)
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
	f := mydcp.Frame{Purpose: mydcp.Membership, Kind: 1, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err = mydcp.Encode(f); err != nil {
		return MemberReply{}, err
	}
	if err = ctx.Err(); err != nil {
		return MemberReply{}, err
	}
	lifetime, _ = lifetime.BeginSend()
	if err = mydcp.WriteFrame(stream, f); err != nil {
		return MemberReply{}, fmt.Errorf("%w: %v", cluster.ErrUnknown, err)
	}
	response, err := mydcp.ReadFrame(stream, 128<<10)
	if err != nil {
		return MemberReply{}, fmt.Errorf("%w: %v", cluster.ErrUnknown, err)
	}
	var reply MemberReply
	if response.Purpose != mydcp.Membership || response.Kind != 2 || response.Request != id || conn.Admit(response, mydcp.Membership, false) != nil || !bytes.Equal(response.Fields[1].Value, digest[:]) || memberDecode(response.Fields[0].Value, &reply) != nil || reply.Schema != 1 {
		return MemberReply{}, mydcp.ErrFrame
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
