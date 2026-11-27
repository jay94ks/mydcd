// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"io"

	"github.com/quic-go/quic-go"
)

type ManagementRequest struct {
	Schema  uint8
	Method  string
	Nonce   [16]byte
	Command []byte
	Key     string
	Latest  bool
	Input   []byte
}
type signedRequest struct {
	Caller    sfcp.Identity
	Body      []byte
	Signature []byte
	Forwarded bool
}

// signedRequestWire carries Body as itself, not base64 (design O4).
type signedRequestWire struct {
	Caller    sfcp.Identity
	Body      json.RawMessage
	Signature []byte
	Forwarded bool
}

func (r signedRequest) MarshalJSON() ([]byte, error) {
	body, err := sfcp.RawBody(r.Body)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedRequestWire{r.Caller, body, r.Signature, r.Forwarded})
}

func (r *signedRequest) UnmarshalJSON(raw []byte) error {
	var w signedRequestWire
	if err := sfcp.StrictJSON(raw, &w); err != nil {
		return err
	}
	*r = signedRequest{Caller: w.Caller, Body: bytes.Clone(w.Body), Signature: w.Signature, Forwarded: w.Forwarded}
	return nil
}

type ObjectView struct {
	Revision, Generation uint64
	Present              bool
	Value                []byte
}
type ManagementReply struct {
	Schema                               uint8
	Code, Message                        string
	Node, Leader                         string
	Local                                bool
	RaftIndex, AppliedTerm, CommandIndex uint64
	Committed                            *Committed    `json:",omitempty"`
	Object                               *ObjectView   `json:",omitempty"`
	Result                               *state.Result `json:",omitempty"`
	Found                                bool
	Data                                 json.RawMessage `json:",omitempty"`
}
type ManagementError struct {
	Code, Message string
	Phase         sfcp.Phase
}

func (e *ManagementError) Error() string {
	return fmt.Sprintf("%s: %s (request phase %d)", e.Code, e.Message, e.Phase)
}

func signingBytes(cluster [32]byte, body []byte) []byte {
	b := append([]byte("sfc-management-1"), cluster[:]...)
	return append(b, body...)
}
func strictJSON(b []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
func (e *Engine) ServeManagement() error {
	return e.mesh.On(sfcp.Management, e.management)
}
func (e *Engine) management(ctx context.Context, s *sfcp.Session, stream *quic.Stream, f sfcp.Frame) error {
	if f.Kind != sfcp.KindRequest && f.Kind != sfcp.KindManagementRead && f.Kind != sfcp.KindRelay {
		return sfcp.ErrFrame
	}
	var envelope signedRequest
	if err := strictJSON(f.Fields[0].Value, &envelope); err != nil {
		return err
	}
	digest := sha256.Sum256(envelope.Body)
	if !bytes.Equal(digest[:], f.Fields[1].Value) || !ed25519.Verify(ed25519.PublicKey(envelope.Caller[:]), signingBytes(e.cluster, envelope.Body), envelope.Signature) {
		return sfcp.ErrAdmission
	}
	if envelope.Forwarded {
		relay, current := e.mesh.Peer(s.Peer().Key)
		if f.Kind != sfcp.KindRelay || !current || !relay.Member {
			return sfcp.ErrAdmission
		}
	} else if f.Kind == sfcp.KindRelay || envelope.Caller != s.Peer().Key {
		return sfcp.ErrAdmission
	}
	var request ManagementRequest
	if err := strictJSON(envelope.Body, &request); err != nil {
		return err
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, envelope.Body) || request.Schema != 1 || request.Nonce == [16]byte{} {
		return sfcp.ErrFrame
	}
	if !envelope.Forwarded && (request.Method == "submit") != (f.Kind == sfcp.KindRequest) {
		return sfcp.ErrFrame
	}
	caller, approved := e.mesh.Peer(envelope.Caller)
	reply := ManagementReply{Schema: 1, Code: "denied", Message: "current caller permission denied", Node: e.id}
	if approved && ((request.Method == "submit" && caller.Manage) || (request.Method != "submit" && caller.Read)) {
		if (request.Latest || request.Method == "submit") && !e.IsLeader() {
			if envelope.Forwarded {
				reply.Code = "not-leader"
				reply.Message = "leader changed; no second forwarding"
			} else {
				address, id := e.Leader()
				target, ok := e.resolve(id, address)
				if !ok || id == "" || string(id) == e.id {
					reply.Code = "unavailable"
					reply.Message = "no authenticated leader"
				} else {
					envelope.Forwarded = true
					forward, phase, callErr := exchange(ctx, e.mesh, target, envelope, sfcp.KindRelay)
					if callErr == nil {
						reply = forward
					} else {
						reply.Code = "unknown"
						if phase == sfcp.NotSent {
							reply.Code = "unavailable"
						}
						reply.Message = callErr.Error()
					}
				}
			}
		} else {
			reply = e.executeManagement(ctx, envelope.Caller, request)
		}
	}
	_, leader := e.Leader()
	reply.Leader = string(leader)
	b, err := json.Marshal(reply)
	if err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.Management, Kind: sfcp.KindResponse, Request: f.Request, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: b}, {Tag: 2, Required: true, Value: digest[:]}}})
}
func (e *Engine) executeManagement(ctx context.Context, caller sfcp.Identity, r ManagementRequest) ManagementReply {
	reply := ManagementReply{Schema: 1, Code: "ok", Node: e.id}
	if r.Method == "submit" {
		if e.nodeCLIAllowed != nil {
			view, err := e.Read(ctx, false)
			if err != nil || !e.nodeCLIAllowed(view.State) {
				reply.Code, reply.Message = "denied", "node CLI operations are disabled; use an independently approved user operation"
				return reply
			}
		}
		c, err := state.DecodeCommand(r.Command)
		if err != nil || c.Actor != hex.EncodeToString(caller[:]) || !r.Latest {
			reply.Code = "invalid"
			reply.Message = "invalid command/caller/consistency"
			return reply
		}
		committed, err := e.Submit(ctx, c)
		if err != nil {
			reply.Code = "unavailable"
			if errors.Is(err, ErrUnknown) {
				reply.Code = "unknown"
			}
			reply.Message = err.Error()
			return reply
		}
		reply.Committed = &committed
		reply.RaftIndex = committed.RaftIndex
		reply.AppliedTerm = committed.Term
		reply.CommandIndex = committed.Result.Index
		return reply
	}
	v, err := e.Read(ctx, r.Latest)
	if err != nil {
		reply.Code = "unavailable"
		reply.Message = err.Error()
		return reply
	}
	actor := hex.EncodeToString(caller[:])
	rights, _, _, known := v.State.Principal(actor)
	current, approved := e.mesh.Peer(caller)
	if !approved || !current.Read || !current.Member && (!known || rights == 0) {
		reply.Code = "denied"
		reply.Message = "read permission revoked"
		return reply
	}
	reply.Local = v.Local
	reply.RaftIndex = v.RaftIndex
	reply.AppliedTerm = v.Term
	reply.CommandIndex = v.State.Index()
	if (r.Method == "get" || r.Method == "plan") && e.nodeCLIAllowed != nil && !e.nodeCLIAllowed(v.State) {
		reply.Code, reply.Message = "denied", "node CLI operations are disabled; use an authenticated user query"
		return reply
	}
	switch m, known := nodeMethods[r.Method]; {
	case known && m.kind == nodeReport:
		if e.commandModule == nil || !r.Latest || v.Local || !current.Member || r.Key != "" || r.Command != nil {
			reply.Code = "denied"
			break
		}
		command, err := e.commandModule(r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code = "denied"
			reply.Message = "current app command denied"
			break
		}
		committed, err := e.Submit(ctx, command)
		if err != nil {
			reply.Code = "unavailable"
			if errors.Is(err, ErrUnknown) {
				reply.Code = "unknown"
			}
			reply.Message = err.Error()
			break
		}
		reply.Committed = &committed
		reply.RaftIndex = committed.RaftIndex
		reply.AppliedTerm = committed.Term
		reply.CommandIndex = committed.Result.Index
	case known && m.kind == nodeLeaderRead:
		if e.readModule == nil || !r.Latest || v.Local || !current.Member || r.Key != "" || r.Command != nil {
			reply.Code = "denied"
			break
		}
		data, err := e.readModule(ctx, r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code = "denied"
			reply.Message = m.fail
		} else {
			reply.Data = data
		}
	case known && m.kind == nodeOwnerRead:
		if e.readModule == nil || r.Latest || !current.Member || r.Key != "" || r.Command != nil {
			reply.Code = "denied"
			break
		}
		data, err := e.readModule(ctx, r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code, reply.Message = "unavailable", m.fail
		} else {
			reply.Data = data
		}
	case known && m.kind == nodeVolumePermit:
		if e.readModule == nil || !r.Latest || !current.Member || r.Key != "" || v.Local {
			reply.Code = "denied"
			reply.Message = "fresh member volume read required"
			break
		}
		// Only this authenticated caller identity is passed to the adapter.
		// Request.Key cannot select or impersonate the owner.
		data, err := e.readModule(ctx, r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code = "denied"
			reply.Message = m.fail
		} else {
			reply.Data = data
		}
	default:
		e.builtinManagement(ctx, caller, r, v, &reply)
	}
	return reply
}

// builtinManagement serves the methods every node has: status, get, result,
// observe and plan.
func (e *Engine) builtinManagement(ctx context.Context, caller sfcp.Identity, r ManagementRequest, v View, reply *ManagementReply) {
	switch r.Method {
	case "status":
	case "get":
		if r.Key == "" || len(r.Key) > 512 {
			reply.Code = "invalid"
			reply.Message = "invalid object key"
			break
		}
		o := v.State.Object(r.Key)
		reply.Found = o.Revision != 0
		reply.Object = &ObjectView{o.Revision, o.Generation, o.Present, []byte(o.Value)}
	case "result":
		c, err := state.DecodeCommand(r.Command)
		if err != nil || c.Actor != hex.EncodeToString(caller[:]) {
			reply.Code = "invalid"
			reply.Message = "result query caller mismatch"
			break
		}
		result, found := v.State.LookupResult(c)
		reply.Found = found
		if found {
			reply.Result = &result
		} else {
			reply.Message = "no retained matching result; execution remains unknown"
		}
	case "observe", "plan":
		if e.readModule == nil || r.Method == "plan" && !r.Latest || r.Method == "observe" && r.Latest {
			reply.Code = "invalid"
			reply.Message = "module read unavailable or wrong consistency mode"
			break
		}
		data, err := e.readModule(ctx, r.Method, r.Key, r.Input, v)
		if err != nil {
			reply.Code = "unavailable"
			reply.Message = err.Error()
		} else {
			reply.Data = data
		}
	default:
		reply.Code = "invalid"
		reply.Message = "unsupported management method"
	}
}

// CallManagement signs the original payload once. The transport never retries a
// command, even if its first write is followed by a timeout or connection loss.
func CallManagement(ctx context.Context, mesh *sfcp.Transport, self *identity.Identity, cluster [32]byte, peer sfcp.Peer, r ManagementRequest) (ManagementReply, error) {
	if self == nil || sfcp.Identity(self.Public) != mesh.LocalKey() {
		return ManagementReply{}, sfcp.ErrAdmission
	}
	r.Schema = 1
	if _, err := rand.Read(r.Nonce[:]); err != nil {
		return ManagementReply{}, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return ManagementReply{}, err
	}
	envelope := signedRequest{Caller: sfcp.Identity(self.Public), Body: body, Signature: ed25519.Sign(self.Private, signingBytes(cluster, body))}
	kind := sfcp.KindManagementRead
	if r.Method == "submit" {
		kind = sfcp.KindRequest
	}
	reply, phase, err := exchange(ctx, mesh, peer, envelope, kind)
	if err != nil {
		return reply, &ManagementError{Code: "transport", Message: err.Error(), Phase: phase}
	}
	if reply.Code != "ok" {
		return reply, &ManagementError{Code: reply.Code, Message: reply.Message, Phase: phase}
	}
	return reply, nil
}
func exchange(ctx context.Context, mesh *sfcp.Transport, peer sfcp.Peer, envelope signedRequest, kind uint8) (ManagementReply, sfcp.Phase, error) {
	digest := sha256.Sum256(envelope.Body)
	id := mesh.NextRequest()
	request, _ := sfcp.NewRequest(fmt.Sprint(id), digest)
	fail := func(err error) (ManagementReply, sfcp.Phase, error) {
		return ManagementReply{}, request.Abandon().Phase(), err
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return fail(err)
	}
	frame := sfcp.Frame{Purpose: sfcp.Management, Kind: kind, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: b}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err = sfcp.Encode(frame); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	s, err := mesh.Dial(ctx, peer)
	if err != nil {
		return fail(err)
	}
	received, err := s.Call(ctx, frame, sfcp.CallOptions{Echo: digest[:], Sent: func() { request, _ = request.BeginSend() }})
	if err != nil {
		return fail(sfcp.CallCause(err))
	}
	var reply ManagementReply
	if err = strictJSON(received.Fields[0].Value, &reply); err != nil || reply.Schema != 1 {
		if err == nil {
			err = sfcp.ErrFrame
		}
		return fail(err)
	}
	if reply.Code == "unknown" {
		return reply, request.Abandon().Phase(), nil
	}
	request, err = request.Reply(fmt.Sprint(id), digest)
	return reply, request.Phase(), err
}
