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
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
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
	Caller    mydcp.Identity
	Body      []byte
	Signature []byte
	Forwarded bool
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
	Phase         mydcp.Phase
}

func (e *ManagementError) Error() string {
	return fmt.Sprintf("%s: %s (request phase %d)", e.Code, e.Message, e.Phase)
}

func signingBytes(cluster [32]byte, body []byte) []byte {
	b := append([]byte("mydc-management-1"), cluster[:]...)
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
	return e.mesh.On(mydcp.Management, e.management)
}
func (e *Engine) management(ctx context.Context, s *mydcp.Session, stream *quic.Stream, f mydcp.Frame) error {
	if f.Kind != 1 && f.Kind != 3 && f.Kind != 4 {
		return mydcp.ErrFrame
	}
	var envelope signedRequest
	if err := strictJSON(f.Fields[0].Value, &envelope); err != nil {
		return err
	}
	digest := sha256.Sum256(envelope.Body)
	if !bytes.Equal(digest[:], f.Fields[1].Value) || !ed25519.Verify(ed25519.PublicKey(envelope.Caller[:]), signingBytes(e.cluster, envelope.Body), envelope.Signature) {
		return mydcp.ErrAdmission
	}
	if envelope.Forwarded {
		relay, current := e.mesh.Peer(s.Peer().Key)
		if f.Kind != 4 || !current || !relay.Member {
			return mydcp.ErrAdmission
		}
	} else if f.Kind == 4 || envelope.Caller != s.Peer().Key {
		return mydcp.ErrAdmission
	}
	var request ManagementRequest
	if err := strictJSON(envelope.Body, &request); err != nil {
		return err
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, envelope.Body) || request.Schema != 1 || request.Nonce == [16]byte{} {
		return mydcp.ErrFrame
	}
	if !envelope.Forwarded && (request.Method == "submit") != (f.Kind == 1) {
		return mydcp.ErrFrame
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
					forward, phase, callErr := exchange(ctx, e.mesh, target, envelope, 4)
					if callErr == nil {
						reply = forward
					} else {
						reply.Code = "unknown"
						if phase == mydcp.NotSent {
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
	return mydcp.WriteFrame(stream, mydcp.Frame{Purpose: mydcp.Management, Kind: 2, Request: f.Request, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: b}, {Tag: 2, Required: true, Value: digest[:]}}})
}
func (e *Engine) executeManagement(ctx context.Context, caller mydcp.Identity, r ManagementRequest) ManagementReply {
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
	method := r.Method
	if _, report := ReportMethod(method); report {
		method = reportKind
	}
	switch method {
	case reportKind:
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
	case "app-observation-renew", "node-shell-owner-view", "node-shell-permit", "node-identity-activation", "node-diagnostics-permit", "lifecycle-source-version-permit", "service-call-permit", "image-build-base-work", "image-build-registry-permit", "image-build-secret-inputs", "image-build-cache-prune-work", "image-build-job-work", "image-build-artifact-work", "image-build-io-permit", "image-build-part-permit", "registry-maintenance-work", "image-cache-plan-permit", "image-cache-work", "tunnel-reconnect-work", "compact-work", "task-restart-permit", "container-session-plan", "container-session-permit", "container-read-permit", "tenant-retirement-work", "node-runtime-work", "route-native-permit", "route-work", "registry-image-permit", "registry-work", "external-registry-work", "checker-cache-gc-fence", "checker-probe-permit", "checker-shutdown-permit", "checker-build-permit", "checker-source-permit", "checker-artifact-permit", "app-native-permit", "app-binding-permit", "app-input-read-permit", "app-delivery-permit", "app-delivery-sync-work", "app-result", "vault-write-permit", "vault-approval-permit", "vault-approval-result", "volume-file-work", "volume-usage-permit", "volume-backup-permit", "volume-restore-permit", "volume-delete-permit", "volume-retained-delete-permit", "volume-create-permit", "volume-move-permit", "node-storage-permit":
		if e.readModule == nil || !r.Latest || v.Local || !current.Member || r.Key != "" || r.Command != nil {
			reply.Code = "denied"
			break
		}
		data, err := e.readModule(ctx, r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code = "denied"
			reply.Message = "current app read denied"
		} else {
			reply.Data = data
		}
	case "node-diagnostics-owner", "lifecycle-source-version-owner", "ingress-observe", "image-build-base-tls-owner", "image-build-registry-tls-owner", "image-build-base-token-owner", "image-build-base-owner", "image-build-caches-owner", "image-build-cache-owner", "image-build-logs-owner", "image-build-publication-owner", "image-build-git-owner", "image-build-draft-owner", "image-build-content-owner", "image-build-source-owner", "image-build-owner", "registry-prune-owner", "registry-catalog-owner", "event-receipt", "image-cache-native-plan", "external-registry-probe", "image-resolve-owner", "container-observe", "route-flow-observe", "checker-cache-observe", "volume-usage-observe", "volume-backup-source-observe", "volume-move-recipe-observe", "volume-move-inputs-observe", "node-storage-space-observe":
		// Node-local readback deliberately stays on the native owner. It is not
		// an authority read: that owner obtains fresh quorum permits itself.
		if e.readModule == nil || r.Latest || !current.Member || r.Key != "" || r.Command != nil {
			reply.Code = "denied"
			break
		}
		data, err := e.readModule(ctx, r.Method, hex.EncodeToString(caller[:]), r.Input, v)
		if err != nil {
			reply.Code, reply.Message = "unavailable", "volume observation unavailable"
			if r.Method == "image-build-publication-owner" {
				reply.Message = "image build publication observation unavailable"
			}
			if r.Method == "image-build-base-owner" {
				reply.Message = "image build base resolution unavailable"
			}
			if r.Method == "image-build-base-tls-owner" || r.Method == "image-build-registry-tls-owner" {
				reply.Message = "image build registry trust unavailable"
			}
			if r.Method == "image-build-base-token-owner" {
				reply.Message = "image build base authentication unavailable"
			}
			if r.Method == "image-build-cache-owner" || r.Method == "image-build-caches-owner" {
				reply.Message = "image build cache observation unavailable"
			}
			if r.Method == "image-build-logs-owner" {
				reply.Message = "image build logs unavailable"
			}
			if r.Method == "route-flow-observe" {
				reply.Message = "route flow observation unavailable"
			}
			if r.Method == "checker-cache-observe" {
				reply.Message = "checker cache observation unavailable"
			}
		} else {
			reply.Data = data
		}
	case "volume-permit":
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
			reply.Message = "current volume activation denied"
		} else {
			reply.Data = data
		}
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
	return reply
}

// reportKind stands for every ReportMethod in the management switch. It is
// not a valid method name.
const reportKind = "\x00report"

// CallManagement signs the original payload once. The transport never retries a
// command, even if its first write is followed by a timeout or connection loss.
func CallManagement(ctx context.Context, mesh *mydcp.Transport, self *identity.Identity, cluster [32]byte, peer mydcp.Peer, r ManagementRequest) (ManagementReply, error) {
	if self == nil || mydcp.Identity(self.Public) != mesh.LocalKey() {
		return ManagementReply{}, mydcp.ErrAdmission
	}
	r.Schema = 1
	if _, err := rand.Read(r.Nonce[:]); err != nil {
		return ManagementReply{}, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return ManagementReply{}, err
	}
	envelope := signedRequest{Caller: mydcp.Identity(self.Public), Body: body, Signature: ed25519.Sign(self.Private, signingBytes(cluster, body))}
	kind := uint8(3)
	if r.Method == "submit" {
		kind = 1
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
func exchange(ctx context.Context, mesh *mydcp.Transport, peer mydcp.Peer, envelope signedRequest, kind uint8) (ManagementReply, mydcp.Phase, error) {
	digest := sha256.Sum256(envelope.Body)
	id := mesh.NextRequest()
	request, _ := mydcp.NewRequest(fmt.Sprint(id), digest)
	fail := func(err error) (ManagementReply, mydcp.Phase, error) {
		return ManagementReply{}, request.Abandon().Phase(), err
	}
	b, err := json.Marshal(envelope)
	if err != nil {
		return fail(err)
	}
	frame := mydcp.Frame{Purpose: mydcp.Management, Kind: kind, Request: id, Fields: []mydcp.Field{{Tag: 1, Required: true, Value: b}, {Tag: 2, Required: true, Value: digest[:]}}}
	if _, err = mydcp.Encode(frame); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	s, err := mesh.Dial(ctx, peer)
	if err != nil {
		return fail(err)
	}
	stream, err := s.Open(ctx)
	if err != nil {
		return fail(err)
	}
	defer stream.CancelRead(0)
	defer stream.Close()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	request, _ = request.BeginSend()
	if err = mydcp.WriteFrame(stream, frame); err != nil {
		return fail(err)
	}
	received, err := mydcp.ReadFrame(stream, 128<<10)
	if err != nil {
		return fail(err)
	}
	if received.Request != id || received.Purpose != mydcp.Management || received.Kind != 2 || s.Admit(received, mydcp.Management, false) != nil || !bytes.Equal(received.Fields[1].Value, digest[:]) {
		return fail(mydcp.ErrAdmission)
	}
	var reply ManagementReply
	if err = strictJSON(received.Fields[0].Value, &reply); err != nil || reply.Schema != 1 {
		if err == nil {
			err = mydcp.ErrFrame
		}
		return fail(err)
	}
	if reply.Code == "unknown" {
		return reply, request.Abandon().Phase(), nil
	}
	request, err = request.Reply(fmt.Sprint(id), digest)
	return reply, request.Phase(), err
}
