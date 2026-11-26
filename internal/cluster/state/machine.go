// SPDX-License-Identifier: Apache-2.0

// Package state models deterministic application of already committed commands.
// It does not implement consensus, authentication, or durable storage.
package state

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"iter"
	"strings"
	"unicode/utf8"
)

var ErrOrder = errors.New("committed entries must be applied in order")

type Command struct {
	Actor, RequestID, Key, Value string
	Expected                     uint64
	Delete                       bool
	Epoch                        uint64
	Kind                         CommandKind
	Target                       string
	Rights                       Rights
}

type CommandKind uint8

const (
	Mutate CommandKind = iota
	SetRights
	RotateLedger
	Module
	ModuleWindow
	ModuleReport
	ModuleUpload
	ModuleAppCAS
)

// Preserve the encoded kind and existing down-operation source compatibility.
const ModuleAppDown = ModuleAppCAS

type Rights uint8

const (
	Network Rights = 1 << iota
	Workload
	Ingress
	Admin
)
const allRights = Network | Workload | Ingress | Admin

func namespaceRights(key string) Rights {
	for prefix, right := range map[string]Rights{"network/": Network, "workload/": Workload, "ingress/": Ingress} {
		if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
			return right
		}
	}
	return 0
}

const LedgerLimit = 256

type principal struct {
	Rights          Rights
	Epoch, Revision uint64
}

type Object struct {
	Revision, Generation uint64
	Value                string
	Present              bool
}

type Code uint8

const (
	Applied Code = iota
	ConditionFailed
	Invalid
	RequestConflict
	Forbidden
	Expired
	LedgerFull
)

type Result struct {
	Reason               string `json:",omitempty"`
	Code                 Code
	Index                uint64
	Revision, Generation uint64
}

type requestKey struct{ actor, id string }
type receipt struct {
	digest [32]byte
	result Result
}

type State struct {
	index          uint64
	objects        map[string]Object
	requests       map[requestKey]receipt
	principals     map[string]principal
	window         *moduleWindow
	reportReceipts map[requestKey]reportReceipt
	reportFloors   map[reportRoot]uint64
}

// New establishes the one genesis administrator. Later policy is committed input.
func New(admin string) (State, error) {
	if admin == "" || len(admin) > 256 || !utf8.ValidString(admin) {
		return State{}, errors.New("invalid genesis administrator")
	}
	return State{principals: map[string]principal{admin: {Rights: allRights, Epoch: 1}}}, nil
}

func (s State) Index() uint64            { return s.index }
func (s State) Object(key string) Object { return s.objects[key] }

// Objects returns an owned view; callers cannot mutate the immutable FSM maps.
func (s State) Objects(prefix string) map[string]Object {
	v := map[string]Object{}
	for key, o := range s.objects {
		if strings.HasPrefix(key, prefix) {
			v[key] = o
		}
	}
	return v
}

// RangeObjects visits the matching keys and Object values in this immutable
// snapshot without copying its map. Like Objects, it includes tombstones and
// has unspecified order. Values are copies; subsequent State candidates do not
// change this snapshot or an iterator already obtained from it.
func (s State) RangeObjects(prefix string) iter.Seq2[string, Object] {
	return func(yield func(string, Object) bool) {
		for key, object := range s.objects {
			if strings.HasPrefix(key, prefix) && !yield(key, object) {
				return
			}
		}
	}
}

func (s State) ReceiptCount() int { return len(s.requests) }

// LookupResult never re-executes an absent/expired request. A false result is
// not evidence that the operation did not commit in an earlier ledger epoch.
func (s State) LookupResult(c Command) (Result, bool) {
	if r, ok := s.windowResult(c); ok {
		return r, true
	}
	if s.ModuleExpired(c) {
		return Result{}, false
	}
	p, known := s.principals[c.Actor]
	r, found := s.requests[requestKey{c.Actor, c.RequestID}]
	if !known || p.Epoch != c.Epoch || !found || r.digest != Digest(c) {
		return Result{}, false
	}
	return r.result, true
}
func (s State) Principal(actor string) (Rights, uint64, uint64, bool) {
	p, ok := s.principals[actor]
	return p.Rights, p.Epoch, p.Revision, ok
}
func Digest(c Command) [32]byte { return commandDigest(c) }

func commandDigest(c Command) [32]byte {
	var b []byte
	for _, field := range []string{c.Actor, c.RequestID, c.Key, c.Value} {
		b = binary.LittleEndian.AppendUint64(b, uint64(len(field)))
		b = append(b, field...)
	}
	b = binary.LittleEndian.AppendUint64(b, c.Expected)
	b = binary.LittleEndian.AppendUint64(b, c.Epoch)
	b = append(b, byte(c.Kind), byte(c.Rights))
	b = binary.LittleEndian.AppendUint64(b, uint64(len(c.Target)))
	b = append(b, c.Target...)
	if c.Delete {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return sha256.Sum256(b)
}

func clone(s State) State {
	n := State{index: s.index, objects: make(map[string]Object, len(s.objects)), requests: make(map[requestKey]receipt, len(s.requests)), principals: make(map[string]principal, len(s.principals))}
	n.reportReceipts = make(map[requestKey]reportReceipt, len(s.reportReceipts))
	n.reportFloors = make(map[reportRoot]uint64, len(s.reportFloors))
	for key, value := range s.reportReceipts {
		n.reportReceipts[key] = value
	}
	for key, value := range s.reportFloors {
		n.reportFloors[key] = value
	}
	if s.window != nil {
		window := *s.window
		n.window = &window
	}
	for k, v := range s.objects {
		n.objects[k] = v
	}
	for k, v := range s.requests {
		n.requests[k] = v
	}
	for k, v := range s.principals {
		n.principals[k] = v
	}
	return n
}

// Apply returns a candidate; the caller publishes it only after atomic persistence.
// Actor is an authenticated full-key identity supplied by the MYDCP adapter, never
// a trusted field copied from an unauthenticated payload. Replicas recheck policy.
func Apply(s State, index uint64, c Command) (State, Result, error) {
	return ApplyChecked(s, index, c, nil)
}

// Validator is deterministic module policy. It runs inside committed apply,
// after authorization/CAS and before the object/result transaction is published.
// Rejected policy is a retained Invalid result, not a fatal storage error.
type Validator func(before, after State, c Command) error

func ApplyChecked(s State, index uint64, c Command, validate Validator) (State, Result, error) {
	return ApplyReduced(s, index, c, validate, nil)
}

// ApplyReduced keeps module metadata, the original request receipt and the
// committed ordinal in the same immutable candidate. Reducers authorize their
// own typed commands; legacy node rights never grant user/tenant permissions.
func ApplyReduced(s State, index uint64, c Command, validate Validator, reduce Reducer) (State, Result, error) {
	return ApplyAdmitted(s, index, c, validate, reduce, nil)
}

func ApplyAdmitted(s State, index uint64, c Command, validate Validator, reduce Reducer, admit ModuleAuthorizer) (State, Result, error) {
	return ApplyDelegated(s, index, c, validate, reduce, admit, nil)
}

// MutationAuthorizer authorizes only an exact already-persisted delegated
// mutation. It grants no rights, cannot register an actor or authorize admin
// commands, and does not replace the ordinary CAS/receipt/validator transaction.
type MutationAuthorizer func(State, Command) bool

func ApplyDelegated(s State, index uint64, c Command, validate Validator, reduce Reducer, admit ModuleAuthorizer, delegate MutationAuthorizer) (State, Result, error) {
	return ApplyTransactional(s, index, c, validate, reduce, admit, delegate, nil)
}

// ApplyTransactional preserves one ordinal/receipt while an explicitly bound
// policy can admit related control namespaces and exact existing native sources
// for explicitly authorized, validated cleanup in the same typed module patch.
func ApplyTransactional(s State, index uint64, c Command, validate Validator, reduce Reducer, admit ModuleAuthorizer, delegate MutationAuthorizer, admitPatch ModulePatchAuthorizer) (State, Result, error) {
	if index == 0 || s.index == ^uint64(0) || index != s.index+1 {
		return s, Result{}, ErrOrder
	}
	n := clone(s)
	n.index = index
	invalid := Result{Code: Invalid, Index: index}
	if c.Actor == "" || len(c.Actor) > 256 || !utf8.ValidString(c.Actor) || c.RequestID == "" || len(c.RequestID) > 256 || !utf8.ValidString(c.RequestID) || c.Epoch == 0 {
		return n, invalid, nil
	}
	if result, ok := s.windowResult(c); ok {
		return n, result, nil
	}
	if s.ModuleExpired(c) {
		return n, Result{Code: Expired, Index: index}, nil
	}
	if c.Kind == ModuleWindow {
		return applyModuleWindow(s, n, index, c, validate, reduce, admit)
	}
	if c.Kind == ModuleReport && !validReport(c, s.index) {
		return n, invalid, nil
	}
	// Only an explicitly admitted, immutable user target may use its own
	// typed CAS instead of the module root. Known actors are rechecked too.
	if (c.Kind == ModuleUpload || c.Kind == ModuleAppDown) && ((c.Key != "control/apps" && (c.Kind != ModuleUpload || c.Key != "control/image-builds")) || !strings.HasPrefix(c.Actor, "user/") || reduce == nil || admit == nil) {
		return n, Result{Code: Forbidden, Index: index}, nil
	}
	p, known := s.principals[c.Actor]
	if !known {
		if c.Kind != Module && c.Kind != ModuleReport && c.Kind != ModuleUpload && c.Kind != ModuleAppDown || c.Epoch != s.ModuleEpoch() || !moduleActor(c.Actor) || len(s.principals) >= ModuleActorLimit || reduce == nil || admit == nil || !admit(s, c) {
			return n, Result{Code: Forbidden, Index: index}, nil
		}
		p = principal{Epoch: s.ModuleEpoch(), Revision: index}
		n.principals[c.Actor] = p
	}
	if c.Epoch != p.Epoch {
		return n, Result{Code: Expired, Index: index}, nil
	}
	key := requestKey{c.Actor, c.RequestID}
	digest := commandDigest(c)
	if old, ok := s.requests[key]; ok {
		if old.digest != digest {
			return n, Result{Code: RequestConflict, Index: index}, nil
		}
		return n, old.result, nil
	}
	if (c.Kind == ModuleUpload || c.Kind == ModuleAppDown) && (p.Rights != 0 || !admit(s, c)) {
		return n, Result{Code: Forbidden, Index: index}, nil
	}
	if c.Kind == ModuleReport && (p.Rights != 0 || admit == nil || !admit(s, c)) {
		return n, Result{Code: Forbidden, Index: index}, nil
	}
	if c.Kind == ModuleReport && !s.reportRootAvailable(c.Actor, c.Key) {
		return n, Result{Code: LedgerFull, Index: index}, nil
	}
	count := 0
	for k := range s.requests {
		if k.actor == c.Actor {
			count++
		}
	}
	// Rotation is the explicit escape from a full ledger. Old epochs can never
	// execute again, including after snapshot/restart. No wall-clock eviction.
	if count >= LedgerLimit && c.Kind != ModuleReport && !(c.Kind == RotateLedger && c.Target == c.Actor) {
		return n, Result{Code: LedgerFull, Index: index}, nil
	}
	result := Result{Code: Invalid, Index: index}
	validMutation := c.Kind == Mutate && c.Target == "" && c.Rights == 0 && len(c.Key) <= 512 && utf8.ValidString(c.Key) && len(c.Value) <= 64*1024 && (!c.Delete || c.Value == "")
	required := namespaceRights(c.Key)
	if c.Kind == Module || c.Kind == ModuleReport || c.Kind == ModuleUpload || c.Kind == ModuleAppDown {
		n, result = applyModule(s, n, index, c, validate, reduce, admitPatch)
	} else if validMutation && required != 0 {
		if p.Rights&required == 0 && p.Rights&Admin == 0 && !(p.Rights == 0 && (strings.HasPrefix(c.Actor, "user/") || strings.HasPrefix(c.Actor, "node/")) && delegate != nil && delegate(s, c)) {
			result.Code = Forbidden
			n.requests[key] = receipt{digest, result}
			return n, result, nil
		}
		old := s.objects[c.Key]
		result.Revision, result.Generation = old.Revision, old.Generation
		result.Code = ConditionFailed
		if c.Expected == old.Revision && (!c.Delete || old.Present) {
			object := Object{Revision: index, Generation: old.Generation, Value: c.Value, Present: !c.Delete}
			if !c.Delete && !old.Present {
				object.Generation = index
			}
			n.objects[c.Key] = object
			result = Result{Code: Applied, Index: index, Revision: index, Generation: object.Generation}
			if validate != nil && validate(s, n, c) != nil {
				if original, exists := s.objects[c.Key]; exists {
					n.objects[c.Key] = original
				} else {
					delete(n.objects, c.Key)
				}
				result = Result{Code: Invalid, Index: index, Revision: old.Revision, Generation: old.Generation}
			}
		}
	} else if (c.Kind == SetRights || c.Kind == RotateLedger) && c.Key == "" && c.Value == "" && !c.Delete && c.Target != "" && len(c.Target) <= 256 && utf8.ValidString(c.Target) && c.Rights & ^allRights == 0 && (c.Kind != RotateLedger || c.Rights == 0) {
		result.Code = Forbidden
		if p.Rights&Admin != 0 {
			target, exists := s.principals[c.Target]
			result.Code = ConditionFailed
			if c.Expected == target.Revision && (c.Kind != RotateLedger || (exists && target.Epoch < ^uint64(0))) {
				if c.Kind == RotateLedger {
					target.Epoch++
					for k := range n.requests {
						if k.actor == c.Target {
							delete(n.requests, k)
						}
					}
				} else {
					// Never revoke the last administrator.
					admins := 0
					for _, v := range s.principals {
						if v.Rights&Admin != 0 {
							admins++
						}
					}
					if target.Rights&Admin != 0 && c.Rights&Admin == 0 && admins == 1 {
						n.requests[key] = receipt{digest, result}
						return n, result, nil
					}
					target.Rights = c.Rights
					if !exists {
						target.Epoch = 1
					}
				}
				target.Revision = index
				n.principals[c.Target] = target
				result = Result{Code: Applied, Index: index, Revision: index, Generation: target.Epoch}
			}
		}
	}
	// Invalid requests without an identity cannot occupy a shared deduplication key.
	// A self-rotation's old request must not reoccupy the new epoch ledger.
	if c.Kind == ModuleReport && count >= LedgerLimit {
		if result.Code != Applied || !collectReports(&n, c.Actor) {
			unchanged := clone(s)
			unchanged.index = index
			return unchanged, Result{Code: LedgerFull, Index: index}, nil
		}
	}
	if !(c.Kind == RotateLedger && c.Target == c.Actor && result.Code == Applied) {
		n.requests[key] = receipt{digest: digest, result: result}
		if c.Kind == ModuleReport {
			n.reportReceipts[key] = reportReceipt{Key: c.Key, Expected: c.Expected}
		}
	}
	return n, result, nil
}
