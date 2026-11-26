// SPDX-License-Identifier: Apache-2.0

// Package volumes is the deterministic cold-volume ownership core. Candidates
// and command results must be committed together by the FSM. Signed native
// facts are inputs, not substitutes for an adapter actually observing/syncing
// them. In particular a Raft owner record does not fence a Docker process.
package volumes

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

var ErrVolume = errors.New("volume ownership, pin or migration conflict")
var ErrNotMovable = errors.New("VOLUME_NOT_MOVABLE: node-fixed volume cannot change owner")
var ErrUnregisterRequired = errors.New("node-fixed volume requires explicit unregister; data deletion is forbidden")

const maxRecords = 256

type Scope struct {
	Cluster         [32]byte
	Tenant, App, ID string
	Generation      uint64
	Registry        string `json:",omitempty"`
}

// An empty app/registry selects the pre-registered tenant node-fixed namespace.
// Registry data uses a distinct management namespace, never a synthetic app.
func (s Scope) TenantManaged() bool   { return s.App == "" && s.Registry == "" }
func (s Scope) RegistryManaged() bool { return s.Registry != "" }
func (s Scope) Key() string {
	if s.RegistryManaged() {
		return s.Tenant + "/@registry/" + s.Registry + "/" + s.ID
	}
	if s.TenantManaged() {
		return s.Tenant + "/@tenant/" + s.ID
	}
	return s.Tenant + "/" + s.App + "/" + s.ID
}
func FixedNativeKey(s Scope) string {
	if !validScope(s) || !s.TenantManaged() {
		return ""
	}
	return "fixed-volume/" + s.Tenant + "/" + s.ID + "/" + strconv.FormatUint(s.Generation, 10)
}

func FixedNativeName(s Scope) string {
	if FixedNativeKey(s) == "" {
		return ""
	}
	raw, _ := json.Marshal(s)
	digest := sha256.Sum256(append([]byte("mydc-fixed-native-name-1\x00"), raw...))
	return "mydc-fixed-" + hex.EncodeToString(digest[:])
}

type Owner struct {
	Node   string
	Key    [32]byte
	Native string
}
type Consumer struct {
	ID            string
	Generation    uint64 // task generation, not volume generation
	Writable      bool
	Lease         reconcile.Lease
	Owner         Owner
	OwnerRevision uint64
}
type Floor struct {
	ID         string
	Generation uint64
}
type Retained struct {
	Owner         Owner
	OwnerRevision uint64
	Move          string
}

// State is immutable, including slices in snapshots and returned views. Native
// identities are reserved for the lifetime of this logical volume; a reverse
// move creates a fresh native copy instead of adopting a stale retained one.
type State struct{ d snapshot }
type snapshot struct {
	Schema                  uint8
	Scope                   Scope
	Fixed                   bool `json:",omitempty"`
	Revision, OwnerRevision uint64
	Owner                   Owner
	Retain                  bool
	Pins                    reconcile.LeaseJournal
	Consumers               []Consumer
	Floors                  []Floor
	Moves                   []Move
	Active                  string
	Used                    []Owner
	Retained                []Retained
	Deletion                *Deletion `json:",omitempty"`
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}
func native(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_' || b == '.') {
			return false
		}
	}
	return s != "." && s != ".."
}
func validScope(s Scope) bool {
	namespace := s.Registry == "" && (s.App == "" || identifier(s.App)) || s.App == "" && identifier(s.Registry)
	return s.Cluster != ([32]byte{}) && identifier(s.Tenant) && namespace && identifier(s.ID) && s.Generation > 0
}
func validOwner(o Owner) bool    { return identifier(o.Node) && o.Key != ([32]byte{}) && native(o.Native) }
func sameNative(a, b Owner) bool { return a.Node == b.Node && a.Native == b.Native }
func validConsumer(c Consumer, scope Scope) bool {
	return identifier(c.ID) && c.Generation > 0 && c.Lease.Generation == scope.Generation && c.Lease.Token > 0 && validOwner(c.Owner) && c.OwnerRevision > 0
}

// New takes an original native identity resolved by the managed-volume adapter.
// It does not create/adopt an Engine volume or claim an enforced disk quota.
func New(c access.Catalog, actor string, scope Scope, owner Owner, readers int) (State, error) {
	if scope.TenantManaged() {
		return State{}, ErrVolume
	}
	return newState(c, actor, scope, owner, readers, false)
}

func NewFixed(c access.Catalog, actor string, scope Scope, owner Owner, readers int) (State, error) {
	if !scope.TenantManaged() {
		return State{}, ErrVolume
	}
	return newState(c, actor, scope, owner, readers, true)
}

func newState(c access.Catalog, actor string, scope Scope, owner Owner, readers int, fixed bool) (State, error) {
	if c.Authorize(actor, scope.Tenant, access.ManageVolumes, owner.Node) != nil {
		return State{}, access.ErrDenied
	}
	if !validScope(scope) || !validOwner(owner) || readers < 1 || readers > maxRecords {
		return State{}, ErrVolume
	}
	p, e := reconcile.NewLeases(scope.Generation, readers)
	if e != nil {
		return State{}, e
	}
	return State{snapshot{Schema: 1, Scope: scope, Fixed: fixed, Revision: 1, OwnerRevision: 1, Owner: owner, Retain: true, Pins: p.Checkpoint(), Used: []Owner{owner}}}, nil
}
func ownSnapshot(d snapshot) snapshot {
	if d.Deletion != nil {
		x := *d.Deletion
		if x.Gone != nil {
			g := *x.Gone
			g.Signature = slices.Clone(g.Signature)
			x.Gone = &g
		}
		d.Deletion = &x
	}
	d.Pins.Active = slices.Clone(d.Pins.Active)
	d.Consumers = slices.Clone(d.Consumers)
	d.Floors = slices.Clone(d.Floors)
	d.Used = slices.Clone(d.Used)
	d.Retained = slices.Clone(d.Retained)
	d.Moves = slices.Clone(d.Moves)
	for i := range d.Moves {
		d.Moves[i] = ownMove(d.Moves[i])
	}
	return d
}
func (s State) clone() (State, error) {
	if s.d.Schema != 1 || s.d.Revision == ^uint64(0) {
		return s, ErrVolume
	}
	d := ownSnapshot(s.d)
	d.Revision++
	return State{d}, nil
}
func (s State) Revision() uint64       { return s.d.Revision }
func (s State) Scope() Scope           { return s.d.Scope }
func (s State) Fixed() bool            { return s.d.Fixed }
func (s State) Owner() (Owner, uint64) { return s.d.Owner, s.d.OwnerRevision }
func (s State) Consumers() []Consumer  { return slices.Clone(s.d.Consumers) }

// ConflictsWithForeignConsumer checks only the current reader/writer matrix.
// A plan has a stable consumer ID, but no committed task generation or lease;
// its own original consumer is therefore left to Acquire's exact replay and
// generation checks. An unclosed foreign consumer remains conflicting even
// when its native process has not been observed recently.
func (s State) ConflictsWithForeignConsumer(id string, writable bool) bool {
	return slices.ContainsFunc(s.d.Consumers, func(p Consumer) bool {
		return foreignConsumerConflict(p, id, writable)
	})
}

// ForeignConsumerConflicts returns owned current pins matching the very same
// matrix as Acquire. It conveys no authorization to release or replace them.
func (s State) ForeignConsumerConflicts(id string, writable bool) []Consumer {
	var out []Consumer
	for _, p := range s.d.Consumers {
		if foreignConsumerConflict(p, id, writable) {
			out = append(out, p)
		}
	}
	return out
}

func foreignConsumerConflict(p Consumer, id string, writable bool) bool {
	return p.ID != id && (writable || p.Writable)
}

func (s State) Retained() []Retained { return slices.Clone(s.d.Retained) }
func (s State) RetainsData() bool    { return s.d.Retain && !s.Deleted() }
func (s State) Moves() []Move {
	out := make([]Move, len(s.d.Moves))
	for i, m := range s.d.Moves {
		out[i] = ownMove(m)
	}
	return out
}
func (s State) Move(id string) (Move, bool) {
	i := s.moveIndex(id)
	if i < 0 {
		return Move{}, false
	}
	return ownMove(s.d.Moves[i]), true
}
func (s State) moveIndex(id string) int {
	return slices.IndexFunc(s.d.Moves, func(m Move) bool { return m.Binding.ID == id })
}
func (s State) consumerIndex(c Consumer) int { return slices.Index(s.d.Consumers, c) }

// CheckActivation is metadata admission for a NEW mount/start or reactivation.
// A running original user may keep its pin during a move, but must not use it
// to mount/start again. Actual Start still requires the fresh quorum permit
// and the synced local gate in gate.go.
func (s State) CheckActivation(c Consumer) error {
	if !s.startAllowed() || c.Owner != s.d.Owner || c.OwnerRevision != s.d.OwnerRevision || s.consumerIndex(c) < 0 {
		return ErrVolume
	}
	return nil
}
func (s State) startAllowed() bool {
	if s.d.Deletion != nil {
		return false
	}
	if s.d.Active == "" {
		return true
	}
	i := s.moveIndex(s.d.Active)
	if i < 0 {
		return false
	}
	return s.d.Moves[i].Phase == Activating || s.d.Moves[i].Phase == Active
}

// AcquireCold uses the same reader journal and refuses parallel migration.
func (s State) AcquireCold(c access.Catalog, actor string, expected uint64, id string, generation uint64) (State, Consumer, error) {
	if s.d.Active != "" {
		return s, Consumer{}, ErrVolume
	}
	return s.Acquire(c, actor, expected, id, generation, false)
}

// Acquire pins a task before any mount/start. Read-only tasks and cold readers
// may coexist with readers, never with a writer. An unknown start retains
// this exact pin until positive original-node closure; absence is insufficient.
func (s State) Acquire(c access.Catalog, actor string, expected uint64, id string, taskGeneration uint64, writable bool) (State, Consumer, error) {
	return s.acquire(c, actor, expected, id, taskGeneration, writable, s.startAllowed())
}

func (s State) acquire(c access.Catalog, actor string, expected uint64, id string, taskGeneration uint64, writable, allowed bool) (State, Consumer, error) {
	if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, s.d.Owner.Node) != nil {
		return s, Consumer{}, access.ErrDenied
	}
	return s.acquireAuthorized(expected, id, taskGeneration, writable, allowed)
}

func (s State) acquireAuthorized(expected uint64, id string, taskGeneration uint64, writable, allowed bool) (State, Consumer, error) {
	for _, p := range s.d.Consumers {
		if p.ID == id && p.Generation == taskGeneration && p.Writable == writable {
			return s, p, nil
		}
	}
	if expected != s.d.Revision || !identifier(id) || taskGeneration == 0 || !allowed {
		return s, Consumer{}, ErrVolume
	}
	for _, f := range s.d.Floors {
		if f.ID == id && taskGeneration <= f.Generation {
			return s, Consumer{}, ErrVolume
		}
	}
	if s.ConflictsWithForeignConsumer(id, writable) || slices.ContainsFunc(s.d.Consumers, func(p Consumer) bool { return p.ID == id }) {
		return s, Consumer{}, ErrVolume
	}
	if len(s.d.Floors) >= maxRecords && !slices.ContainsFunc(s.d.Floors, func(f Floor) bool { return f.ID == id }) {
		return s, Consumer{}, ErrVolume
	}
	pins, e := reconcile.RestoreLeases(s.d.Pins)
	if e != nil {
		return s, Consumer{}, e
	}
	l, e := pins.Acquire()
	if e != nil {
		return s, Consumer{}, e
	}
	n, e := s.clone()
	if e != nil {
		return s, Consumer{}, e
	}
	p := Consumer{id, taskGeneration, writable, l, s.d.Owner, s.d.OwnerRevision}
	n.d.Consumers = append(n.d.Consumers, p)
	n.d.Pins = pins.Checkpoint()
	found := false
	for i, f := range n.d.Floors {
		if f.ID == id {
			n.d.Floors[i].Generation = taskGeneration
			found = true
		}
	}
	if !found {
		n.d.Floors = append(n.d.Floors, Floor{id, taskGeneration})
		slices.SortFunc(n.d.Floors, func(a, b Floor) int { return strings.Compare(a.ID, b.ID) })
	}
	return n, p, nil
}

type Gone struct {
	Scope               Scope
	Consumer            Consumer
	Stopped, MountsGone bool
	Signature           []byte
}

func GoneBytes(g Gone) []byte { g.Signature = nil; return signedBytes("mydc-volume-gone-1", g) }
func signedBytes(domain string, v any) []byte {
	b, _ := json.Marshal(v)
	return append([]byte(domain+"\x00"), b...)
}
func verify(key [32]byte, b, sig []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(key[:]), b, sig)
}
func (s State) Release(g Gone) (State, error) {
	for _, move := range s.d.Moves {
		if move.Binding.MatchesReader(g.Consumer) {
			return s.CloseMoveReader(move.Binding, g)
		}
	}
	return s.release(g)
}

// release returns only the original live lease. Move readers enter through
// CloseMoveReader so the signed receipt and this return share one publication.
func (s State) release(g Gone) (State, error) {
	i := s.consumerIndex(g.Consumer)
	if i < 0 || g.Scope != s.d.Scope || !g.Stopped || !g.MountsGone || !verify(g.Consumer.Owner.Key, GoneBytes(g), g.Signature) {
		return s, ErrVolume
	}
	p, e := reconcile.RestoreLeases(s.d.Pins)
	if e != nil {
		return s, e
	}
	if e = p.Release(g.Consumer.Lease); e != nil {
		return s, e
	}
	n, e := s.clone()
	if e != nil {
		return s, e
	}
	n.d.Consumers = append(n.d.Consumers[:i], n.d.Consumers[i+1:]...)
	n.d.Pins = p.Checkpoint()
	return n, nil
}
