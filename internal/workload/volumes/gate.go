// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/reconcile"
)

type StartRequest struct {
	Scope           Scope
	Consumer        Consumer
	Boot, Challenge [32]byte
	Sequence        uint64
}
type Permit struct {
	Request           StartRequest
	AuthorityRevision uint64
}

// PermitStart runs against a FRESH authoritative quorum read, never a node's
// cached shared DB. The adapter must complete its linearizable barrier and
// authenticate the response over SFCP. The pure core cannot prove that I/O.
func (s State) PermitStart(c access.Catalog, actor string, r StartRequest) (Permit, error) {
	if c.Authorize(actor, s.d.Scope.Tenant, access.ManageVolumes, s.d.Owner.Node) != nil {
		return Permit{}, access.ErrDenied
	}
	if r.Scope != s.d.Scope || r.Boot == ([32]byte{}) || r.Challenge == ([32]byte{}) || r.Sequence == 0 || s.CheckActivation(r.Consumer) != nil {
		return Permit{}, ErrVolume
	}
	return Permit{r, s.d.Revision}, nil
}

type GateCheckpoint struct {
	Schema       uint8
	Scope        Scope
	Owner        Owner
	Boot         [32]byte
	FenceThrough uint64
	Starting     *Consumer
}

// Gate is one native owner's local start barrier. Publish its checkpoint only
// after sync, and serialize Accept/Fence with the actual A2 native dispatch.
// Reboot changes the ephemeral boot challenge but preserves unknown starts.
type Gate struct {
	d       GateCheckpoint
	boot    [32]byte
	pending *StartRequest
	next    uint64
}

func NewGate(scope Scope, owner Owner, boot [32]byte) (Gate, error) {
	return RestoreGate(GateCheckpoint{Schema: 1, Scope: scope, Owner: owner}, boot)
}
func RestoreGate(d GateCheckpoint, boot [32]byte) (Gate, error) {
	if d.Schema != 1 || !validScope(d.Scope) || !validOwner(d.Owner) || boot == ([32]byte{}) || boot == d.Boot || d.Starting != nil && (!validConsumer(*d.Starting, d.Scope) || d.Starting.Owner != d.Owner || d.Starting.OwnerRevision <= d.FenceThrough) {
		return Gate{}, ErrVolume
	}
	if d.Starting != nil {
		c := *d.Starting
		d.Starting = &c
	}
	d.Boot = boot
	return Gate{d: d, boot: boot}, nil
}
func (g Gate) Checkpoint() GateCheckpoint {
	d := g.d
	if d.Starting != nil {
		c := *d.Starting
		d.Starting = &c
	}
	return d
}
func (g Gate) Request(c Consumer, challenge [32]byte) (Gate, StartRequest, error) {
	if g.d.Schema != 1 || g.d.Starting != nil || g.pending != nil || g.next == ^uint64(0) || !validConsumer(c, g.d.Scope) || c.Owner != g.d.Owner || c.OwnerRevision <= g.d.FenceThrough || challenge == ([32]byte{}) {
		return g, StartRequest{}, ErrVolume
	}
	g.next++
	r := StartRequest{Scope: g.d.Scope, Consumer: c, Boot: g.boot, Challenge: challenge, Sequence: g.next}
	g.pending = &r
	return g, r, nil
}

// Accept consumes only an authenticated response to this outstanding request.
// The transport must verify its SFCP peer and authoritative response boundary.
// It is persisted before invoking Start. It does not erase the A2 operation
// ID; that journal still determines original-call recovery after a crash.
func (g Gate) Accept(p Permit) (Gate, error) {
	r := p.Request
	if g.d.Schema != 1 || g.pending == nil || *g.pending != r || r.Boot != g.boot || r.Scope != g.d.Scope || r.Consumer.Owner != g.d.Owner || r.Consumer.OwnerRevision <= g.d.FenceThrough || p.AuthorityRevision < r.Consumer.OwnerRevision || g.d.Starting != nil {
		return g, ErrVolume
	}
	c := r.Consumer
	g.d.Starting = &c
	g.pending = nil
	return g, nil
}

// CancelRequest cancels only a challenge that has never been accepted. It
// cannot abandon an unknown dispatched Start or reuse the sequence number.
func (g Gate) CancelRequest(r StartRequest) (Gate, error) {
	if g.pending == nil || *g.pending != r || g.d.Starting != nil {
		return g, ErrVolume
	}
	g.pending = nil
	return g, nil
}

// CloseStart consumes positive original native closure, not non-observation.
// Its adapter must remove the exact previously synced immutable container ID.
// This does not claim that the historical Start never executed.
func (g Gate) CloseStart(c Consumer) (Gate, error) {
	if g.d.Starting == nil || *g.d.Starting != c {
		return g, ErrVolume
	}
	g.d.Starting = nil
	return g, nil
}
func (g Gate) SettleStart(c Consumer, outcome reconcile.Outcome) (Gate, error) {
	if g.d.Starting == nil || *g.d.Starting != c || outcome < reconcile.EffectApplied || outcome > reconcile.EffectUnknown {
		return g, ErrVolume
	}
	if outcome != reconcile.EffectUnknown {
		g.d.Starting = nil
	}
	return g, nil
}

// Fence invalidates every outstanding permit through the source owner revision.
// An unknown dispatched Start must first settle; a pending unsent challenge is
// cancelled by the fence. Native Stop/Wait/mount closure follows separately.
func (g Gate) Fence(through uint64) (Gate, error) {
	if g.d.Schema != 1 || through == 0 || through < g.d.FenceThrough || g.d.Starting != nil {
		return g, ErrVolume
	}
	g.d.FenceThrough = through
	g.pending = nil
	return g, nil
}
