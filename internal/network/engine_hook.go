// SPDX-License-Identifier: Apache-2.0

package network

import (
	"errors"
	"net/netip"
	"sync"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Seafield's built-in "sfc" network driver asks the node daemon at each
// libnetwork step and waits for the answer (seafield/docs/sfcd-socket.md,
// 네트워크; SFCP purpose 36 EngineNetwork). These are the answers. They do
// not depend on the transport: the purpose 36 handler decodes a request,
// calls one method here and encodes the answer.
//
// Re-entry: the daemon's own Bridge driver calls the engine's NetworkCreate
// while it holds the Bridge journal entry, and the engine asks back inside
// that call. So nothing here takes a journal lock. BridgeDriver.Execute
// registers the exact dispatched operation (Expect) before it sends the
// create, and the hook only answers for a registered one.

// EngineResult is the answer's result: applied, not-applied (with a code),
// or unknown (failed after the effect may have happened).
type EngineResult uint8

const (
	EngineApplied EngineResult = iota + 1
	EngineNotApplied
	EngineUnknown
)

// Not-applied codes, shared with the other engine purposes.
const (
	EngineInvalid  = "invalid"
	EngineNotFound = "not-found"
	EngineConflict = "conflict"
	EngineNotOwner = "not-owner"
	EngineNotReady = "not-ready"
	EngineRefused  = "refused"
)

// EngineEnvelope is on every request: OpID is the same when the engine
// sends the same step again, BootID is new at each engine start.
type EngineEnvelope struct {
	OpID, BootID string
}

type EngineIPAM struct {
	Subnet  netip.Prefix
	Gateway netip.Addr
}

// EngineCreate comes before the engine makes the bridge device.
type EngineCreate struct {
	EngineEnvelope
	ID, Name        string
	Labels, Options map[string]string
	IPAM            []EngineIPAM
}

// EngineCreated is the engine's one readback after it made the device.
type EngineCreated struct {
	EngineEnvelope
	ID, Name, Bridge string
	Labels           map[string]string
	MTU              int
	Gateway          []netip.Addr
}

// EngineJoin comes before the endpoint is moved into the container sandbox.
type EngineJoin struct {
	EngineEnvelope
	ID, Endpoint, ContainerID, ContainerName string
	ContainerLabels                          map[string]string
	Addresses                                []netip.Prefix
	MAC, SandboxKey, HostVeth                string
}

type EngineLeave struct {
	EngineEnvelope
	ID, Endpoint, ContainerID string
	Addresses                 []netip.Prefix
}

type EngineDelete struct {
	EngineEnvelope
	ID, Name string
	Labels   map[string]string
}

type EngineRoute struct {
	Destination netip.Prefix
	NextHop     netip.Addr
}

// EngineAnswer is one step's answer. Bridge and MTU answer a create; Allow,
// MTU, Routes and Sysctls answer a join.
type EngineAnswer struct {
	Result  EngineResult
	Code    string
	Bridge  string
	MTU     int
	Allow   bool
	Routes  []EngineRoute
	Sysctls map[string]string
}

func notApplied(code string) EngineAnswer { return EngineAnswer{Result: EngineNotApplied, Code: code} }

// EngineAdmit is what a join asks about: the Bridge key and generation the
// engine network was made for, and the container with its addresses.
type EngineAdmit struct {
	Key           string
	Generation    uint64
	NetworkID     string
	ContainerID   string
	ContainerName string
	Labels        map[string]string
	Addresses     []netip.Prefix
}

// EngineAdmission decides a join: whether the container holds a lease on
// the Bridge key at that generation. The runtime supplies it. It must not
// take the Bridge journal entry lock for long: a join never runs inside
// that key's Execute, but it may race a borrow.
type EngineAdmission func(EngineAdmit) error

// EngineHooks holds the creates in flight and the answers already given.
type EngineHooks struct {
	Owner string
	Admit EngineAdmission

	mu       sync.Mutex
	inflight map[string]*hookCreate // by engine network name
	networks map[string]hookNetwork // by engine network ID, after created
	answers  map[string]EngineAnswer
}

type hookCreate struct {
	key  string
	op   reconcile.Operation
	spec BridgeSpec
	id   engine.Identity
	// stage: what the engine reached for this create.
	stage hookStage
}

type hookNetwork struct {
	key        string
	generation uint64
	mtu        int
}

type hookStage uint8

const (
	hookNotCalled hookStage = iota // the engine never asked: its driver did not run
	hookRefused                    // we answered not-applied
	hookAnswered                   // we gave a name; the device may exist
	hookConfirmed                  // the readback matched
	hookMismatch                   // the readback did not match
	hookUndone                     // the engine deleted it again inside the same create
)

var errHookBusy = errors.New("another create for this network is in flight")

// Expect registers the dispatched create of key/op before NetworkCreate is
// sent. done reports what the engine reached and forgets the create.
func (h *EngineHooks) Expect(key string, op reconcile.Operation, s BridgeSpec, id engine.Identity) (done func() hookStage, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inflight == nil {
		h.inflight = map[string]*hookCreate{}
	}
	if _, busy := h.inflight[id.Name]; busy {
		return nil, errHookBusy
	}
	c := &hookCreate{key: key, op: op, spec: s, id: id}
	h.inflight[id.Name] = c
	return func() hookStage {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.inflight, id.Name)
		return c.stage
	}, nil
}

// replay gives the same answer to a step the engine sends again.
func (h *EngineHooks) replay(e EngineEnvelope, step string) (EngineAnswer, bool) {
	a, ok := h.answers[step+"\x00"+e.BootID+"\x00"+e.OpID]
	return a, ok
}

func (h *EngineHooks) remember(e EngineEnvelope, step string, a EngineAnswer) EngineAnswer {
	if e.OpID == "" || e.BootID == "" {
		return a
	}
	if h.answers == nil {
		h.answers = map[string]EngineAnswer{}
	}
	if len(h.answers) >= 4096 {
		clear(h.answers) // a retry beyond this window is answered afresh
	}
	h.answers[step+"\x00"+e.BootID+"\x00"+e.OpID] = a
	return a
}

// Create answers only the exact create this daemon dispatched: labels name
// it, and the IPAM it asks for is the spec's. A network made with the sfc
// driver through the engine API by anyone else is not-owner.
func (h *EngineHooks) Create(r EngineCreate) EngineAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Only while the create is in flight: once Execute is done with it, a
	// late or repeated create is refused, so the engine can make nothing
	// Execute did not see.
	c, ok := h.inflight[r.Name]
	if !ok || !c.id.Matches(r.Name, r.Labels) || r.Labels["org.sfc.owner"] != h.Owner {
		return notApplied(EngineNotOwner)
	}
	if a, ok := h.replay(r.EngineEnvelope, "create"); ok {
		return a
	}
	if r.OpID == "" || r.BootID == "" {
		return notApplied(EngineInvalid)
	}
	if !sameIPAM(r.IPAM, c.spec) {
		c.stage = hookRefused
		return h.remember(r.EngineEnvelope, "create", notApplied(EngineInvalid))
	}
	c.stage = hookAnswered
	return h.remember(r.EngineEnvelope, "create", EngineAnswer{Result: EngineApplied, Bridge: bridgeDeviceName(c.id), MTU: c.spec.MTU})
}

// Created records the engine's readback for the create in flight.
func (h *EngineHooks) Created(r EngineCreated) EngineAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if a, ok := h.replay(r.EngineEnvelope, "created"); ok {
		return a
	}
	var c *hookCreate
	for _, candidate := range h.inflight {
		if candidate.stage >= hookAnswered && bridgeDeviceName(candidate.id) == r.Bridge && candidate.id.Matches(r.Name, r.Labels) {
			c = candidate
		}
	}
	if c == nil || r.ID == "" {
		return h.remember(r.EngineEnvelope, "created", notApplied(EngineNotOwner))
	}
	if r.MTU != c.spec.MTU || !sameGateways(r.Gateway, c.spec) {
		c.stage = hookMismatch
		return h.remember(r.EngineEnvelope, "created", notApplied(EngineConflict))
	}
	c.stage = hookConfirmed
	if h.networks == nil {
		h.networks = map[string]hookNetwork{}
	}
	h.networks[r.ID] = hookNetwork{key: c.key, generation: c.op.Target.Generation, mtu: c.spec.MTU}
	return h.remember(r.EngineEnvelope, "created", EngineAnswer{Result: EngineApplied})
}

// Adopt records a network this daemon already made, read back from the
// engine (after a restart the in-memory record is gone). The Bridge
// manager calls it when it confirms an applied Bridge.
func (h *EngineHooks) Adopt(engineID, key string, generation uint64, mtu int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.networks == nil {
		h.networks = map[string]hookNetwork{}
	}
	h.networks[engineID] = hookNetwork{key: key, generation: generation, mtu: mtu}
}

// Join lets a container in only when it holds a lease on the network.
func (h *EngineHooks) Join(r EngineJoin) EngineAnswer {
	h.mu.Lock()
	if a, ok := h.replay(r.EngineEnvelope, "join"); ok {
		h.mu.Unlock()
		return a
	}
	n, ok := h.networks[r.ID]
	admit := h.Admit
	h.mu.Unlock()
	answer := EngineAnswer{Result: EngineApplied, Allow: true, MTU: n.mtu, Routes: []EngineRoute{}, Sysctls: map[string]string{}}
	switch {
	case !ok:
		// Not a network this daemon made since it started: its record is
		// read again by the runtime before it starts containers on it.
		answer = notApplied(EngineNotReady)
	case r.ContainerLabels["org.sfc.owner"] != h.Owner:
		answer = notApplied(EngineNotOwner)
	case admit == nil:
		answer = notApplied(EngineNotReady)
	default:
		if err := admit(EngineAdmit{Key: n.key, Generation: n.generation, NetworkID: r.ID, ContainerID: r.ContainerID, ContainerName: r.ContainerName, Labels: r.ContainerLabels, Addresses: r.Addresses}); err != nil {
			answer = notApplied(EngineRefused)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.remember(r.EngineEnvelope, "join", answer)
}

// Leave: pins are returned after the container ends, as before.
func (h *EngineHooks) Leave(r EngineLeave) EngineAnswer {
	return EngineAnswer{Result: EngineApplied}
}

// Delete comes after the device is gone. Isolation is removed later by the
// Bridge journal's own Remove, after the network and TUN are gone.
func (h *EngineHooks) Delete(r EngineDelete) EngineAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Labels["org.sfc.owner"] != h.Owner {
		return notApplied(EngineNotOwner)
	}
	delete(h.networks, r.ID)
	// A delete inside the create that named the device is the engine's
	// undo: it failed that create and removed what it had made.
	if c, ok := h.inflight[r.Name]; ok && c.stage == hookAnswered && c.id.Matches(r.Name, r.Labels) {
		c.stage = hookUndone
	}
	return EngineAnswer{Result: EngineApplied}
}

func sameIPAM(got []EngineIPAM, s BridgeSpec) bool {
	if len(got) != len(s.Pools) {
		return false
	}
	for _, p := range s.Pools {
		found := false
		for _, g := range got {
			found = found || g.Subnet == p.Prefix && g.Gateway == p.Gateway
		}
		if !found {
			return false
		}
	}
	return true
}

func sameGateways(got []netip.Addr, s BridgeSpec) bool {
	if len(got) != len(s.Pools) {
		return false
	}
	for _, p := range s.Pools {
		found := false
		for _, g := range got {
			found = found || g == p.Gateway
		}
		if !found {
			return false
		}
	}
	return true
}

// hookRefusedCreate reports a failed NetworkCreate the engine positively did
// not carry out: its driver asks before it makes anything, so an error
// before our answer, or after our refusal, means nothing was made. So does
// one after the engine's own undo delete, which comes after the device is
// gone.
func hookRefusedCreate(stage hookStage) bool {
	return stage == hookNotCalled || stage == hookRefused || stage == hookUndone
}
