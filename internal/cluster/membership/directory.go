// SPDX-License-Identifier: Apache-2.0

// Package membership joins accepted member intent to the same A2 operation
// core used by native modules. It never elects leaders or infers non-execution.
package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/reconcile"
)

var ErrMember = errors.New("invalid, conflicting or unsettled member operation")

type Phase string

const (
	Invited   Phase = "invited"
	Learner   Phase = "learner"
	Ready     Phase = "ready"
	Promoting Phase = "promoting"
	Demoting  Phase = "demoting"
	// Moving: a joined server's endpoint change is being installed.
	Moving Phase = "moving"
	Active Phase = "active"
)

// Ack attests to the target's durable installation, not to mere reachability.
// The adapter must sign only after installing the actual configuration/applied
// floor in the SAME local lifecycle.Root. The core verifies that fixed proof.
type Ack struct {
	Schema                           uint8
	Cluster                          [32]byte
	Node, JoinID                     string
	Key                              [32]byte
	ConfigurationIndex, AppliedIndex uint64
	Signature                        []byte
}

func AckBytes(a Ack) []byte {
	a.Signature = nil
	b, _ := json.Marshal(a)
	return append([]byte("sfc-member-install-1\x00"), b...)
}

type Entry struct {
	Keys                   []lifecycle.IdentityTransition `json:",omitempty"`
	Voting                 *VotingChange                  `json:",omitempty"`
	Peer                   config.Peer
	JoinID                 string
	Revision               uint64
	Phase                  Phase
	Job                    reconcile.State
	Source                 [32]byte
	BaseIndex, NativeIndex uint64
	Ack                    *Ack `json:",omitempty"`
	// Abort is the signed abort-node-join original of a learner whose join
	// is being given up: the leader removes it from Raft, then the entry
	// goes and its name is free again.
	Abort json.RawMessage `json:",omitempty"`
	// Address is the server's fixed address in the system range's server
	// block (network.ServerBlock), set when the server is added (genesis
	// or invite). It is the server's tunnel address in every TUN network.
	// A removed server's address is free for the next one.
	Address netip.Addr
	// Restore is the signed `sfcd restore` record of a server that rebuilt
	// the cluster from a backup. It stands in for the join evidence (job,
	// ACK, source) such a server never had.
	Restore *lifecycle.ClusterRestore `json:",omitempty"`
}
type Directory struct {
	Rotations []IdentityRotation `json:",omitempty"`
	Drains    []Drain            `json:",omitempty"`
	Cordons   []Cordon           `json:",omitempty"`
	Runtime   *RuntimeState      `json:",omitempty"`
	Schema    uint8
	Cluster   [32]byte
	Genesis   config.Peer
	Revision  uint64
	Entries   []Entry
}

// Addresses compare in canonical text form without consulting external DNS in
// a deterministic transition. Different DNS names remain different endpoints.
func validPeer(p config.Peer) bool {
	key, err := identity.ParseKey(p.Key)
	return lifecycle.ValidID(p.ID) && err == nil && p.Key == identityHex(key) && config.ValidateCanonicalEndpoint(p.Endpoint) == nil
}
func identityHex(key [32]byte) string { return hex.EncodeToString(key[:]) }
func peerResource(p config.Peer) reconcile.Resource {
	raw, _ := json.Marshal(p)
	return reconcile.Resource{Generation: 1, Spec: string(raw), Present: true}
}
func New(cluster [32]byte, genesis config.Peer) (Directory, error) {
	if cluster == ([32]byte{}) || !validPeer(genesis) || !genesis.Voter {
		return Directory{}, ErrMember
	}
	return Directory{Schema: 1, Cluster: cluster, Genesis: genesis, Revision: 1, Entries: []Entry{{Peer: genesis, JoinID: "genesis", Revision: 1, Phase: Active, Address: network.ServerBlock.Addr().Next()}}}, nil
}

// gone: the server was removed from the cluster; its address is free.
// Gone reports whether server id was removed or retired.
func (d Directory) Gone(id string) bool { return d.gone(id) }

func (d Directory) gone(id string) bool {
	if d.Runtime == nil {
		return false
	}
	t, err := d.Topology()
	if err != nil {
		return false
	}
	n, exists := t.Node(id)
	return exists && (n.Phase == lifecycle.Removed || n.Phase == lifecycle.Retired)
}

// nextAddress is the first server address no present server holds and
// no network still uses (inUse: a removed server's tunnel address stays
// taken until its last network member is gone).
func (d Directory) nextAddress(inUse map[netip.Addr]bool) (netip.Addr, bool) {
	held := map[netip.Addr]bool{}
	for _, e := range d.Entries {
		if !d.gone(e.Peer.ID) {
			held[e.Address] = true
		}
	}
	for a := network.ServerBlock.Addr().Next(); network.ValidServerAddress(a); a = a.Next() {
		if !held[a] && !inUse[a] {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// ServerAddresses are every server's fixed address by node ID. A removed
// server keeps its entry, so network members it left behind still check
// against their own address; Invite does not hand that address out again
// while a network uses it.
func (d Directory) ServerAddresses() map[string]netip.Addr {
	out := map[string]netip.Addr{}
	for _, e := range d.Entries {
		out[e.Peer.ID] = e.Address
	}
	return out
}
func clone(d Directory) Directory {
	n := d
	n.Drains = ownDrains(d.Drains)
	if d.Rotations != nil {
		raw, _ := json.Marshal(d.Rotations)
		_ = json.Unmarshal(raw, &n.Rotations)
	}
	if d.Runtime != nil {
		raw, _ := json.Marshal(d.Runtime)
		var runtime RuntimeState
		_ = json.Unmarshal(raw, &runtime)
		n.Runtime = &runtime
	}
	n.Cordons = slices.Clone(d.Cordons)
	for i := range n.Cordons {
		n.Cordons[i].Origin = bytes.Clone(n.Cordons[i].Origin)
	}
	n.Entries = slices.Clone(d.Entries)
	for i := range n.Entries {
		n.Entries[i].Keys = lifecycle.OwnIdentityTransitions(n.Entries[i].Keys)
		if v := n.Entries[i].Voting; v != nil {
			copy := *v
			copy.Origin = bytes.Clone(v.Origin)
			n.Entries[i].Voting = &copy
		}
		if op := n.Entries[i].Job.Pending; op != nil {
			copied := *op
			n.Entries[i].Job.Pending = &copied
		}
		if a := n.Entries[i].Ack; a != nil {
			copied := *a
			copied.Signature = bytes.Clone(a.Signature)
			n.Entries[i].Ack = &copied
		}
		if r := n.Entries[i].Restore; r != nil {
			copied := *r
			copied.Signature = bytes.Clone(r.Signature)
			n.Entries[i].Restore = &copied
		}
	}
	return n
}
func (d Directory) Entry(id string) (Entry, bool) {
	for _, e := range d.Entries {
		if e.Peer.ID == id {
			return clone(Directory{Entries: []Entry{e}}).Entries[0], true
		}
	}
	return Entry{}, false
}
func FullMember(e Entry) bool {
	return e.Phase == Ready || e.Phase == Active || e.Phase == Promoting || e.Phase == Demoting || e.Phase == Moving
}

// EndpointMatches reports whether Raft may hold server e at address: its
// recorded endpoint, or the new one of an endpoint change in progress (the
// installed configuration can name it before the change is observed).
func (e Entry) EndpointMatches(address string) bool {
	return address == e.Peer.Endpoint || e.Phase == Moving && e.Voting != nil && e.Job.Pending != nil && address == e.Voting.Endpoint
}
func (d Directory) MemberKey(key [32]byte) bool {
	found := false
	for _, e := range d.Entries {
		if FullMember(e) && e.CurrentPeer().Key == identityHex(key) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	if d.Runtime == nil {
		return true
	}
	t, err := d.Topology()
	if err != nil {
		return false
	}
	for _, e := range d.Entries {
		if e.CurrentPeer().Key == identityHex(key) {
			n, exists := t.Node(e.Peer.ID)
			_, installed := t.Configuration().Member(e.Peer.ID)
			return exists && installed && n.Phase != lifecycle.Removed && n.Phase != lifecycle.Retired
		}
	}
	return false
}
func (d Directory) HistoricalMemberKey(key [32]byte) bool {
	for _, e := range d.Entries {
		if !FullMember(e) {
			continue
		}
		if e.Peer.Key == identityHex(key) {
			return true
		}
		for _, row := range e.Keys {
			if row.Proof.Old == key || row.Proof.New == key {
				return true
			}
		}
	}
	return false
}

func (d Directory) WorkKey(key [32]byte) bool {
	if !d.MemberKey(key) {
		return false
	}
	if d.Runtime == nil {
		return true
	}
	t, err := d.Topology()
	if err != nil {
		return false
	}
	for _, e := range d.Entries {
		if e.CurrentPeer().Key == identityHex(key) {
			return t.AdmitWork(e.Peer.ID)
		}
	}
	return false
}

// ReplicationKey preserves provisional join and installed consensus channels.
// A committed removal revokes them; business isolation alone does not.
func (d Directory) ReplicationKey(key [32]byte) bool {
	for _, entry := range d.Entries {
		if entry.CurrentPeer().Key != identityHex(key) {
			continue
		}
		if d.Runtime == nil {
			return true
		}
		t, err := d.Topology()
		if err != nil {
			return false
		}
		node, exists := t.Node(entry.Peer.ID)
		return !exists || node.Phase != lifecycle.Removed && node.Phase != lifecycle.Retired
	}
	return false
}
func (d Directory) Issuers() [][32]byte {
	var keys [][32]byte
	for _, e := range d.Entries {
		key, _ := identity.ParseKey(e.CurrentPeer().Key)
		// Existing account signatures remain verifiable during isolation and
		// recovery. New node effects use WorkKey, not session-issuer identity.
		if FullMember(e) && d.MemberKey(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// VoterKey reports whether key is an active installed Raft voter (the same
// set as SessionIssuers). Only voters hold the certificate master key.
func (d Directory) VoterKey(key [32]byte) bool {
	return slices.Contains(d.SessionIssuers(), key)
}

// SessionIssuers is narrower than installed replication/provider membership.
// A new user grant requires an active installed Raft voter. Invitations,
// non-voters, isolation and removal cannot provide session authority. Existing
// committed grants retain their own original signatures independently.
func (d Directory) SessionIssuers() [][32]byte {
	var keys [][32]byte
	for _, entry := range d.Entries {
		key, err := identity.ParseKey(entry.CurrentPeer().Key)
		if err != nil || !FullMember(entry) || !entry.Peer.Voter || !d.WorkKey(key) {
			continue
		}
		if d.Runtime != nil {
			topology, err := d.Topology()
			if err != nil {
				return nil
			}
			member, installed := topology.Configuration().Member(entry.Peer.ID)
			if !installed || !member.Voter || member.Key != key {
				continue
			}
		}
		keys = append(keys, key)
	}
	return keys
}
func (d Directory) writable() bool { return d.Revision < math.MaxUint64 && d.Validate() == nil }
func (d Directory) replace(entry Entry) Directory {
	n := clone(d)
	n.Revision++
	entry.Revision = n.Revision
	for i, e := range n.Entries {
		if e.Peer.ID == entry.Peer.ID {
			n.Entries[i] = entry
			return clone(n)
		}
	}
	n.Entries = append(n.Entries, entry)
	slices.SortFunc(n.Entries, func(a, b Entry) int { return strings.Compare(a.Peer.ID, b.Peer.ID) })
	return clone(n)
}

// Invite adds a non-voter and gives it the first free server address.
// inUse are the tunnel addresses networks still use (tenancy
// Networks.TunnelAddressesInUse).
func (d Directory) Invite(peer config.Peer, id string, inUse map[netip.Addr]bool) (Directory, error) {
	if !d.writable() || !validPeer(peer) || peer.Voter || !lifecycle.ValidID(id) || id == "genesis" || len(d.Entries) >= 1024 {
		return d, ErrMember
	}
	if key, e := identity.ParseKey(peer.Key); e != nil || d.HistoricalMemberKey(key) {
		return d, ErrMember
	}
	for _, e := range d.Entries {
		if e.Peer.ID == peer.ID || e.Peer.Key == peer.Key || e.Peer.Endpoint == peer.Endpoint && !d.gone(e.Peer.ID) || e.JoinID == id {
			return d, ErrMember
		}
	}
	job, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: d.Revision + 1, Resource: peerResource(peer)})
	if err != nil {
		return d, err
	}
	job, _, err = reconcile.Plan(job)
	if err != nil {
		return d, err
	}
	address, ok := d.nextAddress(inUse)
	if !ok {
		return d, ErrMember
	}
	return d.replace(Entry{Peer: peer, JoinID: id, Phase: Invited, Job: job, Address: address}), nil
}
func (d Directory) Promote(id string, expected uint64) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || e.Phase != Ready {
		return d, ErrMember
	}
	peer := e.Peer
	peer.Voter = true
	job, err := reconcile.SetDesired(e.Job, reconcile.Desired{Revision: d.Revision + 1, Resource: peerResource(peer)})
	if err != nil {
		return d, err
	}
	job, _, err = reconcile.Plan(job)
	if err != nil {
		return d, err
	}
	e.Job, e.Phase, e.Source, e.BaseIndex = job, Promoting, [32]byte{}, 0
	return d.replace(e), nil
}

// Dispatch accepts an actual committed native configuration index. It serializes
// native changes globally, including unresolved effects after source failure.
func (d Directory) Dispatch(id string, expected, jobID, index uint64, source [32]byte) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || index == 0 || index < e.NativeIndex || e.Ack != nil && index < e.Ack.ConfigurationIndex || !d.MemberKey(source) || e.Phase != Invited && e.Phase != Promoting && e.Phase != Demoting && e.Phase != Moving {
		return d, ErrMember
	}
	for _, other := range d.Entries {
		if other.Job.Pending != nil && other.Job.Pending.Phase != reconcile.Prepared {
			return d, ErrMember
		}
	}
	if d.runtimeDispatched() {
		return d, ErrMember
	}
	job, err := reconcile.Dispatch(e.Job, jobID)
	if err != nil {
		return d, err
	}
	e.Job, e.Source, e.BaseIndex = job, source, index
	return d.replace(e), nil
}
func (d Directory) Unknown(id string, expected, jobID uint64) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected {
		return d, ErrMember
	}
	job, err := reconcile.Settle(e.Job, jobID, reconcile.EffectUnknown)
	if err != nil {
		return d, err
	}
	e.Job = job
	return d.replace(e), nil
}

// Absent settles a join whose native add never happened: the leader read
// the committed configuration (behind a read barrier, with no uncommitted
// configuration entry) at index >= the dispatch's base index, and the
// server is not in it. The add was conditioned on the base index and is
// sent only once, so it can no longer land. The join is planned again
// (Prepared): the server may run 'sfcd join' again, or the invitation may
// be cancelled.
func (d Directory) Absent(id string, expected, jobID, index uint64) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || e.Phase != Invited || e.Job.Pending == nil || e.Job.Pending.ID != jobID || index < e.BaseIndex || e.NativeIndex != 0 ||
		e.Job.Pending.Phase != reconcile.Dispatched && e.Job.Pending.Phase != reconcile.RecoveryRequired {
		return d, ErrMember
	}
	if _, err := reconcile.Settle(e.Job, jobID, reconcile.EffectNotApplied); err != nil {
		return d, err
	}
	// The same approval as the invitation (Desired keeps its revision, so
	// the invitation the server holds stays valid), as a fresh first job.
	job, err := reconcile.SetDesired(reconcile.State{}, e.Job.Desired)
	if err != nil {
		return d, err
	}
	if job, _, err = reconcile.Plan(job); err != nil {
		return d, err
	}
	e.Job, e.Source, e.BaseIndex = job, [32]byte{}, 0
	return d.replace(e), nil
}

// Observe is positive evidence for the ORIGINAL target. Timeout, loss of
// leadership, or a newer Desired never clears a dispatched job; target absence
// clears it only through Absent, with a committed configuration at or after
// the dispatch index that does not name the server.
func (d Directory) Observe(id string, expected, jobID, index uint64, actual config.Peer) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || e.Job.Pending == nil || index <= e.BaseIndex || peerResource(actual) != e.Job.Pending.Target {
		return d, ErrMember
	}
	job, err := reconcile.Settle(e.Job, jobID, reconcile.EffectApplied)
	if err != nil {
		return d, err
	}
	e.Job, e.NativeIndex, e.Peer, e.Phase = job, index, actual, Learner
	if e.Voting != nil {
		e.Phase = Ready
	}
	if actual.Voter {
		e.Phase = Active
	}
	return d.replace(e), nil
}
func (d Directory) Installed(a Ack, expected uint64) (Directory, error) {
	e, ok := d.Entry(a.Node)
	_, err := identity.ParseKey(e.Peer.Key)
	if !ok || err != nil || !d.writable() || e.Revision != expected || e.Phase != Learner || e.Abort != nil || !validAck(a, d.Cluster, e) || a.ConfigurationIndex < e.NativeIndex {
		return d, ErrMember
	}
	e.Ack, e.Phase = &a, Ready
	return d.replace(e), nil
}
func validAck(a Ack, cluster [32]byte, e Entry) bool {
	key, _ := identity.ParseKey(e.Peer.Key)
	return a.Schema == 1 && a.Cluster == cluster && a.Node == e.Peer.ID && a.JoinID == e.JoinID && a.Key == key && a.ConfigurationIndex > 0 && a.AppliedIndex >= a.ConfigurationIndex && ed25519.Verify(ed25519.PublicKey(key[:]), AckBytes(a), a.Signature)
}
func (d Directory) Validate() error {
	if d.validateIdentityRotations() != nil || d.validateDrains() != nil {
		return ErrMember
	}
	if d.validateCordons() != nil {
		return ErrMember
	}
	if d.Schema != 1 || d.Cluster == ([32]byte{}) || d.Revision == 0 || len(d.Entries) == 0 || len(d.Entries) > 1024 || !validPeer(d.Genesis) || !d.Genesis.Voter {
		return ErrMember
	}
	ids, keys, endpoints, joins := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	addresses := map[netip.Addr]bool{}
	genesis, dispatched := false, 0
	for i, e := range d.Entries {
		if !network.ValidServerAddress(e.Address) {
			return ErrMember
		}
		if !d.gone(e.Peer.ID) {
			if addresses[e.Address] {
				return ErrMember
			}
			addresses[e.Address] = true
		}
		// A removed or retired server's endpoint is free for a new server.
		present := !d.gone(e.Peer.ID)
		if !validPeer(e.Peer) || ids[e.Peer.ID] || keys[e.Peer.Key] || present && endpoints[e.Peer.Endpoint] || joins[e.JoinID] || !lifecycle.ValidID(e.JoinID) || e.Revision == 0 || e.Revision > d.Revision || i > 0 && e.Peer.ID <= d.Entries[i-1].Peer.ID || reconcile.Validate(e.Job) != nil {
			return ErrMember
		}
		original, _ := identity.ParseKey(e.Peer.Key)
		current, valid := lifecycle.ValidIdentityTransitions(d.Cluster, e.Peer.ID, original, e.Keys)
		if !valid || current != mustPeerKey(e.CurrentPeer()) {
			return ErrMember
		}
		for _, transition := range e.Keys {
			if transition.Index == 0 || transition.Revision > d.Revision || keys[identityHex(transition.Proof.New)] {
				return ErrMember
			}
			keys[identityHex(transition.Proof.New)] = true
		}
		ids[e.Peer.ID], keys[e.Peer.Key], joins[e.JoinID] = true, true, true
		if present {
			endpoints[e.Peer.Endpoint] = true
			// A move's new endpoint is taken as soon as it is accepted.
			if v := e.Voting; v != nil && v.Endpoint != "" && e.Job.Pending != nil {
				if endpoints[v.Endpoint] {
					return ErrMember
				}
				endpoints[v.Endpoint] = true
			}
		}
		if r := e.Restore; r != nil {
			if !r.Valid() || r.Cluster != d.Cluster || r.Node != e.Peer.ID || r.Key != original || r.Endpoint != e.Peer.Endpoint || r.RequestID != e.JoinID || !e.Peer.Voter || e.Phase != Active || e.Revision <= 1 || e.Voting != nil || e.Job != (reconcile.State{}) || e.Ack != nil || e.Abort != nil || e.Source != ([32]byte{}) || e.NativeIndex != 0 || e.BaseIndex != 0 {
				return ErrMember
			}
			continue
		}
		if e.Voting != nil {
			if e.JoinID == "genesis" {
				// The genesis endpoint stays in d.Genesis; the server
				// itself may have moved since (set-node-endpoint).
				if e.Peer.ID != d.Genesis.ID || e.Peer.Key != d.Genesis.Key {
					return ErrMember
				}
				genesis = true
			}
			active, err := d.validateVotingEntry(e)
			if err != nil {
				return err
			}
			if active {
				dispatched++
			}
			continue
		}
		if e.JoinID == "genesis" {
			if e.Peer != d.Genesis || e.Phase != Active || (len(e.Keys) == 0 && e.Revision != 1) || e.Job != (reconcile.State{}) || e.Ack != nil || e.Source != ([32]byte{}) || e.NativeIndex != 0 || e.BaseIndex != 0 {
				return ErrMember
			}
			genesis = true
			continue
		}
		wanted := e.Peer
		if e.Phase == Promoting {
			wanted.Voter = true
		}
		desired := e.Job.Desired
		if e.Revision <= 1 || desired.Revision < 2 || desired.Revision > e.Revision || desired.Retiring != 0 || desired.Resource != peerResource(wanted) || e.Job.GenerationFloor != 1 || e.Job.Stopped {
			return ErrMember
		}
		pending := e.Job.Pending
		if pending != nil {
			if pending.Kind != reconcile.Apply || pending.Target != desired.Resource {
				return ErrMember
			}
			if pending.Phase != reconcile.Prepared {
				dispatched++
				if !d.HistoricalMemberKey(e.Source) || e.BaseIndex == 0 || e.BaseIndex < e.NativeIndex || e.Ack != nil && e.BaseIndex < e.Ack.ConfigurationIndex {
					return ErrMember
				}
			} else if e.Source != ([32]byte{}) || e.BaseIndex != 0 {
				return ErrMember
			}
		} else if !d.HistoricalMemberKey(e.Source) || e.BaseIndex == 0 || e.NativeIndex <= e.BaseIndex {
			return ErrMember
		}
		if e.Abort != nil && e.Phase != Learner {
			return ErrMember
		}
		switch e.Phase {
		case Invited:
			if e.Peer.Voter || pending == nil || e.NativeIndex != 0 || e.Ack != nil || e.Job.Applied != (reconcile.Resource{}) || e.Job.LastID != 1 {
				return ErrMember
			}
		case Learner:
			if e.Abort != nil && (len(e.Abort) > 64<<10 || !json.Valid(e.Abort)) {
				return ErrMember
			}
			if e.Peer.Voter || pending != nil || e.Job.Applied != peerResource(e.Peer) || e.NativeIndex == 0 || e.Ack != nil || e.Job.LastID != 1 {
				return ErrMember
			}
		case Ready, Promoting, Active:
			if e.Ack == nil || !validAck(*e.Ack, d.Cluster, e) || e.NativeIndex == 0 || e.Job.Applied != peerResource(e.Peer) {
				return ErrMember
			}
			if e.Phase == Ready && (e.Peer.Voter || pending != nil || e.Job.LastID != 1) || e.Phase == Promoting && (e.Peer.Voter || pending == nil || e.Job.LastID != 2) || e.Phase == Active && (!e.Peer.Voter || pending != nil || e.Job.LastID != 2) {
				return ErrMember
			}
			if e.Phase != Active && e.Ack.ConfigurationIndex < e.NativeIndex || e.Phase == Active && e.Ack.ConfigurationIndex > e.BaseIndex {
				return ErrMember
			}
		default:
			return ErrMember
		}
	}
	if !genesis || dispatched > 1 {
		return ErrMember
	}
	return d.validateRuntime(dispatched)
}
func (d Directory) Encode() ([]byte, error) {
	if d.Validate() != nil {
		return nil, ErrMember
	}
	return json.Marshal(d)
}
func Decode(raw []byte) (Directory, error) {
	var d Directory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || d.Validate() != nil {
		return d, ErrMember
	}
	b, _ := json.Marshal(d)
	if !bytes.Equal(b, raw) {
		return d, ErrMember
	}
	return d, nil
}

// DecodeChecked decodes a directory whose exact bytes already passed Decode
// (a caller's memo of checked bytes). It skips Validate and the canonical
// re-encode, which are the costly part, and only refuses unknown fields.
func DecodeChecked(raw []byte) (Directory, error) {
	var d Directory
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil {
		return Directory{}, ErrMember
	}
	return d, nil
}

// ErrJoinStarted refuses to cancel an invitation whose join was already
// dispatched to Raft: the server may be a learner, so it leaves through
// the removal path once it is a member.
var ErrJoinStarted = errors.New("membership: join already dispatched")

// ErrNotInvited: the entry is past the invitation (a learner or member).
var ErrNotInvited = errors.New("membership: not an invitation")

// CancelableInvite reports whether e is an invitation whose join never
// reached Raft, so CancelInvite may forget it.
func CancelableInvite(e Entry) error {
	if e.Phase != Invited || e.JoinID == "genesis" {
		return ErrNotInvited
	}
	if e.Job.Pending != nil && e.Job.Pending.Phase != reconcile.Prepared || e.NativeIndex != 0 || e.Ack != nil {
		return ErrJoinStarted
	}
	return nil
}

// CancelInvite forgets a server that was invited and never joined: its
// name, key, endpoint and server address are free again.
func (d Directory) CancelInvite(id string, expected uint64) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected {
		return d, ErrMember
	}
	if err := CancelableInvite(e); err != nil {
		return d, err
	}
	n := clone(d)
	n.Revision++
	n.Entries = slices.DeleteFunc(n.Entries, func(x Entry) bool { return x.Peer.ID == id })
	n.Cordons = slices.DeleteFunc(n.Cordons, func(c Cordon) bool { return c.Node == id })
	if err := n.Validate(); err != nil {
		return d, err
	}
	return clone(n), nil
}

// ErrNotLearner: only a learner's join can be aborted this way.
var ErrNotLearner = errors.New("membership: not a learner")

// BeginAbortJoin records the signed decision to give up a learner whose
// server never acknowledged its installation (the server is gone or was
// set up wrong). From now on its ack is refused.
func (d Directory) BeginAbortJoin(id string, expected uint64, origin json.RawMessage) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || len(origin) == 0 || len(origin) > 64<<10 || !json.Valid(origin) {
		return d, ErrMember
	}
	if e.Phase != Learner || e.Ack != nil || e.Abort != nil {
		return d, ErrNotLearner
	}
	e.Abort = bytes.Clone(origin)
	return d.replace(e), nil
}

// FinishAbortJoin forgets an aborting learner once the leader saw the
// committed configuration at index (after the learner's own) without it.
func (d Directory) FinishAbortJoin(id string, expected, index uint64) (Directory, error) {
	e, ok := d.Entry(id)
	if !ok || !d.writable() || e.Revision != expected || e.Phase != Learner || e.Abort == nil || index <= e.NativeIndex {
		return d, ErrMember
	}
	n := clone(d)
	n.Revision++
	if n.Runtime != nil {
		t, err := n.Topology()
		if err != nil {
			return d, err
		}
		if _, present := t.Configuration().Member(id); present {
			if t, err = t.DropUnjoined(id); err != nil {
				return d, err
			}
			raw, err := t.Encode()
			if err != nil {
				return d, ErrMember
			}
			n.Runtime.Topology = raw
		}
	}
	n.Entries = slices.DeleteFunc(n.Entries, func(x Entry) bool { return x.Peer.ID == id })
	n.Cordons = slices.DeleteFunc(n.Cordons, func(c Cordon) bool { return c.Node == id })
	if err := n.Validate(); err != nil {
		return d, err
	}
	return clone(n), nil
}
