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
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

var ErrMember = errors.New("invalid, conflicting or unsettled member operation")

type Phase string

const (
	Invited   Phase = "invited"
	Learner   Phase = "learner"
	Ready     Phase = "ready"
	Promoting Phase = "promoting"
	Demoting  Phase = "demoting"
	Active    Phase = "active"
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
	return append([]byte("mydc-member-install-1\x00"), b...)
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
	return Directory{Schema: 1, Cluster: cluster, Genesis: genesis, Revision: 1, Entries: []Entry{{Peer: genesis, JoinID: "genesis", Revision: 1, Phase: Active}}}, nil
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
	return e.Phase == Ready || e.Phase == Active || e.Phase == Promoting || e.Phase == Demoting
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
func (d Directory) Invite(peer config.Peer, id string) (Directory, error) {
	if !d.writable() || !validPeer(peer) || peer.Voter || !lifecycle.ValidID(id) || id == "genesis" || len(d.Entries) >= 1024 {
		return d, ErrMember
	}
	if key, e := identity.ParseKey(peer.Key); e != nil || d.HistoricalMemberKey(key) {
		return d, ErrMember
	}
	for _, e := range d.Entries {
		if e.Peer.ID == peer.ID || e.Peer.Key == peer.Key || e.Peer.Endpoint == peer.Endpoint || e.JoinID == id {
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
	return d.replace(Entry{Peer: peer, JoinID: id, Phase: Invited, Job: job}), nil
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
	if !ok || !d.writable() || e.Revision != expected || index == 0 || index < e.NativeIndex || e.Ack != nil && index < e.Ack.ConfigurationIndex || !d.MemberKey(source) || e.Phase != Invited && e.Phase != Promoting && e.Phase != Demoting {
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

// Observe is positive evidence for the ORIGINAL target. Mere target absence,
// timeout, loss of leadership, or a newer Desired never clears a dispatched job.
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
	if !ok || err != nil || !d.writable() || e.Revision != expected || e.Phase != Learner || !validAck(a, d.Cluster, e) || a.ConfigurationIndex < e.NativeIndex {
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
	genesis, dispatched := false, 0
	for i, e := range d.Entries {
		if !validPeer(e.Peer) || ids[e.Peer.ID] || keys[e.Peer.Key] || endpoints[e.Peer.Endpoint] || joins[e.JoinID] || !lifecycle.ValidID(e.JoinID) || e.Revision == 0 || e.Revision > d.Revision || i > 0 && e.Peer.ID <= d.Entries[i-1].Peer.ID || reconcile.Validate(e.Job) != nil {
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
		ids[e.Peer.ID], keys[e.Peer.Key], endpoints[e.Peer.Endpoint], joins[e.JoinID] = true, true, true, true
		if e.Voting != nil {
			if e.JoinID == "genesis" {
				if e.Peer.ID != d.Genesis.ID || e.Peer.Key != d.Genesis.Key || e.Peer.Endpoint != d.Genesis.Endpoint {
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
		switch e.Phase {
		case Invited:
			if e.Peer.Voter || pending == nil || e.NativeIndex != 0 || e.Ack != nil || e.Job.Applied != (reconcile.Resource{}) || e.Job.LastID != 1 {
				return ErrMember
			}
		case Learner:
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
