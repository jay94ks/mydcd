// SPDX-License-Identifier: Apache-2.0

// Package lifecycle models bootstrap and runtime node operations. It validates
// already authenticated/committed inputs; it does not elect leaders or decide
// whether a Raft configuration entry has committed.
package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
)

var ErrLifecycle = errors.New("invalid or stale node lifecycle transition")

type Intent string

const (
	Init Intent = "init"
	Join Intent = "join"
)

type Member struct {
	ID    string
	Key   [32]byte
	Voter bool
}

// Configuration is supplied only after the Raft library commits and the local
// owner durably installs the corresponding state. Index is the actual Raft
// configuration index, never an application revision or a count of sockets.
type Configuration struct {
	Index   uint64
	Members []Member
}

func (c Configuration) Validate() error {
	if c.Index == 0 || len(c.Members) == 0 || len(c.Members) > 1024 {
		return ErrLifecycle
	}
	ids, keys, voters := map[string]bool{}, map[[32]byte]bool{}, 0
	for i, m := range c.Members {
		if !validID(m.ID) || m.Key == ([32]byte{}) || ids[m.ID] || keys[m.Key] || i > 0 && m.ID <= c.Members[i-1].ID {
			return ErrLifecycle
		}
		ids[m.ID] = true
		keys[m.Key] = true
		if m.Voter {
			voters++
		}
	}
	if voters == 0 {
		return ErrLifecycle
	}
	return nil
}
func validID(s string) bool {
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

// ValidID shares the persisted node/operation name grammar with real adapters.
func ValidID(s string) bool { return validID(s) }
func (c Configuration) Member(id string) (Member, bool) {
	for _, m := range c.Members {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}
func (c Configuration) Voters() int {
	n := 0
	for _, m := range c.Members {
		if m.Voter {
			n++
		}
	}
	return n
}
func (c Configuration) Quorum() int {
	if c.Validate() != nil {
		return 0
	}
	return c.Voters()/2 + 1
}
func (c Configuration) Standalone(self string) bool {
	m, ok := c.Member(self)
	return c.Validate() == nil && len(c.Members) == 1 && ok && m.Voter
}
func ownConfig(c Configuration) Configuration { c.Members = slices.Clone(c.Members); return c }

type Root struct {
	Keys               []IdentityTransition `json:",omitempty"`
	Schema             uint8
	Intent             Intent
	Cluster, TrustRoot [32]byte
	Self               Member
	Operation          string
	Installed          Configuration
	AppliedIndex       uint64
}

func Prepare(intent Intent, cluster, trust [32]byte, self Member, operation string) (Root, error) {
	if intent != Init && intent != Join && intent != RestoreIntent || cluster == ([32]byte{}) || trust == ([32]byte{}) || !validID(self.ID) || self.Key == ([32]byte{}) || !validID(operation) {
		return Root{}, ErrLifecycle
	}
	if intent == Init && (!self.Voter || trust != self.Key) || intent == Join && self.Voter || intent == RestoreIntent && (!self.Voter || trust == self.Key) {
		return Root{}, ErrLifecycle
	}
	return Root{Schema: 1, Intent: intent, Cluster: cluster, TrustRoot: trust, Self: self, Operation: operation}, nil
}
func (r Root) Validate() error {
	original := r.Self
	original.Key = r.OriginalKey()
	current, valid := ValidIdentityTransitions(r.Cluster, r.Self.ID, original.Key, r.Keys)
	if !valid || current != r.Self.Key {
		return ErrLifecycle
	}

	if _, err := Prepare(r.Intent, r.Cluster, r.TrustRoot, original, r.Operation); err != nil || r.Schema != 1 {
		return ErrLifecycle
	}
	if r.Installed.Index == 0 {
		if len(r.Installed.Members) != 0 || r.AppliedIndex != 0 || len(r.Keys) != 0 {
			return ErrLifecycle
		}
		return nil
	}
	if r.Installed.Validate() != nil || r.AppliedIndex < r.Installed.Index {
		return ErrLifecycle
	}
	m, ok := r.Installed.Member(r.Self.ID)
	if !ok || m.Key != r.Self.Key {
		return ErrLifecycle
	}
	return nil
}

// Resume requires the original root, cluster and full node key. A failed join
// has no transition to Init and cannot acquire a different cluster identity.
func (r Root) Resume(cluster [32]byte, self Member) error {
	if r.Validate() != nil || cluster != r.Cluster || self.ID != r.Self.ID || self.Key != r.Self.Key {
		return ErrLifecycle
	}
	return nil
}
func (r Root) Install(cluster [32]byte, c Configuration, applied uint64) (Root, error) {
	if r.Validate() != nil || cluster != r.Cluster || c.Validate() != nil || applied < c.Index || applied < r.AppliedIndex || c.Index < r.Installed.Index {
		return r, ErrLifecycle
	}
	m, ok := c.Member(r.Self.ID)
	if !ok || m.Key != r.Self.Key {
		return r, ErrLifecycle
	}
	if r.Installed.Index == 0 && (r.Intent == Init || r.Intent == RestoreIntent) && !c.Standalone(r.Self.ID) {
		return r, ErrLifecycle
	}
	if r.Installed.Index == 0 && r.Intent == Join && m.Voter {
		return r, ErrLifecycle
	}
	if c.Index == r.Installed.Index && !slices.Equal(c.Members, r.Installed.Members) {
		return r, ErrLifecycle
	}
	r.Installed = ownConfig(c)
	r.AppliedIndex = applied
	return r, nil
}

type Phase string

const (
	Active    Phase = "active"
	Isolating Phase = "isolating"
	Isolated  Phase = "isolated"
	Restoring Phase = "restoring"
	Removing  Phase = "removing"
	Removed   Phase = "removed"
	Retiring  Phase = "retiring"
	Retired   Phase = "retired"
)

type Action string

const (
	Isolate     Action = "isolate"
	Restore     Action = "restore"
	Remove      Action = "remove"
	ForceRemove Action = "force-remove"
)

type Operation struct {
	ID                                       string
	Action                                   Action
	Generation, Revision, ConfigurationIndex uint64
	Epoch                                    uint64
}
type Node struct {
	Keys       []IdentityTransition `json:",omitempty"`
	Retirement *RemovalProbe        `json:",omitempty"`
	// Recovery is the signed `sfcd recover` plan that retired this member
	// when the cluster lost its voter majority (instead of a Retirement probe).
	Recovery *Recovery `json:",omitempty"`
	// Restored is the restore generation that retired this member when the
	// cluster was rebuilt from a backup on a new server.
	Restored             uint64 `json:",omitempty"`
	Member               Member
	Generation, Revision uint64
	Phase                Phase
	Pending              *Operation
	Closure              *Proof
}
type Topology struct {
	cluster       [32]byte
	revision      uint64
	epoch         uint64
	configuration Configuration
	nodes         map[string]Node
	// Completed operation identities remain reserved. They must not silently
	// become a different request after a process restart or node re-admission.
	operations map[string]Operation
	// restores are the `sfcd restore` records, oldest first.
	restores []ClusterRestore
}

func New(cluster [32]byte, c Configuration) (Topology, error) {
	if cluster == ([32]byte{}) || c.Validate() != nil {
		return Topology{}, ErrLifecycle
	}
	t := Topology{cluster: cluster, revision: 1, epoch: 1, configuration: ownConfig(c), nodes: map[string]Node{}, operations: map[string]Operation{}}
	for _, m := range c.Members {
		t.nodes[m.ID] = Node{Member: m, Generation: c.Index, Revision: 1, Phase: Active}
	}
	return t, nil
}
func ownNode(n Node) Node {
	n.Keys = OwnIdentityTransitions(n.Keys)
	n.Recovery = ownRecovery(n.Recovery)
	if n.Retirement != nil {
		v := *n.Retirement
		v.Signature = slices.Clone(v.Signature)
		n.Retirement = &v
	}
	if n.Pending != nil {
		v := *n.Pending
		n.Pending = &v
	}
	if n.Closure != nil {
		v := *n.Closure
		v.Signature = slices.Clone(v.Signature)
		n.Closure = &v
	}
	return n
}
func (t Topology) Node(id string) (Node, bool)  { n, ok := t.nodes[id]; return ownNode(n), ok }
func (t Topology) Configuration() Configuration { return ownConfig(t.configuration) }
func (t Topology) Epoch() uint64                { return t.epoch }
func (t Topology) Revision() uint64             { return t.revision }
func (t Topology) Cluster() [32]byte            { return t.cluster }
func (t Topology) Operations() []Operation {
	operations := make([]Operation, 0, len(t.operations))
	for _, operation := range t.operations {
		operations = append(operations, operation)
	}
	slices.SortFunc(operations, func(a, b Operation) int { return strings.Compare(a.ID, b.ID) })
	return operations
}
func (t Topology) AdmitWork(id string) bool {
	n, ok := t.nodes[id]
	_, member := t.configuration.Member(id)
	return ok && member && n.Phase == Active
}
func (t Topology) clone() (Topology, error) {
	if t.cluster == ([32]byte{}) || t.nodes == nil || t.operations == nil || t.configuration.Validate() != nil || t.revision == ^uint64(0) {
		return t, ErrLifecycle
	}
	n := Topology{cluster: t.cluster, revision: t.revision + 1, epoch: t.epoch, configuration: ownConfig(t.configuration), nodes: map[string]Node{}, operations: map[string]Operation{}}
	for id, v := range t.nodes {
		n.nodes[id] = ownNode(v)
	}
	for id, v := range t.operations {
		n.operations[id] = v
	}
	for _, r := range t.restores {
		n.restores = append(n.restores, ownRestore(r))
	}
	return n, nil
}

// Begin runs only for a committed system-admin request. The transport/FSM must
// retain its request receipt; this core never resubmits unknown requests.
func (t Topology) Begin(node, id string, action Action, expected, epoch uint64) (Topology, error) {
	if action == ForceRemove {
		return t, ErrLifecycle
	}
	return t.begin(node, id, action, expected, epoch)
}
func (t Topology) begin(node, id string, action Action, expected, epoch uint64) (Topology, error) {
	v, exists := t.nodes[node]
	if epoch != t.epoch || epoch == 0 || !exists || !validID(id) || v.Revision != expected || v.Pending != nil || len(t.operations) >= 4096 {
		return t, ErrLifecycle
	}
	if _, used := t.operations[id]; used {
		return t, ErrLifecycle
	}
	switch action {
	case Isolate:
		if v.Phase != Active {
			return t, ErrLifecycle
		}
		v.Phase = Isolating
	case Restore:
		if v.Phase != Isolated {
			return t, ErrLifecycle
		}
		v.Phase = Restoring
	case Remove, ForceRemove:
		if v.Phase != Active && v.Phase != Isolated || len(t.configuration.Members) <= 1 || v.Member.Voter && t.configuration.Voters() <= 1 {
			return t, ErrLifecycle
		}
		// Several accepted removals must not reserve the final member/voter.
		// Native dispatch stays serial, but planning two removals against the
		// same old configuration must not strand an unavoidable final removal.
		remaining, voters := 0, 0
		for _, member := range t.configuration.Members {
			if member.ID == node || (t.nodes[member.ID].Phase == Removing || t.nodes[member.ID].Phase == Retiring) {
				continue
			}
			remaining++
			if member.Voter {
				voters++
			}
		}
		if remaining == 0 || voters == 0 {
			return t, ErrLifecycle
		}
		v.Phase = Removing
		if action == ForceRemove {
			v.Phase = Retiring
		}
	default:
		return t, ErrLifecycle
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	op := Operation{ID: id, Action: action, Generation: v.Generation, Revision: n.revision, ConfigurationIndex: t.configuration.Index, Epoch: t.epoch}
	v.Revision = n.revision
	v.Pending = &op
	v.Closure = nil
	n.nodes[node] = v
	n.operations[id] = op
	return n, nil
}

// RotateOperations opens an explicit new request window only after every
// admitted operation is settled. Closed evidence remains reserved for snapshot
// validation; stale requests retain their old epoch and can never execute anew.
func (t Topology) RotateOperations(expectedRevision, expectedEpoch uint64) (Topology, error) {
	if expectedRevision != t.revision || expectedEpoch != t.epoch || t.epoch == ^uint64(0) {
		return t, ErrLifecycle
	}
	for _, v := range t.nodes {
		if v.Pending != nil {
			return t, ErrLifecycle
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	n.epoch++
	n.operations = map[string]Operation{}
	for _, v := range n.nodes {
		if v.Retirement != nil {
			op, ok := t.operations[v.Retirement.Operation]
			if !ok {
				return t, ErrLifecycle
			}
			n.operations[op.ID] = op
		}
		if v.Closure != nil {
			op, ok := t.operations[v.Closure.Operation]
			if !ok {
				return t, ErrLifecycle
			}
			n.operations[op.ID] = op
		}
	}
	return n, nil
}

// Proof is an owner-signed aggregation of actual local closure/recovery
// observations. Isolation cannot be completed from remote silence, lost sockets,
// a leader's role, or an administrator asserting that effects were cancelled.
type Proof struct {
	Cluster                                   [32]byte
	Node, Operation                           string
	Generation, Revision, ConfigurationIndex  uint64
	Resources, Flows, Writers, Leases, CDJobs uint32
	Closed, Ready                             bool
	Signature                                 []byte
}

func ProofBytes(p Proof) []byte {
	p.Signature = nil
	b, _ := json.Marshal(p)
	return append([]byte("sfc-node-lifecycle-1\x00"), b...)
}
func (t Topology) Observe(p Proof) (Topology, error) {
	v, ok := t.nodes[p.Node]
	if !ok || v.Pending == nil {
		return t, ErrLifecycle
	}
	op := *v.Pending
	if p.Cluster != t.cluster || p.Operation != op.ID || p.Generation != v.Generation || p.Generation != op.Generation || p.Revision != op.Revision || p.ConfigurationIndex != t.configuration.Index || p.ConfigurationIndex < op.ConfigurationIndex || p.Closed == p.Ready || !ed25519.Verify(ed25519.PublicKey(v.Member.Key[:]), ProofBytes(p), p.Signature) {
		return t, ErrLifecycle
	}
	if op.Action == ForceRemove {
		return t, ErrLifecycle
	}
	if op.Action == Restore {
		if v.Phase != Restoring || !p.Ready {
			return t, ErrLifecycle
		}
	} else if !p.Closed || p.Resources|p.Flows|p.Writers|p.Leases|p.CDJobs != 0 {
		return t, ErrLifecycle
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	v.Revision = n.revision
	p.Signature = slices.Clone(p.Signature)
	v.Closure = &p
	if op.Action == Isolate {
		v.Phase = Isolated
		v.Pending = nil
	} else if op.Action == Restore {
		v.Phase = Active
		v.Pending = nil
	}
	n.nodes[p.Node] = v
	return n, nil
}

// CommitConfiguration consumes a real SDK-committed configuration, not a proposal
// or a majority count provided by clients. Removing a member also requires the
// original owner-closure evidence or an explicit logical retirement record.
// Neither path permits offline promotion or manufactures native closure.
func (t Topology) CommitConfiguration(cluster [32]byte, c Configuration) (Topology, error) {
	if cluster != t.cluster || c.Validate() != nil || c.Index < t.configuration.Index {
		return t, ErrLifecycle
	}
	if c.Index == t.configuration.Index {
		if !slices.Equal(c.Members, t.configuration.Members) {
			return t, ErrLifecycle
		}
		return t, nil
	}
	for _, m := range t.configuration.Members {
		if next, exists := c.Member(m.ID); exists {
			if next.Key != m.Key {
				return t, ErrLifecycle
			}
			continue
		}
		v := t.nodes[m.ID]
		closed := v.Phase == Removing && v.Pending != nil && v.Pending.Action == Remove && v.Closure != nil && v.Closure.Closed
		retired := v.Phase == Retiring && v.Pending != nil && v.Pending.Action == ForceRemove && v.Retirement != nil
		if !closed && !retired {
			return t, ErrLifecycle
		}
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	n.configuration = ownConfig(c)
	for id, v := range n.nodes {
		if _, exists := c.Member(id); !exists && v.Phase != Removed && v.Phase != Retired {
			v.Phase = Removed
			if v.Retirement != nil {
				v.Phase = Retired
			}
			v.Pending = nil
			v.Revision = n.revision
			n.nodes[id] = v
		}
	}
	for _, m := range c.Members {
		v, exists := n.nodes[m.ID]
		if !exists || v.Phase == Removed || v.Phase == Retired {
			v = Node{Member: m, Generation: c.Index, Revision: n.revision, Phase: Active}
		} else {
			v.Member = m
		}
		n.nodes[m.ID] = v
	}
	return n, nil
}

type topologyRecord struct {
	Schema        uint8
	Cluster       [32]byte
	Revision      uint64
	Epoch         uint64
	Configuration Configuration
	Nodes         []Node
	Operations    []Operation
	Restores      []ClusterRestore `json:",omitempty"`
}

func (t Topology) Encode() ([]byte, error) {
	r := topologyRecord{Schema: 1, Cluster: t.cluster, Revision: t.revision, Epoch: t.epoch, Configuration: ownConfig(t.configuration)}
	for _, v := range t.nodes {
		r.Nodes = append(r.Nodes, ownNode(v))
	}
	for _, v := range t.operations {
		r.Operations = append(r.Operations, v)
	}
	slices.SortFunc(r.Nodes, func(a, b Node) int { return strings.Compare(a.Member.ID, b.Member.ID) })
	slices.SortFunc(r.Operations, func(a, b Operation) int { return strings.Compare(a.ID, b.ID) })
	for _, v := range t.restores {
		r.Restores = append(r.Restores, ownRestore(v))
	}
	return json.Marshal(r)
}
func Decode(b []byte) (Topology, error) {
	var r topologyRecord
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || r.Schema != 1 || r.Cluster == ([32]byte{}) || r.Revision == 0 || r.Epoch == 0 || r.Configuration.Validate() != nil || len(r.Nodes) > 4096 || len(r.Operations) > 4096 {
		return Topology{}, ErrLifecycle
	}
	t := Topology{cluster: r.Cluster, revision: r.Revision, epoch: r.Epoch, configuration: ownConfig(r.Configuration), nodes: map[string]Node{}, operations: map[string]Operation{}}
	if len(r.Restores) > maxRestores {
		return Topology{}, ErrLifecycle
	}
	for i, v := range r.Restores {
		if !v.Valid() || v.Cluster != r.Cluster || v.Generation != uint64(i)+1 || v.Index() > r.Configuration.Index || i > 0 && v.Index() <= r.Restores[i-1].Index() {
			return Topology{}, ErrLifecycle
		}
		t.restores = append(t.restores, ownRestore(v))
	}
	for _, op := range r.Operations {
		if op.Epoch == 0 || op.Epoch > r.Epoch || !validID(op.ID) || op.Generation == 0 || op.Revision == 0 || op.Revision > r.Revision || op.ConfigurationIndex == 0 || op.ConfigurationIndex > r.Configuration.Index || op.Action != Isolate && op.Action != Restore && op.Action != Remove && op.Action != ForceRemove {
			return Topology{}, ErrLifecycle
		}
		if _, exists := t.operations[op.ID]; exists {
			return Topology{}, ErrLifecycle
		}
		t.operations[op.ID] = op
	}
	for _, v := range r.Nodes {
		if !validID(v.Member.ID) || v.Member.Key == ([32]byte{}) || v.Generation == 0 || v.Generation > r.Configuration.Index || v.Revision == 0 || v.Revision > r.Revision {
			return Topology{}, ErrLifecycle
		}
		originalKey := v.Member.Key
		if len(v.Keys) > 0 {
			originalKey = v.Keys[0].Proof.Old
		}
		currentKey, validKeys := ValidIdentityTransitions(r.Cluster, v.Member.ID, originalKey, v.Keys)
		for _, row := range v.Keys {
			if row.Revision > v.Revision {
				return Topology{}, ErrLifecycle
			}
		}
		if !validKeys || currentKey != v.Member.Key {
			return Topology{}, ErrLifecycle
		}
		if _, exists := t.nodes[v.Member.ID]; exists {
			return Topology{}, ErrLifecycle
		}
		m, member := r.Configuration.Member(v.Member.ID)
		if v.Phase == Removed || v.Phase == Retired {
			if member || v.Pending != nil {
				return Topology{}, ErrLifecycle
			}
		} else if !member || m != v.Member {
			return Topology{}, ErrLifecycle
		}
		switch v.Phase {
		case Active, Isolated, Removed, Retired:
			if v.Pending != nil {
				return Topology{}, ErrLifecycle
			}
		case Isolating, Restoring, Removing, Retiring:
			if v.Pending == nil {
				return Topology{}, ErrLifecycle
			}
		default:
			return Topology{}, ErrLifecycle
		}
		if op := v.Pending; op != nil {
			saved, exists := t.operations[op.ID]
			if !exists || saved != *op || op.Generation != v.Generation || op.Revision > v.Revision || v.Phase == Isolating && op.Action != Isolate || v.Phase == Restoring && op.Action != Restore || v.Phase == Removing && op.Action != Remove || v.Phase == Retiring && op.Action != ForceRemove {
				return Topology{}, ErrLifecycle
			}
		}
		if p := v.Closure; p != nil {
			op, exists := t.operations[p.Operation]
			if !exists || p.Node != v.Member.ID || p.Cluster != r.Cluster || p.Generation != v.Generation || p.Revision != op.Revision || op.Generation != v.Generation || p.ConfigurationIndex > r.Configuration.Index || p.ConfigurationIndex < op.ConfigurationIndex || p.Closed == p.Ready || !verifyNodeProof(v, *p) {
				return Topology{}, ErrLifecycle
			}
			if p.Closed && p.Resources|p.Flows|p.Writers|p.Leases|p.CDJobs != 0 {
				return Topology{}, ErrLifecycle
			}
		}
		if v.Phase == Isolated && (v.Closure == nil || !v.Closure.Closed) {
			return Topology{}, ErrLifecycle
		}
		if v.Phase == Isolating || v.Phase == Restoring {
			if v.Closure != nil {
				return Topology{}, ErrLifecycle
			}
		}
		if p := v.Closure; p != nil {
			op := t.operations[p.Operation]
			if v.Phase == Active && (op.Action != Restore || !p.Ready) || v.Phase == Isolated && op.Action != Isolate || v.Phase == Removed && op.Action != Remove || v.Phase == Removing && (v.Pending == nil || v.Pending.ID != p.Operation || op.Action != Remove) {
				return Topology{}, ErrLifecycle
			}
		}
		if v.Restored != 0 {
			if v.Phase != Retired || v.Retirement != nil || v.Closure != nil || v.Recovery != nil || v.Restored > uint64(len(r.Restores)) {
				return Topology{}, ErrLifecycle
			}
		} else if v.Recovery != nil {
			rec := v.Recovery
			if v.Phase != Retired || v.Retirement != nil || v.Closure != nil || !rec.Valid() || rec.Cluster != r.Cluster || rec.Index() > r.Configuration.Index || slices.Contains(rec.Voters, v.Member.ID) {
				return Topology{}, ErrLifecycle
			}
		} else if v.Phase == Retiring || v.Phase == Retired {
			p := v.Retirement
			if p == nil || !p.Valid() || p.Responding || p.Cluster != r.Cluster || p.Node != v.Member.ID || p.Target != v.Member.Key || p.Expected >= v.Revision || p.ConfigurationIndex > r.Configuration.Index || v.Closure != nil {
				return Topology{}, ErrLifecycle
			}
			op, found := t.operations[p.Operation]
			if !found || op.Action != ForceRemove || op.Generation != v.Generation || op.Epoch != p.Epoch || op.ConfigurationIndex != p.ConfigurationIndex || v.Phase == Retiring && (v.Pending == nil || v.Pending.ID != op.ID) {
				return Topology{}, ErrLifecycle
			}
		} else if v.Retirement != nil {
			return Topology{}, ErrLifecycle
		}
		if v.Phase == Removed && v.Closure == nil {
			return Topology{}, ErrLifecycle
		}
		t.nodes[v.Member.ID] = ownNode(v)
	}
	for _, m := range r.Configuration.Members {
		if _, ok := t.nodes[m.ID]; !ok {
			return Topology{}, ErrLifecycle
		}
	}
	canonical, err := t.Encode()
	if err != nil || !bytes.Equal(canonical, b) {
		return Topology{}, ErrLifecycle
	}
	return t, nil
}

// DropUnjoined forgets id from the installed configuration prefix: a
// non-voter whose join was aborted (and removed from Raft) before it ever
// acknowledged its installation, so it holds no work and no records. The
// next real configuration (already without it) is committed as usual. Its
// node is forgotten; a later join under the same name starts anew.
func (t Topology) DropUnjoined(id string) (Topology, error) {
	old, present := t.configuration.Member(id)
	node, exists := t.nodes[id]
	if !present || !exists || old.Voter || node.Pending != nil || node.Phase != Active {
		return t, ErrLifecycle
	}
	n, err := t.clone()
	if err != nil {
		return t, err
	}
	n.configuration.Members = slices.DeleteFunc(n.configuration.Members, func(m Member) bool { return m.ID == id })
	if n.configuration.Validate() != nil {
		return t, ErrLifecycle
	}
	delete(n.nodes, id) // it never joined: no closure, no history to keep
	return n, nil
}
