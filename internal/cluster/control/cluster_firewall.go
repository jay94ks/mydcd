// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/firewall"
)

// ClusterFirewallKey is the cluster's own firewall: the default policy and
// the shared rules every managed server applies under its own
// (devel/design/node-firewall.md "클러스터 기본값"). Unlike a server's
// firewall it lives in Raft, because every server must apply the same
// committed value.
const ClusterFirewallKey = "control/firewall"

// ClusterFirewallAction changes the cluster firewall: payload firewall.Delta,
// Change.Expected the revision it was read at.
const ClusterFirewallAction = "set-cluster-firewall"

// ClusterFirewallChange is the last committed change, kept for its event.
type ClusterFirewallChange struct {
	Origin   UserOperation
	From, To uint64
	Added    []string `json:",omitempty"`
}

type clusterFirewallCheckpoint struct {
	Schema   uint8
	Cluster  [32]byte
	Firewall firewall.State
	Last     ClusterFirewallChange
}

// ClusterFirewall is the committed cluster firewall; before its first change
// it is firewall.NewCluster().
func (p Policy) ClusterFirewall(s state.State) (firewall.State, error) {
	f, _, err := p.clusterFirewall(s)
	return f, err
}

func (p Policy) clusterFirewall(s state.State) (firewall.State, ClusterFirewallChange, error) {
	raw, revision, err := readCheckpoint(s, ClusterFirewallKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return firewall.State{}, ClusterFirewallChange{}, err
	}
	if raw == nil {
		return firewall.NewCluster(), ClusterFirewallChange{}, nil
	}
	var disk clusterFirewallCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Firewall.Scope != firewall.ScopeCluster || !disk.Firewall.Valid() || disk.Firewall.Revision != revision || disk.Last.To != revision || disk.Last.From+1 != revision || disk.Last.Origin.VerifyOriginal(p.Cluster) != nil || disk.Last.Origin.Change.Action != ClusterFirewallAction || disk.Last.Origin.Change.Expected != disk.Last.From {
		return firewall.State{}, ClusterFirewallChange{}, ErrCatalog
	}
	if disk.Firewall.Rules == nil {
		disk.Firewall.Rules = []firewall.Rule{}
	}
	return disk.Firewall, disk.Last, nil
}

func (p Policy) reduceClusterFirewall(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind != state.Module || cmd.Key != ClusterFirewallKey {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	users, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(users, cmd, false)
	if err != nil || op.Change.Action != ClusterFirewallAction || p.authorizeChange(s, users, op) != nil {
		return nil, state.Forbidden
	}
	var d firewall.Delta
	if canonical(op.Change.Payload, &d) != nil || d.Empty() {
		return nil, state.Invalid
	}
	current, _, err := p.clusterFirewall(s)
	if err != nil {
		return nil, state.Invalid
	}
	next, added, err := current.Change(op.Change.Expected, d)
	if err != nil {
		return nil, state.ConditionFailed
	}
	raw, err := json.Marshal(clusterFirewallCheckpoint{Schema: 1, Cluster: p.Cluster, Firewall: next, Last: ClusterFirewallChange{Origin: op, From: current.Revision, To: next.Revision, Added: added}})
	if err != nil || len(raw) > 1<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, ClusterFirewallKey, p.Cluster, p.TrustRoot, next.Revision, raw)
}

// clusterFirewallBook is the ClusterFirewallKey Raft book (see book.go).
var clusterFirewallBook = Book{
	Key:       ClusterFirewallKey,
	Actions:   []string{ClusterFirewallAction},
	Reduce:    Policy.reduceClusterFirewall,
	Authorize: authorizeSystemCluster,
	Events:    clusterFirewallEvents,
}

func clusterFirewallEvents(p Policy, before, after state.State, emit eventEmitter) error {
	old, _, err := p.clusterFirewall(before)
	if err != nil {
		return err
	}
	next, last, err := p.clusterFirewall(after)
	if err != nil || next.Revision == old.Revision {
		return err
	}
	var d firewall.Delta
	_ = canonical(last.Origin.Change.Payload, &d)
	detail := eventlog.Detail{Operation: last.Origin.RequestID, FromVersion: last.From, ToVersion: last.To}
	eventReason(&detail, last.Origin)
	detail.OperatorReason, detail.Reason = detail.Reason, firewall.Summary(d, last.Added)
	emit("cluster-firewall-changed", "cluster", eventlog.Target{}, detail)
	return nil
}

// authorizeSystemCluster is a cluster manager who is also a system
// administrator, as for a server's own firewall.
func authorizeSystemCluster(p Policy, s state.State, c access.Catalog, op UserOperation) error {
	if err := authorizeCluster(p, s, c, op); err != nil || !c.SystemAllowed(op.Session.User) {
		return access.ErrDenied
	}
	return nil
}

// ClusterFirewallQuery is the cluster-firewall read; it takes nothing.
type ClusterFirewallQuery struct{}

// ClusterFirewallView is the committed cluster firewall.
type ClusterFirewallView struct {
	Schema   uint8
	Firewall firewall.State
	MaxRules int
}

func (v ClusterFirewallView) Valid() bool {
	return v.Schema == 1 && v.Firewall.Scope == firewall.ScopeCluster && v.Firewall.Valid()
}

// ReadClusterFirewall is the cluster firewall for a system administrator.
func (p Policy) ReadClusterFirewall(s state.State, session access.Session, at int64) (ClusterFirewallView, error) {
	current, err := p.Current(s)
	if err != nil {
		return ClusterFirewallView{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return ClusterFirewallView{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil || !c.SystemAllowed(session.User) {
		return ClusterFirewallView{}, access.ErrDenied
	}
	f, err := current.ClusterFirewall(s)
	if err != nil {
		return ClusterFirewallView{}, err
	}
	return ClusterFirewallView{Schema: 1, Firewall: f, MaxRules: firewall.MaxRules}, nil
}
