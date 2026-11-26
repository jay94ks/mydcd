// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/maintenance"
)

type CompactWorkRequest struct{ Operation string }
type CompactWork struct {
	Schema                                                  uint8
	Cluster, Owner                                          [32]byte
	Operation, Node, Leader, State                          string
	NodeRevision, RootRevision, Epoch, Index, AcceptedIndex uint64
	Options                                                 maintenance.CompactOptions
	Target                                                  [32]byte
	CanBegin, Allowed                                       bool
}

func (p Policy) CompactWork(s state.State, caller [32]byte, q CompactWorkRequest, leader string) (CompactWork, error) {
	var out CompactWork
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	members, err := p.Members(s)
	if err != nil || !members.MemberKey(caller) {
		return out, access.ErrDenied
	}
	c, err := p.Compactions(s)
	if err != nil {
		return out, err
	}
	record, ok := c.Record(q.Operation)
	if !ok {
		return out, access.ErrDenied
	}
	node := ""
	var selected maintenance.CompactNode
	for _, n := range record.Job.Nodes {
		if n.Key == caller {
			node = n.Node
			selected = n
			break
		}
	}
	if node == "" {
		return out, access.ErrDenied
	}
	users, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	allowed := users.OperationAllowed(record.Origin.Session, "raft-compact") == nil && users.AuthorizeAccepted(record.Origin.Session, p.Cluster, record.Origin.At, "", access.ManageCluster, "") == nil
	out = CompactWork{Schema: 1, Cluster: p.Cluster, Owner: caller, Operation: q.Operation, Node: node, Leader: leader, State: selected.State, NodeRevision: selected.Revision, RootRevision: s.Object(CompactKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), AcceptedIndex: record.AcceptedIndex, Options: record.Job.Options, Target: record.Plan.Target, Allowed: allowed, CanBegin: record.Job.CanBegin(node, leader)}
	return out, nil
}
