// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"time"
)

func (c Client) NodeStoragePage(ctx context.Context, target mydcp.Peer, session access.Session, node, after string) (Reply, error) {
	return c.query(ctx, target, session, Request{Method: "node-storage", Node: node, After: after})
}

func (s Service) nodeStorageSpace(ctx context.Context, view cluster.View, q Request, session access.Session) Reply {
	unavailable := Reply{Schema: 1, Code: "unavailable"}
	denied := Reply{Schema: 1, Code: "denied"}
	if q.NodeStorage == nil || s.NodeStorageObserver == nil {
		return unavailable
	}
	root, err := s.Policy.NodeStorageRead(view.State, session, time.Now().Unix(), *q.NodeStorage)
	if err != nil {
		return denied
	}
	value, err := s.NodeStorageObserver(ctx, root)
	if err != nil {
		return unavailable
	}
	roots, err := s.Policy.NodeStorage(view.State)
	if err != nil {
		return unavailable
	}
	if _, err = roots.Capacities([]nodestorage.Space{value}); err != nil || value.Root != root.Reference(s.Policy.Cluster) {
		return unavailable
	}
	latest, err := s.Engine.Read(ctx, true)
	if err != nil || latest.Local {
		return unavailable
	}
	current, err := s.Policy.NodeStorageRead(latest.State, session, time.Now().Unix(), *q.NodeStorage)
	a, _ := json.Marshal(root)
	b, _ := json.Marshal(current)
	if err != nil || !bytes.Equal(a, b) {
		return denied
	}
	book, err := s.Policy.NodeStorage(latest.State)
	if err != nil {
		return unavailable
	}
	return Reply{Schema: 1, Code: "ok", RootRevision: latest.State.Object(control.CatalogKey).Revision, ModuleEpoch: latest.State.ModuleEpoch(), NodeStorageRootRevision: latest.State.Object(control.NodeStorageKey).Revision, NodeStorageRevision: book.Revision(), NodeStorageObservedIndex: latest.State.Index(), NodeStorageSpace: &value}
}

func (c Client) NodeStorageSpace(ctx context.Context, target mydcp.Peer, session access.Session, selection control.NodeStorageSelection) (Reply, error) {
	reply, err := c.query(ctx, target, session, Request{Method: "node-storage-space", NodeStorage: &selection})
	if err != nil {
		return reply, err
	}
	v := reply.NodeStorageSpace
	if v == nil || v.Root.Validate() != nil || v.Root.Cluster != c.Cluster || v.Root.Node != selection.Node || v.Root.ID != selection.ID || reply.NodeStorageObservedIndex == 0 || reply.NodeStorageRootRevision == 0 || reply.ModuleEpoch == 0 {
		return Reply{}, mydcp.ErrAdmission
	}
	if _, err = nodestorage.AggregateSpaces([]nodestorage.Space{*v}); err != nil {
		return Reply{}, mydcp.ErrAdmission
	}
	return reply, nil
}
