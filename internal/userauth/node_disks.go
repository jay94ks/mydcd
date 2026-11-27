// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// NodeDiskMethod formats, mounts or unmounts one additional disk of a
// server, or reads such an operation back (Action status). A system
// administrator only; it never goes through Raft
// (devel/proposals/node-disk-management.md §4.2).
var NodeDiskMethod = define(Method[control.NodeDiskOp, control.NodeDiskResult]{Name: "node-disk"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, op control.NodeDiskOp) (control.NodeDiskResult, string) {
	read, err := s.Policy.ReadNodeDisk(view.State, session, time.Now().Unix(), op)
	if err != nil {
		return control.NodeDiskResult{}, "denied"
	}
	if s.NodeDiskChanger == nil {
		return control.NodeDiskResult{}, "unavailable"
	}
	result, err := s.NodeDiskChanger(ctx, read)
	if err != nil {
		if errors.Is(err, ErrNodeDiskMissing) {
			return control.NodeDiskResult{}, "missing"
		}
		return control.NodeDiskResult{}, "unavailable"
	}
	if !result.Valid() || result.Operation != op.Operation || result.Node != op.Node {
		return control.NodeDiskResult{}, "unavailable"
	}
	return result, "ok"
})

// ErrNodeDiskMissing: no operation with that ID on the server.
var ErrNodeDiskMissing = errors.New("no such disk operation")

// NodeDisk sends one disk operation (or its status read) through target.
func (c Client) NodeDisk(ctx context.Context, target sfcp.Peer, session access.Session, op control.NodeDiskOp) (control.NodeDiskResult, error) {
	r, err := call(ctx, c, target, session, NodeDiskMethod, op)
	if err == nil && (!r.Valid() || r.Operation != op.Operation || r.Node != op.Node) {
		return control.NodeDiskResult{}, sfcp.ErrFrame
	}
	return r, err
}
