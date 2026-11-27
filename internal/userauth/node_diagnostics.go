// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"time"
)

// NodeQuery names the one server a per-node plan or bundle is about.
type NodeQuery struct{ Node string }

func (q NodeQuery) Valid() bool { return lifecycle.ValidID(q.Node) }

func (c Client) NodeDiagnostics(ctx context.Context, peer sfcp.Peer, session access.Session, node string) (control.NodeDiagnosticsBundle, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeDiagnosticsBundle{}, access.ErrInvalid
	}
	bundle, err := call(ctx, c, peer, session, NodeDiagnosticsMethod, NodeQuery{Node: node})
	if err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	if !bundle.Valid(node) {
		return control.NodeDiagnosticsBundle{}, sfcp.ErrAdmission
	}
	return bundle, nil
}

var NodeDiagnosticsMethod = define(Method[NodeQuery, control.NodeDiagnosticsBundle]{Name: "node-diagnostics"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q NodeQuery) (control.NodeDiagnosticsBundle, string) {
	if !s.manageCluster(view, session) {
		return control.NodeDiagnosticsBundle{}, "denied"
	}
	read, err := s.Policy.ReadNodeDiagnostics(view.State, session, time.Now().Unix(), q.Node)
	if err != nil {
		return control.NodeDiagnosticsBundle{}, "denied"
	}
	if s.NodeDiagnostics == nil {
		return control.NodeDiagnosticsBundle{}, "unavailable"
	}
	result, err := s.NodeDiagnostics(ctx, read)
	if err != nil || !result.Valid(q.Node) {
		return control.NodeDiagnosticsBundle{}, "unavailable"
	}
	return result, "ok"
})
