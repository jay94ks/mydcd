// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"time"
)

func (c Client) NodeDiagnostics(ctx context.Context, peer mydcp.Peer, session access.Session, node string) (control.NodeDiagnosticsBundle, error) {
	if !lifecycle.ValidID(node) {
		return control.NodeDiagnosticsBundle{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "node-diagnostics", Node: node})
	if err != nil {
		return control.NodeDiagnosticsBundle{}, err
	}
	if reply.NodeDiagnostics == nil || !reply.NodeDiagnostics.Valid(node) {
		return control.NodeDiagnosticsBundle{}, mydcp.ErrAdmission
	}
	return *reply.NodeDiagnostics, nil
}
func (s Service) nodeDiagnosticsReply(ctx context.Context, view cluster.View, session access.Session, node string) Reply {
	read, err := s.Policy.ReadNodeDiagnostics(view.State, session, time.Now().Unix(), node)
	if err != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	if s.NodeDiagnostics == nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	result, err := s.NodeDiagnostics(ctx, read)
	if err != nil || !result.Valid(node) {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	return Reply{Schema: 1, Code: "ok", NodeDiagnostics: &result}
}
