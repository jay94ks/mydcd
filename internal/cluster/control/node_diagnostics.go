// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"time"
)

const NodeDiagnosticsMaxBytes = 64 << 10
const NodeDiagnosticsExpandedBytes = 128 << 10

type NodeDiagnosticsRead struct {
	Session                   access.Session
	Node                      string
	Owner                     [32]byte
	At                        int64
	Index, MembersRoot, Epoch uint64
}
type NodeDiagnosticsBundle struct {
	Schema                  uint8
	Node, Format, CreatedAt string
	Bytes, LimitBytes       uint64
	ExpandedLimitBytes      uint64
	Digest                  [32]byte
	Truncated               bool
	Data                    []byte
}

func (b NodeDiagnosticsBundle) Valid(node string) bool {
	_, err := time.Parse(time.RFC3339, b.CreatedAt)
	return b.Schema == 1 && b.Node == node && lifecycle.ValidID(node) && b.Format == "tar+gzip" && err == nil && b.LimitBytes == NodeDiagnosticsMaxBytes && b.ExpandedLimitBytes == NodeDiagnosticsExpandedBytes && b.Bytes == uint64(len(b.Data)) && len(b.Data) > 0 && len(b.Data) <= NodeDiagnosticsMaxBytes && sha256.Sum256(b.Data) == b.Digest
}
func (p Policy) ReadNodeDiagnostics(s state.State, session access.Session, at int64, node string) (NodeDiagnosticsRead, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeDiagnosticsRead{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return NodeDiagnosticsRead{}, err
	}
	if !lifecycle.ValidID(node) || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return NodeDiagnosticsRead{}, access.ErrDenied
	}
	owner, err := current.nodeOwner(s, node)
	if err != nil {
		return NodeDiagnosticsRead{}, err
	}
	return NodeDiagnosticsRead{Session: session, Node: node, Owner: owner, At: at, Index: s.Index(), MembersRoot: s.Object(MembersKey).Revision, Epoch: s.ModuleEpoch()}, nil
}
