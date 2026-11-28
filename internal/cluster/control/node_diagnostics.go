// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"slices"
	"time"
)

const NodeDiagnosticsMaxBytes = 64 << 10
const NodeDiagnosticsExpandedBytes = 128 << 10

// NodeDiagnosticsMaxCPUProfileSeconds bounds the optional CPU profile a
// diagnostics read records; the whole read must answer inside the 30s SFCP
// handler deadline (local socket and node-to-node relay alike).
const NodeDiagnosticsMaxCPUProfileSeconds = 20

type NodeDiagnosticsRead struct {
	Session                   access.Session
	Node                      string
	Owner                     [32]byte
	At                        int64
	Index, MembersRoot, Epoch uint64
	// CPUProfileSeconds asks the owner to record a CPU profile this long
	// (0 = none, at most NodeDiagnosticsMaxCPUProfileSeconds).
	CPUProfileSeconds uint8 `json:",omitempty"`
}
type NodeDiagnosticsBundle struct {
	Schema                  uint8
	Node, Format, CreatedAt string
	Bytes, LimitBytes       uint64
	ExpandedLimitBytes      uint64
	Digest                  [32]byte
	Truncated               bool
	// Omitted says what Truncated stands for, in fixed codes:
	// events-gap (the server's event log itself missed events, e.g. engine
	// events before it started), events-older (only the newest 100 events
	// are kept), events-unavailable (an event log could not be read),
	// profile-goroutine / profile-cpu (a profile did not fit the limits).
	Omitted []string `json:",omitempty"`
	Data    []byte
}

// NodeDiagnosticsOmissions are the codes Omitted may hold.
var NodeDiagnosticsOmissions = []string{"events-gap", "events-older", "events-unavailable", "profile-goroutine", "profile-cpu"}

func validOmissions(codes []string, truncated bool) bool {
	if len(codes) > len(NodeDiagnosticsOmissions) || len(codes) > 0 && !truncated {
		return false
	}
	for i, c := range codes {
		if !slices.Contains(NodeDiagnosticsOmissions, c) || slices.Contains(codes[:i], c) {
			return false
		}
	}
	return true
}

func (b NodeDiagnosticsBundle) Valid(node string) bool {
	_, err := time.Parse(time.RFC3339, b.CreatedAt)
	return b.Schema == 1 && b.Node == node && lifecycle.ValidID(node) && b.Format == "tar+gzip" && err == nil && b.LimitBytes == NodeDiagnosticsMaxBytes && b.ExpandedLimitBytes == NodeDiagnosticsExpandedBytes && b.Bytes == uint64(len(b.Data)) && len(b.Data) > 0 && len(b.Data) <= NodeDiagnosticsMaxBytes && sha256.Sum256(b.Data) == b.Digest && validOmissions(b.Omitted, b.Truncated)
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
