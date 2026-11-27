// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
)

// NodeStorageReport binds native evidence to the exact node key, registration
// generation, current module epoch, root CAS and original request identity.
// It confers neither a user management right nor a Volume Start permit.
type NodeStorageReport struct {
	Schema                        uint8
	Cluster, Reporter             [32]byte
	Action                        string
	Expected, Epoch, RootRevision uint64
	Index                         uint64                  // committed quorum-read context, not a native operation ID
	Ready                         *nodestorage.RootFact   `json:",omitempty"`
	Closed                        *nodestorage.RootClosed `json:",omitempty"`
	// Default is the node's own default root (Action "default"), sent once
	// on the node's first run in the cluster. Expected is 0.
	Default   *nodestorage.Definition `json:",omitempty"`
	Signature []byte
}

func NodeStorageReportBytes(r NodeStorageReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-node-storage-report-1\x00"), raw...)
}

func (r NodeStorageReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: NodeStorageKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func (p Policy) ResolveNodeStorageReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var report NodeStorageReport
	if canonical(raw, &report) != nil || caller != report.Reporter {
		return state.Command{}, ErrCatalog
	}
	cmd, err := report.Command()
	if err != nil {
		return cmd, err
	}
	_, _, err = p.nodeStorageReport(s, cmd)
	return cmd, err
}

func (p Policy) nodeStorageReport(s state.State, cmd state.Command) (NodeStorageReport, nodestorage.Reference, error) {
	var r NodeStorageReport
	var ref nodestorage.Reference
	if cmd.Kind != state.ModuleReport || cmd.Key != NodeStorageKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Reporter == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.Index == 0 || r.Index > s.Index() || !ed25519.Verify(r.Reporter[:], NodeStorageReportBytes(r), r.Signature) {
		return r, ref, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || want != cmd {
		return r, ref, ErrCatalog
	}
	switch r.Action {
	case "registered":
		if r.Ready == nil || r.Closed != nil || r.Default != nil || r.Ready.Verify() != nil {
			return r, ref, ErrCatalog
		}
		ref = r.Ready.Root
	case "default":
		d := r.Default
		if d == nil || r.Ready != nil || r.Closed != nil || r.Expected != 0 || d.Key != r.Reporter || d.ID != nodestorage.DefaultRootID || nodestorage.ValidateRootPath(d.Path) != nil {
			return r, ref, ErrCatalog
		}
		// Only the node's active owner registers its default root, as for
		// add-node-storage; the generation is assigned by the catalog.
		if active, err := p.workNodeOwner(s, d.Node); err != nil || active != r.Reporter {
			return r, ref, ErrCatalog
		}
		ref = nodestorage.Reference{Cluster: p.Cluster, Node: d.Node, Key: d.Key, ID: d.ID, Path: d.Path}
	case "closed":
		if r.Closed == nil || r.Ready != nil || r.Default != nil || r.Closed.Verify() != nil {
			return r, ref, ErrCatalog
		}
		ref = r.Closed.Root
	default:
		return r, ref, ErrCatalog
	}
	key, err := p.nodeOwner(s, ref.Node)
	if err != nil || key != r.Reporter || !p.ownsResource(s, key, ref.Key) || ref.Cluster != p.Cluster {
		return r, ref, ErrCatalog
	}
	return r, ref, nil
}

func (p Policy) reduceNodeStorageReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, ref, err := p.nodeStorageReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, state.Invalid
	}
	if r.Default != nil {
		// RegisterDefault refuses a node that ever had a default root, so an
		// operator's removal is not undone by a restart or rejoin.
		if roots, err = roots.RegisterDefault(*r.Default); err != nil {
			return nil, state.ConditionFailed
		}
		return p.nodeStorageCheckpoint(s, roots)
	}
	root, ok := roots.Root(ref.Node, ref.ID)
	if !ok || root.Revision != r.Expected || root.Reference(p.Cluster) != ref {
		return nil, state.ConditionFailed
	}
	if r.Ready != nil {
		roots, err = roots.Observe(*r.Ready, r.Reporter)
	} else {
		v, e := p.Volumes(s)
		if e != nil {
			return nil, state.Invalid
		}
		if registeredOnRoot(v, ref) != 0 {
			return nil, state.ConditionFailed
		}
		roots, err = roots.ObserveClosed(*r.Closed, r.Reporter)
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	// Repeated native facts may be semantically unchanged. The existing
	// committed root bytes stay stable; the FSM still records the request.
	if roots.Revision() == 0 {
		return nil, state.Invalid
	}
	return p.nodeStorageCheckpoint(s, roots)
}
