// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"slices"
)

type CompactNode struct {
	Node     string
	Key      [32]byte
	Revision uint64
	State    string
	Result   *CompactResult `json:",omitempty"`
	Code     string         `json:",omitempty"`
}
type CompactJob struct {
	Schema     uint8
	Operation  string
	Options    CompactOptions
	Sequential bool
	Nodes      []CompactNode
}

func NewCompactJob(operation string, options CompactOptions, sequential bool, targets []CompactNode) (CompactJob, error) {
	j := CompactJob{Schema: 1, Operation: operation, Options: options, Sequential: sequential, Nodes: slices.Clone(targets)}
	for i := range j.Nodes {
		j.Nodes[i].Revision = 1
		j.Nodes[i].State = "queued"
		j.Nodes[i].Result = nil
		j.Nodes[i].Code = ""
	}
	slices.SortFunc(j.Nodes, func(a, b CompactNode) int {
		if a.Node < b.Node {
			return -1
		}
		if a.Node > b.Node {
			return 1
		}
		return 0
	})
	return j, j.Validate()
}
func (j CompactJob) Validate() error {
	if j.Schema != 1 || !lifecycle.ValidID(j.Operation) || j.Options.Validate() != nil || len(j.Nodes) == 0 || len(j.Nodes) > 1024 {
		return ErrCompact
	}
	previous := ""
	keys := map[[32]byte]bool{}
	running := 0
	for _, n := range j.Nodes {
		if !lifecycle.ValidID(n.Node) || n.Node <= previous || n.Key == ([32]byte{}) || keys[n.Key] || n.Revision == 0 {
			return ErrCompact
		}
		previous = n.Node
		keys[n.Key] = true
		switch n.State {
		case "queued", "running":
			if n.Result != nil || n.Code != "" {
				return ErrCompact
			}
			if n.State == "running" {
				running++
			}
		case "done":
			if n.Result == nil || n.Result.Validate() != nil || n.Result.ErrorCode != "" || !n.Result.ConfigRestored || !n.Result.TargetMet || !n.Result.Compacted() || n.Code != "" {
				return ErrCompact
			}
		case "failed":
			if n.Code == "" || len(n.Code) > 64 || n.Result != nil && n.Result.Validate() != nil {
				return ErrCompact
			}
		case "skipped":
			if n.Code != "unreachable" || n.Result != nil {
				return ErrCompact
			}
		default:
			return ErrCompact
		}
		if n.Result != nil && (n.Result.Dispatch.Operation != j.Operation || n.Result.Dispatch.Options != j.Options) {
			return ErrCompact
		}
	}
	if j.Sequential && running > 1 {
		return ErrCompact
	}
	return nil
}
func (j CompactJob) Terminal() bool {
	for _, n := range j.Nodes {
		if n.State == "queued" || n.State == "running" {
			return false
		}
	}
	return true
}
func (j CompactJob) Node(node string) (CompactNode, bool) {
	for _, n := range j.Nodes {
		if n.Node == node {
			if n.Result != nil {
				v := *n.Result
				n.Result = &v
			}
			return n, true
		}
	}
	return CompactNode{}, false
}

// The leader is supplied by the current quorum adapter, never elected here.
// A queued new leader waits for every other target, including after handoff.
func (j CompactJob) CanBegin(node, leader string) bool {
	if !lifecycle.ValidID(leader) {
		return false
	}
	target, ok := j.Node(node)
	if !ok || target.State != "queued" {
		return false
	}
	for _, n := range j.Nodes {
		if n.Node == node {
			continue
		}
		pending := n.State == "queued" || n.State == "running"
		if node == leader && pending {
			return false
		}
		if j.Sequential && n.State == "running" {
			return false
		}
		if j.Sequential && n.State == "queued" && n.Node != leader && n.Node < node {
			return false
		}
	}
	return true
}
func (j CompactJob) Begin(node, leader string, expected uint64) (CompactJob, error) {
	n, ok := j.Node(node)
	if j.Validate() != nil || !ok || n.Revision == ^uint64(0) || n.Revision != expected || !j.CanBegin(node, leader) {
		return j, ErrCompact
	}
	j.Nodes = slices.Clone(j.Nodes)
	for i := range j.Nodes {
		if j.Nodes[i].Node == node {
			j.Nodes[i].State = "running"
			j.Nodes[i].Revision++
			break
		}
	}
	return j, j.Validate()
}
func (j CompactJob) Skip(node string, expected uint64) (CompactJob, error) {
	n, ok := j.Node(node)
	if j.Validate() != nil || !ok || n.Revision == ^uint64(0) || n.State != "queued" || n.Revision != expected {
		return j, ErrCompact
	}
	j.Nodes = slices.Clone(j.Nodes)
	for i := range j.Nodes {
		if j.Nodes[i].Node == node {
			j.Nodes[i].State = "skipped"
			j.Nodes[i].Code = "unreachable"
			j.Nodes[i].Revision++
			break
		}
	}
	return j, j.Validate()
}
func (j CompactJob) Finish(node string, expected uint64, result *CompactResult, code string) (CompactJob, error) {
	n, ok := j.Node(node)
	if j.Validate() != nil || !ok || n.Revision == ^uint64(0) || n.State != "running" || n.Revision != expected || result != nil && result.Validate() != nil {
		return j, ErrCompact
	}
	state := "failed"
	if result != nil && result.ErrorCode == "" && result.ConfigRestored && result.TargetMet && result.Compacted() {
		state = "done"
		code = ""
	}
	if state == "failed" && code == "" {
		return j, ErrCompact
	}
	j.Nodes = slices.Clone(j.Nodes)
	for i := range j.Nodes {
		if j.Nodes[i].Node == node {
			j.Nodes[i].State = state
			j.Nodes[i].Code = code
			j.Nodes[i].Revision++
			if result != nil {
				v := *result
				j.Nodes[i].Result = &v
			}
			break
		}
	}
	return j, j.Validate()
}

func (j CompactJob) CancelQueued(node string, expected uint64) (CompactJob, error) {
	n, ok := j.Node(node)
	if j.Validate() != nil || !ok || n.Revision == ^uint64(0) || n.State != "queued" || n.Revision != expected {
		return j, ErrCompact
	}
	j.Nodes = slices.Clone(j.Nodes)
	for i := range j.Nodes {
		if j.Nodes[i].Node == node {
			j.Nodes[i].State = "failed"
			j.Nodes[i].Code = "authority-revoked"
			j.Nodes[i].Revision++
			break
		}
	}
	return j, j.Validate()
}
