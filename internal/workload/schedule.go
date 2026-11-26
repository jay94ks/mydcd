// SPDX-License-Identifier: Apache-2.0

// Package workload provides placement proposals; only a later committed command
// can change Desired. Observations and time are explicit immutable inputs.
package workload

import (
	"errors"
	"math/bits"
)

var ErrPlacement = errors.New("invalid placement input or no eligible capacity")

type Resources struct{ CPU, Memory uint64 }
type Node struct {
	ID                               string
	Generation, Revision, ObservedAt uint64
	Capacity, Used                   Resources
	Ready, Draining                  bool
	Labels                           map[string]string
}
type Eligibility struct{ Generation, MinRevision uint64 }
type Task struct {
	Revision uint64
	Current  string
	Need     Resources
	Labels   map[string]string
	Move     bool
}
type Proposal struct {
	Node               string
	ExpectedRevision   uint64
	Preserved, Blocked bool
}

func ratioLess(a, b, c, d uint64) int {
	hi, lo := bits.Mul64(a, d)
	hj, lj := bits.Mul64(c, b)
	if hi < hj || hi == hj && lo < lj {
		return -1
	}
	if hi == hj && lo == lj {
		return 0
	}
	return 1
}
func fresh(n Node, e Eligibility, now, age uint64) bool {
	return n.Generation == e.Generation && n.Generation > 0 && n.Revision >= e.MinRevision && n.ObservedAt <= now && now-n.ObservedAt <= age && n.Ready && !n.Draining && n.Capacity.CPU > 0 && n.Capacity.Memory > 0 && n.Used.CPU <= n.Capacity.CPU && n.Used.Memory <= n.Capacity.Memory
}
func Propose(t Task, nodes []Node, eligible map[string]Eligibility, now, maxAge uint64) (Proposal, error) {
	if t.Current != "" && t.Revision == 0 || t.Move && t.Current == "" || t.Need.CPU == 0 || t.Need.Memory == 0 || maxAge == 0 {
		return Proposal{}, ErrPlacement
	}
	seen := map[string]bool{}
	for _, n := range nodes {
		if n.ID == "" || seen[n.ID] {
			return Proposal{}, ErrPlacement
		}
		seen[n.ID] = true
	}
	// A stale/missing health report cannot silently evict an existing user.
	if t.Current != "" && !t.Move {
		p := Proposal{Node: t.Current, ExpectedRevision: t.Revision, Preserved: true, Blocked: true}
		for _, n := range nodes {
			if n.ID == t.Current {
				e, ok := eligible[n.ID]
				p.Blocked = !ok || !fresh(n, e, now, maxAge)
			}
		}
		return p, nil
	}
	var best *Node
	for i := range nodes {
		n := &nodes[i]
		e, ok := eligible[n.ID]
		if !ok || !fresh(*n, e, now, maxAge) || t.Need.CPU > n.Capacity.CPU-n.Used.CPU || t.Need.Memory > n.Capacity.Memory-n.Used.Memory {
			continue
		}
		matches := true
		for k, v := range t.Labels {
			if got, ok := n.Labels[k]; !ok || got != v {
				matches = false
				break
			}
		}
		if !matches {
			continue
		}
		if best == nil {
			best = n
			continue
		}
		a := ratioLess(n.Used.CPU, n.Capacity.CPU, best.Used.CPU, best.Capacity.CPU)
		b := ratioLess(n.Used.Memory, n.Capacity.Memory, best.Used.Memory, best.Capacity.Memory)
		if a < 0 || a == 0 && (b < 0 || b == 0 && n.ID < best.ID) {
			best = n
		}
	}
	if best == nil {
		return Proposal{}, ErrPlacement
	}
	return Proposal{Node: best.ID, ExpectedRevision: t.Revision}, nil
}
