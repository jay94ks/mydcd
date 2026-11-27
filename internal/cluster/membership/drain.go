// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"slices"
)

// Drain stores only the original signed management input and selected public
// plan. App execution/retirement remains in the existing app inventories.
type Drain struct {
	Started         []string `json:",omitempty"`
	Pending         uint32   `json:",omitempty"`
	Node, Operation string
	Origin, Plan    json.RawMessage
}

func (d Directory) BeginDrain(node, operation string, expected uint64, origin, plan json.RawMessage, pending ...uint32) (Directory, error) {
	if !d.writable() || !lifecycle.ValidID(operation) || len(plan) == 0 || len(plan) > 64<<10 || !json.Valid(plan) {
		return d, ErrMember
	}
	for _, old := range d.Drains {
		if old.Operation == operation {
			return d, ErrMember
		}
	}
	n := d
	var err error
	if cordon := d.Cordon(node); !cordon.Enabled {
		n, err = d.SetCordon(node, expected, true, origin)
		if err != nil {
			return d, err
		}
	} else if cordon.Revision != expected {
		return d, ErrMember
	}
	if len(n.Drains) >= 128 {
		return d, ErrMember
	}
	n = clone(n)
	n.Revision++
	count := uint32(0)
	if len(pending) > 1 {
		return d, ErrMember
	}
	if len(pending) == 1 {
		count = pending[0]
	}
	if count > 128 {
		return d, ErrMember
	}
	n.Drains = append(n.Drains, Drain{Pending: count, Node: node, Operation: operation, Origin: bytes.Clone(origin), Plan: bytes.Clone(plan)})
	return n, n.Validate()
}
func (d Directory) validateDrains() error {
	if len(d.Drains) > 128 {
		return ErrMember
	}
	seen := map[string]bool{}
	for _, row := range d.Drains {
		if row.Pending > 128 || len(row.Started) > 128 {
			return ErrMember
		}
		seenChildren := map[string]bool{}
		for _, id := range row.Started {
			if !lifecycle.ValidID(id) || seenChildren[id] {
				return ErrMember
			}
			seenChildren[id] = true
		}
		if !lifecycle.ValidID(row.Node) || !lifecycle.ValidID(row.Operation) || seen[row.Operation] || len(row.Origin) == 0 || len(row.Origin) > 64<<10 || !json.Valid(row.Origin) || len(row.Plan) == 0 || len(row.Plan) > 64<<10 || !json.Valid(row.Plan) {
			return ErrMember
		}
		if _, found := d.Entry(row.Node); !found {
			return ErrMember
		}
		seen[row.Operation] = true
	}
	return nil
}
func ownDrains(rows []Drain) []Drain {
	out := slices.Clone(rows)
	for i := range out {
		out[i].Started = slices.Clone(out[i].Started)
		out[i].Origin = bytes.Clone(out[i].Origin)
		out[i].Plan = bytes.Clone(out[i].Plan)
	}
	return out
}

func (d Directory) StartDrainMove(node, operation, child string) (Directory, error) {
	if !d.writable() || !lifecycle.ValidID(child) {
		return d, ErrMember
	}
	n := clone(d)
	for i, row := range n.Drains {
		if row.Node != node || row.Operation != operation {
			continue
		}
		if row.Pending == 0 || slices.Contains(row.Started, child) {
			return d, ErrMember
		}
		n.Revision++
		n.Drains[i].Started = append(row.Started, child)
		n.Drains[i].Pending--
		return n, n.Validate()
	}
	return d, ErrMember
}
