// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"github.com/jay94ks/seafield/internal/schema"
)

type Report struct {
	Schema uint8
	Node   Node
}

func DecodeReport(b []byte) (Report, error) {
	r, err := schema.Decode[Report](b)
	n := r.Node
	if err != nil || r.Schema != 1 || n.ID == "" || n.Generation == 0 || n.Revision == 0 || n.ObservedAt == 0 || len(n.Labels) > 128 || n.Ready && (n.Used.CPU > n.Capacity.CPU || n.Used.Memory > n.Capacity.Memory) {
		return r, ErrPlacement
	}
	return r, nil
}

// PlacementInput is an explicit read-only proposal request. The returned spec
// still requires an ordinary authenticated CAS/ledger command and Raft commit.
type PlacementInput struct {
	Schema       uint8
	Key, Network string
	Expected     uint64
	Template     ContainerSpec
	Labels       map[string]string
}
type PlacementPlan struct {
	Schema   uint8
	Key      string
	Expected uint64
	Proposal Proposal
	Spec     ContainerSpec
}
