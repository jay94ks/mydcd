// SPDX-License-Identifier: Apache-2.0

package mydc

// RQ12 advanced server actions (system admin). The payloads and
// plans are mydcd's control types (fake_node_ops_real.go); the views below
// are the fake's own working state behind them.

const (
	ActionDrainNode          = "drain-node"
	ActionDemoteNode         = "demote-node"
	ActionRotateNodeIdentity = "rotate-node-identity"
	ActionForceRemoveNode    = "force-remove-node"
)

// Refusal and blocked-task codes.
const (
	NodeFixedVolume = "FIXED_VOLUME" // task bound to a fixed volume on the server
	NodeNoTarget    = "NO_TARGET"    // no other allowed, ready server
	NodeNotVoter    = "NOT_VOTER"
	NodeLastVoter   = "LAST_VOTER"
	NodeQuorumLoss  = "QUORUM_LOSS"
	NodeUnknown     = "NODE_UNKNOWN"
)

// drainPlanView: where each task on the server goes (To) or why it stays
// (Blocked).
type drainPlanView struct {
	Node  string
	Tasks []drainTask
	Plan  [32]byte
}

type drainTask struct {
	Tenant, App, Service, Instance string
	To                             string `json:",omitempty"`
	Blocked                        string `json:",omitempty"`
}

// voterPlanView: what demote-node (or a removal) leaves: voters, quorum,
// tolerated failures.
type voterPlanView struct {
	Node        string
	Code        string `json:",omitempty"`
	VotersAfter int
	Quorum      int
	Tolerates   int
	Plan        [32]byte
}
