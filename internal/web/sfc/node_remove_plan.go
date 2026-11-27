// SPDX-License-Identifier: Apache-2.0

package sfc

import "github.com/jay94ks/seafield/internal/cluster/state"

// the fake's remove check behind PlanNodeRemoval (control.NodeRemovePlan)
// and remove-node.

const (

	// Blocker codes; remove-node refuses with the same code (ResultErrorCode).
	// LAST_VOTER and QUORUM_LOSS are NodeLastVoter / NodeQuorumLoss.
	NodeOperationPending  = "NODE_OPERATION_PENDING"
	NodeFixedVolumeStays  = "FIXED_VOLUME_PRESENT"
	NodeStorageNotDrained = "NODE_STORAGE_NOT_DRAINED"
	NodeSelfRemoval       = "SELF_REMOVAL"
)

// Result codes for a refused node operation: sfcd's state codes, with
// Result.Reason = the blocker code (state.RejectionReason).
const (
	ResultLastVoter             = state.NodeLastVoter
	ResultQuorumLoss            = state.NodeQuorumLoss
	ResultNodeOperationPending  = state.NodeOperationPending
	ResultFixedVolumePresent    = state.NodeFixedVolumePresent
	ResultNodeStorageNotDrained = state.NodeStorageNotDrained
	ResultSelfRemoval           = state.NodeSelfRemoval
	ResultNativeUnsettled       = state.NodeNativeUnsettled
	ResultTasksPresent          = state.NodeTasksPresent
	ResultConfigurationPending  = state.NodeConfigurationPending
	ResultNodeResponding        = state.NodeStillResponding
	// REQ-67 open-node-shell refusals (Result.Reason = the Code name).
	ResultNodeShellDisabled    = state.NodeShellDisabled
	ResultNodeShellNotReady    = state.NodeShellNotReady
	ResultNodeShellLimit       = state.NodeShellLimit
	ResultNodeShellUnreachable = state.NodeShellUnreachable
)

// More blocker codes (RQ12).
const (
	NodeNativeUnsettled      = "NATIVE_UNSETTLED"
	NodeTasksPresent         = "TASKS_PRESENT"
	NodeConfigurationPending = "CONFIGURATION_NOT_INSTALLED"
	NodeResponding           = "NODE_RESPONDING"
)

// removePlanView: the remove check. Epoch and Expected go unchanged into
// remove-node (control.NodeLifecycleChange{ID, Operation, Epoch}, Expected).
type removePlanView struct {
	Node                string
	Epoch, Expected     uint64
	Removable           bool
	Blockers            []removeBlocker
	VotersBefore        int
	VotersAfter         int
	QuorumAfter         int
	FaultToleranceAfter int
	Tasks               []removeTask
	Storage             []removeStorage
	PendingOperation    string `json:",omitempty"`
}

type removeBlocker struct {
	Code   string
	Detail string `json:",omitempty"`
}

// removeTask: an app task (App/Service/Instance) or a standalone
// container (Standalone) on the node. Reason is set when it cannot move
// (FIXED_VOLUME, NO_TARGET, PINNED_TO_NODE).
type removeTask struct {
	Tenant     string
	App        string `json:",omitempty"`
	Service    string `json:",omitempty"`
	Instance   string `json:",omitempty"`
	Standalone string `json:",omitempty"`
	Movable    bool
	Reason     string `json:",omitempty"`
}

// removeStorage: a storage root on the node; Volumes are the fixed
// volumes (tenant/name) registered on it, Bytes their used bytes.
type removeStorage struct {
	ID, Path string
	Volumes  []string
	Bytes    uint64 `json:",omitempty"`
	Drained  bool
}

// NodePinned: a standalone container cannot move off its node.
const NodePinned = "PINNED_TO_NODE"
