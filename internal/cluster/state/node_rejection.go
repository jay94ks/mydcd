// SPDX-License-Identifier: Apache-2.0

package state

// Typed node refusals are ordinary retained operation results. Existing Code
// values remain fixed; the reason is public deterministic metadata, not a
// second operation/rejection store or a retry permission.
const (
	NodeLastVoter Code = LedgerFull + 1 + iota
	NodeQuorumLoss
	NodeOperationPending
	NodeFixedVolumePresent
	NodeStorageNotDrained
	NodeSelfRemoval
	NodeNativeUnsettled
	NodeTasksPresent
	NodeConfigurationPending
	NodeStillResponding
	NodeShellDisabled
	NodeShellNotReady
	NodeShellLimit
	NodeShellUnreachable
	// NetworkSystemRange: a workspace network's subnet or tunnel address
	// overlaps the system network range.
	NetworkSystemRange
)

func RejectionReason(code Code) string {
	switch code {
	case NodeLastVoter:
		return "LAST_VOTER"
	case NodeQuorumLoss:
		return "QUORUM_LOSS"
	case NodeOperationPending:
		return "NODE_OPERATION_PENDING"
	case NodeFixedVolumePresent:
		return "FIXED_VOLUME_PRESENT"
	case NodeStorageNotDrained:
		return "NODE_STORAGE_NOT_DRAINED"
	case NodeSelfRemoval:
		return "SELF_REMOVAL"
	case NodeNativeUnsettled:
		return "NATIVE_UNSETTLED"
	case NodeTasksPresent:
		return "TASKS_PRESENT"
	case NodeConfigurationPending:
		return "CONFIGURATION_NOT_INSTALLED"
	case NodeStillResponding:
		return "NODE_RESPONDING"
	case NodeShellDisabled:
		return "node-shell-disabled"
	case NodeShellNotReady:
		return "node-shell-not-ready"
	case NodeShellLimit:
		return "limit"
	case NodeShellUnreachable:
		return "node-unreachable"
	case NetworkSystemRange:
		return "system-range-overlap"
	}
	return ""
}
func ValidResultCode(code Code) bool { return code <= NetworkSystemRange }
func (r Result) ValidReason() bool {
	return ValidResultCode(r.Code) && r.Reason == RejectionReason(r.Code)
}
