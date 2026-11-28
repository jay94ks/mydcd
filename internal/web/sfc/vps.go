// SPDX-License-Identifier: Apache-2.0

package sfc

// VPS actions (devel/design/vps-nodes.md, docs/cli/vps.md). Expected is the
// VPS catalog Revision (QueryVPS) and the root is Whoami.Roots[VPSKey].
// sfcd checks these through its own typed commands.
//
//   - put-vps-account: control.VPSAccountPut (a new account or a new key
//     pair carries the sealed Credential from SealVPSCredential)
//   - remove-vps-account: control.VPSAccountSelection
//   - create-vps-node: control.VPSServerCreate
//   - stop-vps-node: control.VPSServerStop (cordon and drain first)
//   - start-vps-node, delete-vps-node: control.VPSServerSelection
//   - set-vps-node-cap: control.VPSServerCap
const (
	ActionPutVPSAccount    = "put-vps-account"
	ActionRemoveVPSAccount = "remove-vps-account"
	ActionCreateVPSNode    = "create-vps-node"
	ActionStopVPSNode      = "stop-vps-node"
	ActionStartVPSNode     = "start-vps-node"
	ActionDeleteVPSNode    = "delete-vps-node"
	ActionSetVPSNodeCap    = "set-vps-node-cap"
)

// Owned VPS actions (devel/design/vps-hostinger.md). Expected is the owned
// catalog RootRevision (QueryOwnedVPS); an owned vendor's account still
// uses put/remove-vps-account with AccountRootRevision.
//
//   - attach-owned-vps: control.OwnedVPSAttach
//   - detach-owned-vps: control.OwnedVPSSelection (forgets the record only)
//   - set-owned-vps: control.OwnedVPSSet
const (
	ActionAttachOwnedVPS = "attach-owned-vps"
	ActionDetachOwnedVPS = "detach-owned-vps"
	ActionSetOwnedVPS    = "set-owned-vps"
)
