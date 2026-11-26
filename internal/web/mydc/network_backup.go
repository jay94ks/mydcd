// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

// --- REQ-33 (mock): signed network closure after a drain ---

// NetworkClosure is the owner-signed tenancy.NetworkClosure; put it as is in
// fence-network-change (control.NetworkChangeFence.Closed, Expected = the
// change Revision) or as the retire-network payload (Expected = the member
// Revision; bridge members only).
type NetworkClosure = tenancy.NetworkClosure

// NetworkChangeFence: the real fence-network-change payload.
type NetworkChangeFence = control.NetworkChangeFence

// NetworkClosureView: REQ-33 `network-closure` for one network member
// (NetworkMember.ID: the network name for a bridge, "<network>-<node>" for a
// TUN member). Network is that member ID.
type NetworkClosureView struct {
	Tenant, Network, Node string
	Draining              bool
	// Unreachable: the owner server did not answer; nothing else is known.
	Unreachable bool
	// Closed: set when the member is drained and closed; signed by the owner.
	Closed *NetworkClosure `json:",omitempty"`
	// Still in use (when not closed).
	PendingEndpoints, PendingFlows, PendingPins uint64
	NativeGone                                  bool
	Endpoints                                   []ContainerSelection
	ObservedAt                                  int64
}

// --- REQ-35 (mock): what uses a network ---

const (
	NetworkUserService    = "service"
	NetworkUserStandalone = "standalone"
)

// NetworkUsers: REQ-35 `network-users` (tenant Read) for a network name.
// Apps / Standalones are the counts the network row (Network) also carries.
type NetworkUsers struct {
	Tenant, Network   string
	Users             []NetworkUser
	Apps, Standalones int
	ObservedAt        int64
}

// NetworkUser is one app service or standalone container on the network.
// Attached: a container of it is running with an endpoint now (else only
// the definition asks for the network).
type NetworkUser struct {
	Kind                     string // service / standalone
	App, Service, Standalone string `json:",omitempty"`
	Node                     string `json:",omitempty"`
	Attached                 bool
	// Selection of a running container (opens logs etc.), when Attached.
	Selection []ContainerSelection `json:",omitempty"`
}

// --- REQ-34 (mock): volume backup limits ---

// VolumeBackupLimit: the real set-volume-backup-limit payload / limit row.
// Tenant "" is the server-wide limit. In the payload Revision and Owner are
// zero; Change.Expected is the current row Revision (0 = none).
type VolumeBackupLimit = control.VolumeBackupLimit

const ActionSetVolumeBackupLimit = "set-volume-backup-limit"

// VolumeBackupLimits: the fake's internal shape of `volume-backup-limits` (the real read is PublicRead). A tenant member sees its own
// rows and, for the server-wide row, only that it exists (Hidden, zero
// values).
type VolumeBackupLimits struct {
	Rows []BackupLimitRow
}

type BackupLimitRow struct {
	Limit  VolumeBackupLimit
	Hidden bool // server-wide row without values (not a system admin)
	Used   BackupUsage
}

type BackupUsage struct {
	Count, StagingCount uint32
	Bytes, StagingBytes uint64
}
