// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"encoding/json"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/control"
)

// REQ-28 files in a tenant volume (the web's automatic backups).
//
// Real shape (docs/reference/volume-files.md): VolumeFilePlan gives the
// control.VolumeFileChange to sign with Expected = plan.Revision; Submit
// reserves the job; VolumeFile streams the body once (purpose18) and
// VolumeFileStatus reads the job by VolumeFileID. Grants carry
// access.VolumeFileFolderGrant.

const (
	ActionGetVolumeFile         = "volume-file-get"
	ActionListVolumeFiles       = "volume-file-list"
	ActionPutVolumeFile         = "volume-file-put"
	ActionDeleteVolumeFile      = "volume-file-delete"
	ActionGrantVolumeFiles      = "volume-file-grant"
	ActionRevokeVolumeFileGrant = "volume-file-revoke"
)

// MaxVolumeFileBytes: the web's cap for one backup file (mydcd allows up
// to volumes.MaxFileBytes, 1 GiB).
const MaxVolumeFileBytes = 256 << 20

// VolumeFileGrant: a stored folder grant (tenant manager). User may list,
// read, write and delete files under Prefix of Volume only. App "" is the
// tenant-registered volume. The action payload is
// access.VolumeFileFolderGrant (Revision 0, Expected = TenantMembers
// Collection).
type VolumeFileGrant struct {
	Tenant, App, Volume, Prefix string
	User                        string
}

// VolumeFileID: the job ID of a signed volume-file-put/get/list/delete
// (control.VolumeFileID), for VolumeFileStatus after a lost reply.
func VolumeFileID(op SignedOp) (string, error) {
	var v control.UserOperation
	if err := json.Unmarshal(op, &v); err != nil || v.RequestID == "" {
		return "", errors.New("mydc: malformed signed operation")
	}
	return control.VolumeFileID(v), nil
}
