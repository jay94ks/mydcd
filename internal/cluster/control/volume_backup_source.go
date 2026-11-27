// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// VolumeBackupSource is a read-only preflight. It exposes no native name,
// host path, session, task command/environment or file data. The fingerprint
// selects the exact public writer recipe, not a database recovery guarantee.
type VolumeBackupSource struct {
	Schema                       uint8
	Scope                        volumes.Scope
	Node                         string
	Owner                        [32]byte
	NativeBinding, Compatibility [32]byte
	Image                        string
	WriterGeneration             uint64
	Exit                         volumes.ProcessExit
}

func VolumeNativeDigest(ready volumes.NativeReady) [32]byte {
	return volumes.NativeBindingDigest(ready)
}
func (s VolumeBackupSource) Valid(cluster [32]byte, tenant string, q VolumeSelector) bool {
	id, err := hex.DecodeString(strings.TrimPrefix(s.Image, "sha256:"))
	return s.Schema == 1 && s.Scope.Cluster == cluster && s.Scope.Tenant == tenant && s.Scope.App == q.App && s.Scope.ID == q.ID && q.Valid() && lifecycle.ValidID(tenant) && s.Scope.Generation > 0 && lifecycle.ValidID(s.Node) && s.Owner != ([32]byte{}) && s.NativeBinding != ([32]byte{}) && s.Compatibility != ([32]byte{}) && len(s.Image) == 71 && strings.HasPrefix(s.Image, "sha256:") && err == nil && len(id) == 32 && hex.EncodeToString(id) == s.Image[7:] && s.WriterGeneration > 0 && s.Exit.Clean()
}
func (s VolumeBackupSource) Matches(ready volumes.NativeReady) bool {
	return ready.Verify() == nil && s.Valid(ready.Spec.Scope.Cluster, ready.Spec.Scope.Tenant, VolumeSelector{App: ready.Spec.Scope.App, ID: ready.Spec.Scope.ID}) && s.Scope == ready.Spec.Scope && s.Node == ready.Owner.Node && s.Owner == ready.Owner.Key && s.NativeBinding == VolumeNativeDigest(ready)
}
