// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestVolumeBackupSourcePublicBindingAndCleanExit(t *testing.T) {
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32))
	ready := volumeFact(t, volumes.Scope{Cluster: [32]byte{82}, Tenant: "tenant", App: "app", ID: "data", Generation: 1}, "node-a", node)
	value := VolumeBackupSource{Schema: 1, Scope: ready.Spec.Scope, Node: ready.Owner.Node, Owner: ready.Owner.Key, NativeBinding: VolumeNativeDigest(ready), Compatibility: [32]byte{1}, Image: "sha256:" + strings.Repeat("a", 64), WriterGeneration: 2, Exit: volumes.ProcessExit{StartedAt: "2026-11-12T00:00:00Z", FinishedAt: "2026-11-12T00:00:01Z", Status: "exited"}}
	if !value.Matches(ready) {
		t.Fatal("valid source")
	}
	for _, alter := range []func(*VolumeBackupSource){
		func(v *VolumeBackupSource) { v.Scope.Tenant = "foreign" },
		func(v *VolumeBackupSource) { v.Scope.Generation++ },
		func(v *VolumeBackupSource) { v.Node = "other" },
		func(v *VolumeBackupSource) { v.Owner = [32]byte{1} },
		func(v *VolumeBackupSource) { v.NativeBinding = [32]byte{1} },
		func(v *VolumeBackupSource) { v.Compatibility = [32]byte{} },
		func(v *VolumeBackupSource) { v.Image = "repo:latest" },
		func(v *VolumeBackupSource) { v.Image = "sha256:" + strings.Repeat("A", 64) },
		func(v *VolumeBackupSource) { v.WriterGeneration = 0 },
		func(v *VolumeBackupSource) { v.Exit.Code = 137 },
		func(v *VolumeBackupSource) { v.Exit.OOM = true },
		func(v *VolumeBackupSource) { v.Exit.FinishedAt = "" },
	} {
		bad := value
		alter(&bad)
		if bad.Matches(ready) {
			t.Fatal("invalid source accepted", bad)
		}
	}
}
