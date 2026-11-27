// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/workload/volumes"
)

func TestVolumeUsagePublicBindingRejectsTamperedObservations(t *testing.T) {
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{79}, 32))
	ready := volumeFact(t, volumes.Scope{Cluster: [32]byte{80}, Tenant: "tenant", App: "app", ID: "data", Generation: 1}, "node-a", node)
	value := volumes.Usage{Schema: 1, Scope: ready.Spec.Scope, Owner: ready.Owner, Generation: ready.Generation, QuotaMode: "observe", Entries: 2, Files: 1, Directories: 1, LogicalBytes: 17, AllocatedBytes: 4096, FilesystemBytes: 1 << 20, FilesystemAvailableBytes: 1 << 19}
	if !value.Matches(ready) {
		t.Fatal("valid public binding")
	}
	for _, alter := range []func(*volumes.Usage){
		func(v *volumes.Usage) { v.Scope.Tenant = "foreign" },
		func(v *volumes.Usage) { v.Owner.Native = "foreign" },
		func(v *volumes.Usage) { v.Generation++ },
		func(v *volumes.Usage) { v.QuotaMode = "enforced" },
		func(v *volumes.Usage) { v.Snapshot = true },
		func(v *volumes.Usage) { v.Entries = 0 },
		func(v *volumes.Usage) { v.Directories = ^uint64(0) },
		func(v *volumes.Usage) { v.Files = 3 },
		func(v *volumes.Usage) { v.AllocatedBytes++ },
		func(v *volumes.Usage) { v.FilesystemAvailableBytes = v.FilesystemBytes + 1 },
	} {
		bad := value
		alter(&bad)
		if bad.Matches(ready) {
			t.Fatal("tampered observation accepted", bad)
		}
	}
	for _, q := range []VolumeSelector{{}, {App: "app", ID: "../data"}, {App: "/host", ID: "data"}} {
		if q.Valid() {
			t.Fatal("native/path selector accepted", q)
		}
	}
}
