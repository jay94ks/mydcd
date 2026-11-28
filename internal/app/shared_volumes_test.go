// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"

	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// After a node key rotation the earlier key's historical owner opens its
// modules on the same transport. It must not register VolumeFS again: the
// transport takes one handler per purpose, and the refused second one
// failed every sfcd start after a rotation (lab jay3, 2026-11-28).
func TestHistoricalOwnerDoesNotServeSharedVolumesAgain(t *testing.T) {
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	mesh, err := sfcp.NewTransport(self, [32]byte{1}, func(sfcp.Identity) (sfcp.Peer, bool) { return sfcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	// The current-key runtime already serves VolumeFS.
	if err = mesh.OnVolumeFS(func(context.Context, *sfcp.Session, []byte, []byte) ([]byte, []byte, error) { return nil, nil, nil }); err != nil {
		t.Fatal(err)
	}
	historical := &Runtime{historicalOwner: true, Mesh: mesh, activations: &volumes.Activations{}}
	if err = historical.openSharedVolumes(t.TempDir()); err != nil {
		t.Fatal("historical owner start failed:", err)
	}
	if historical.sharedHome != nil || historical.remoteMounts != nil {
		t.Fatal("historical owner opened shared volumes")
	}
}
