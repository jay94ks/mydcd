// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Typed volume queries over the fixture's real loopback SFCP and SDK Raft:
// each reaches its handler through Params and returns Data.
func TestTypedVolumeQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	// Only node-a serves users here; it answers as the leader.
	if err := f.service.Serve(); err != nil {
		t.Fatal(err)
	}
	for !f.engines[0].IsLeader() {
		_ = f.engines[1].TransferLeadership(f.ctx, f.peers[0].ID, f.peers[0].Endpoint)
		if f.ctx.Err() != nil {
			t.Fatal(f.ctx.Err())
		}
		time.Sleep(50 * time.Millisecond)
	}
	page, err := f.client.VolumePage(f.ctx, f.peers[0], f.session, "tenant", "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Scope.ID != "data" || page.RootRevision == 0 || page.Revision == 0 || page.ModuleEpoch == 0 {
		t.Fatal("volumes", page, err)
	}
	if backups, err := f.client.VolumeBackupPage(f.ctx, f.peers[0], f.session, "tenant", ""); err != nil || backups.Items == nil || backups.RootRevision != page.RootRevision {
		t.Fatal("volume backups", err)
	}
	if status, err := f.client.VolumeFileStatus(f.ctx, f.peers[0], f.session, "tenant", f.job.ID); err != nil || status.ID != f.job.ID {
		t.Fatal("volume file status", err)
	}
	var refused *Error
	if _, err := f.client.VolumeFileStatus(f.ctx, f.peers[0], f.session, "tenant", "missing"); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("missing volume file job", err)
	}
	// The fixture installs no owner observer, so the leader cannot measure.
	if _, err := f.client.VolumeUsage(f.ctx, f.peers[0], f.session, "tenant", control.VolumeSelector{App: "app", ID: "data"}); !errors.As(err, &refused) || refused.Code != "unavailable" {
		t.Fatal("volume usage without an observer", err)
	}
}
