// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Typed Vault and storage queries over the fixture's real loopback SFCP and
// SDK Raft: each reaches its handler through Params and returns Data.
func TestTypedVaultStorageQueriesActualWire(t *testing.T) {
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
	peer := f.peers[0]
	if page, err := f.client.NodeStoragePage(f.ctx, peer, f.session, "", ""); err != nil || page.Items == nil {
		t.Fatal("node storage", page, err)
	}
	if page, err := f.client.TenantStoragePage(f.ctx, peer, f.session, "tenant", "", ""); err != nil || page.Index == 0 {
		t.Fatal("tenant storage", page, err)
	}
	if page, err := f.client.QueryVault(f.ctx, peer, f.session, "", ""); err != nil || page.Items == nil {
		t.Fatal("cluster vault", page, err)
	}
	var refused *Error
	reader := f.session
	reader.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(reader))
	// Read alone neither places data on a tenant's roots nor lists every root.
	if _, err := f.client.TenantStoragePage(f.ctx, peer, reader, "tenant", "", ""); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("tenant storage without ManageVolumes or ManageRegistry", err)
	}
	if _, err := f.client.NodeStoragePage(f.ctx, peer, reader, "", ""); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("node storage without ManageCluster", err)
	}
	if _, err := f.client.QueryVault(f.ctx, peer, reader, "tenant", ""); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("vault without ManageSecrets", err)
	}
	// The fixture installs no owner observer, so the leader cannot measure.
	if _, err := f.client.NodeStorageSpace(f.ctx, peer, f.session, control.NodeStorageSelection{Node: "node-a", ID: "hdd"}); !errors.As(err, &refused) || refused.Code == "ok" {
		t.Fatal("node storage space without an observer", err)
	}
}
