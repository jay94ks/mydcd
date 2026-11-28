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

// Registry and image queries over the fixture's real loopback SFCP and SDK Raft: each
// reaches its handler through Params, and a session's tenant scope still
// decides who may read.
func TestRegistryQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
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
	page, err := f.client.RegistryPage(f.ctx, f.peers[0], f.session, "tenant", "")
	if err != nil || page.RootRevision == 0 && len(page.Items) != 0 {
		t.Fatal("registries", err)
	}
	if _, err = f.client.ExternalRegistryPage(f.ctx, f.peers[0], f.session, "tenant", ""); err != nil {
		t.Fatal("external registries", err)
	}
	var refused *Error
	if _, err = f.client.RegistryPage(f.ctx, f.peers[0], f.session, "other", ""); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("another tenant's registries", err)
	}
	if _, err = f.client.PlanRegistryMaintenance(f.ctx, f.peers[0], f.session, "tenant", control.RegistryMaintenanceQuery{Action: "gc-registry", ID: "private"}); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("maintenance plan with read only", err)
	}
	if page, err := f.client.ImageUsages(f.ctx, f.peers[0], f.session, "tenant", control.ImageUsageQuery{}, ""); err != nil || page.Tenant != "tenant" {
		t.Fatal("image usages", err)
	}
	if _, err = f.client.ImageCacheStatus(f.ctx, f.peers[0], f.session, "missing-original"); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("image cache status without cluster administration", err)
	}
	if _, err = f.client.RegistryCredential(f.ctx, f.peers[0], f.session, RegistryCredentialQuery{Tenant: "tenant", ID: "missing", Actions: []string{"pull"}}); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("credential for a missing registry", err)
	}
}
