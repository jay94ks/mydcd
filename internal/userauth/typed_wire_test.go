// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Typed node and cluster queries over the fixture's real loopback SFCP and
// SDK Raft: each reaches its handler through Params and returns Data.
func TestTypedNodeQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
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
	node := f.peers[0].ID
	if plan, err := f.client.NodeRemovePlan(f.ctx, f.peers[0], f.session, node); err != nil || plan.Node != node {
		t.Fatal("remove plan", err)
	}
	if plan, err := f.client.NodeDemotePlan(f.ctx, f.peers[0], f.session, node); err != nil || plan.Node != node {
		t.Fatal("demote plan", err)
	}
	if page, err := f.client.TasksPage(f.ctx, f.peers[0], f.session, control.TaskSelection{}, ""); err != nil || page.RootRevision == 0 && len(page.Tasks) != 0 {
		t.Fatal("tasks", err)
	}
	plan, err := f.client.CompactPlan(f.ctx, f.peers[0], f.session, control.CompactSelection{Mode: "minimal", Retain: 1000})
	if err != nil || len(plan.Nodes) == 0 {
		t.Fatal("compact plan", err)
	}
	var refused *Error
	if _, err := f.client.CompactStatus(f.ctx, f.peers[0], f.session, CompactStatusQuery{Operation: "missing-original"}); !errors.As(err, &refused) || refused.Code == "ok" {
		t.Fatal("missing compaction original", err)
	}
	if _, err := f.client.NodeDrainStatus(f.ctx, f.peers[0], f.session, control.NodeDrainQuery{Node: node}); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("drain status without an original", err)
	}
}

// The network reads (resources, network-dns-names, PublicRead) over the
// same real wire: a page comes back as Data, a foreign selector is refused.
func TestTypedNetworkQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
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
	if page, err := f.client.Resources(f.ctx, f.peers[0], f.session, ResourcesQuery{}); err != nil || page.Index == 0 || len(page.Items) == 0 {
		t.Fatal("resources", page, err)
	}
	if page, err := f.client.PublicRead(f.ctx, f.peers[0], f.session, "route-endpoints", "tenant", control.PublicReadQuery{}, ""); err != nil || page.Method != "route-endpoints" || page.Tenant != "tenant" {
		t.Fatal("route-endpoints", page, err)
	}
	if _, err := f.client.NetworkDNSNames(f.ctx, f.peers[0], f.session, NetworkDNSNamesQuery{Tenant: "tenant", Network: "missing"}); err != nil {
		t.Fatal("dns names", err)
	}
	reader := f.session
	reader.Scopes = []access.Scope{{Tenant: "other", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(reader))
	var refused *Error
	if _, err := f.client.Resources(f.ctx, f.peers[0], reader, ResourcesQuery{Tenant: "tenant"}); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("resources of a tenant the session cannot read", err)
	}
	if _, err := f.client.PublicRead(f.ctx, f.peers[0], f.session, "network-users", "tenant", control.PublicReadQuery{Node: "node-a"}, ""); err == nil {
		t.Fatal("foreign selector sent")
	}
}

// ingresses and the tunnel reconnect reads over the same real wire: an
// ingress page from the owner observer, and refusals for a missing reconnect
// original and for a plan with no observations to plan from.
func TestTypedIngressAndTunnelQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = fullUserScopes()
	f.session.Signature = ed25519.Sign(f.nodes[0].Private, access.SessionBytes(f.session))
	f.service.IngressObserver = func(ctx context.Context, read control.IngressRead) (control.IngressPage, error) {
		view, err := f.engines[0].Read(ctx, true)
		if err != nil {
			return control.IngressPage{}, err
		}
		return f.service.Policy.IngressPage(view.State, read.Session, read.At, read.Query)
	}
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
	page, err := f.client.Ingresses(f.ctx, f.peers[0], f.session, control.IngressQuery{Part: "mappings"})
	if err != nil || page.Schema != 1 || page.Index == 0 {
		t.Fatal("ingresses", page, err)
	}
	var refused *Error
	if _, err := f.client.TunnelReconnectStatus(f.ctx, f.peers[0], f.session, "missing-original"); !errors.As(err, &refused) || refused.Code != "conflict" {
		t.Fatal("reconnect status without an original", err)
	}
	if _, err := f.client.TunnelReconnectPlan(f.ctx, f.peers[0], f.session, f.peers[0].ID, f.peers[1].ID); !errors.As(err, &refused) || refused.Code == "ok" {
		t.Fatal("reconnect plan without observations", err)
	}
}

// lifecycles and lifecycle-source over the actual wire: the tenant's empty
// book pages with its revisions, and another tenant is denied.
func TestTypedLifecycleQueriesActualWire(t *testing.T) {
	f := newVolumeFileWireFixture(t)
	f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.ManageServices}}}
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
	page, err := f.client.Lifecycles(f.ctx, f.peers[0], f.session, LifecyclesQuery{Tenant: "tenant"})
	if err != nil || len(page.Items) != 0 || page.Next != "" {
		t.Fatal("lifecycles", page, err)
	}
	var refused *Error
	if _, err := f.client.Lifecycles(f.ctx, f.peers[0], f.session, LifecyclesQuery{Tenant: "other"}); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("other tenant's lifecycles", err)
	}
	if _, err := f.client.LifecycleSource(f.ctx, f.peers[0], f.session, "other", "ready", 1); !errors.As(err, &refused) || refused.Code != "denied" {
		t.Fatal("other tenant's lifecycle source", err)
	}
}
