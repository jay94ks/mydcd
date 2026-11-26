// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/servicecall"
)

func TestCDProbeRequiresCurrentProviderNodeAssignment(t *testing.T) {
	f, _, _, _, _ := checkerProbePermitFixture(t)
	read := CDProbeRead{Session: f.session, Tenant: "tenant", Query: deployment.GitProbeRequest{App: "first", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}, Epoch: f.s.ModuleEpoch()}
	if err := f.p.CDProbePermit(f.s, read, 10, "node-c"); err == nil {
		t.Fatal("tenant Deploy admitted an unassigned provider")
	}
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	if len(tenant.AllowedNodes) != 2 {
		t.Fatal("explicit two-node assignment fixture changed", tenant.AllowedNodes)
	}
	if err := f.p.CDProbePermit(f.s, read, 10, "node-b"); err != nil {
		t.Fatal("current tenant assignment not consumed", err)
	}
}

// Current signed user policy/Binding/FSM facts are real; owner/native health
// observations are the existing core fixture's injected facts.
func TestServiceCallUsesCallServiceCeilingAndExactHealthyOwner(t *testing.T) {
	f, _, _, consumer, provider := checkerProbePermitFixture(t)
	session := f.session
	session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.CallService}}}
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	q := servicecall.Request{App: "first", Service: "beta", Port: 8080, Path: "/decide", Method: "POST"}
	target, err := f.p.ServiceCallTarget(f.s, session, 10, "tenant", q, consumer)
	if err != nil || !target.Valid() || target.Container.Owner != provider || target.Container.Service != "beta" || target.Address.String() != "10.80.2.10" {
		t.Fatal(target, err)
	}
	read := ServiceCallRead{Session: session, Tenant: "tenant", Request: q, Target: target, Epoch: f.s.ModuleEpoch()}
	if _, err := f.p.ServiceCallPermit(f.s, provider, read, 10); err != nil {
		t.Fatal("current exact owner", err)
	}
	if _, err := f.p.ServiceCallPermit(f.s, consumer, read, 10); err == nil {
		t.Fatal("another member became HTTP owner")
	}
	for _, mutate := range []func(*ServiceCallRead){func(r *ServiceCallRead) { r.Tenant = "other" }, func(r *ServiceCallRead) { r.Target.Address = r.Target.Address.Next() }, func(r *ServiceCallRead) { r.Target.Container.Generation++ }, func(r *ServiceCallRead) { r.Target.Container.NativeID = "foreign" }, func(r *ServiceCallRead) { r.Request.Port++ }, func(r *ServiceCallRead) { r.Epoch++ }} {
		bad := read
		mutate(&bad)
		if _, err := f.p.ServiceCallPermit(f.s, provider, bad, 10); err == nil {
			t.Fatal("altered HTTP source admitted")
		}
	}
	deploy := session
	deploy.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Deploy}}}
	deploy.Signature = ed25519.Sign(f.node, access.SessionBytes(deploy))
	if _, err := f.p.ServiceCallTarget(f.s, deploy, 10, "tenant", q, consumer); err == nil {
		t.Fatal("Deploy widened to CallService")
	}
	if _, err := f.p.ServiceCallTarget(f.s, session, 10, "other", q, consumer); err == nil {
		t.Fatal("cross tenant request")
	}
	q.Service = "absent"
	if target, err := f.p.ServiceCallTarget(f.s, session, 10, "tenant", q, consumer); err != nil || target.Valid() {
		t.Fatal("missing service invented ready Task", target, err)
	}
}

func TestCDProbeRequiresCurrentDeployAndLeavesSharedStateUntouched(t *testing.T) {
	f, _, _, _, _ := checkerProbePermitFixture(t)
	before := f.s.Index()
	root := f.s.Object(AppsKey)
	read := CDProbeRead{Session: f.session, Tenant: "tenant", Query: deployment.GitProbeRequest{App: "first", Repository: "https://git.example/repo.git", Branch: "main", Path: "app.yaml"}, Epoch: f.s.ModuleEpoch()}
	if err := f.p.CDProbePermit(f.s, read, 10, "node-a"); err != nil {
		t.Fatal(err)
	}
	limited := read.Session
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read, access.CallService}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	read.Session = limited
	if err := f.p.CDProbePermit(f.s, read, 10, "node-a"); err == nil {
		t.Fatal("Read/CallService widened to Deploy")
	}
	if f.s.Index() != before || f.s.Object(AppsKey) != root {
		t.Fatal("read probe mutated CD/app state")
	}
}
