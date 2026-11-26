// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/tests/gitfixture"
)

// Consume the existing handoff runtime before its ordinary voter promotion.
// Only this learner has rq8-provider-read; the original leader has git-read.
// Neither a leader relay nor a fallback to another installed profile can satisfy
// both positive and negative controls. The original app/CD/native state stays put.
func verifyManagedNonVoterCDProbe(t *testing.T, ctx context.Context, leader, provider *Runtime, original userauth.Client, ingress mydcp.Peer, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), source *gitfixture.Fixture, query deployment.GitProbeRequest, commit string, size int64, fingerprint func() [32]byte) {
	t.Helper()
	view, err := provider.currentView(ctx)
	if err != nil || view.Local || provider.Engine().IsLeader() {
		t.Fatal("original Git provider did not consume a current nonleader prefix", err)
	}
	members, err := p.Members(view.State)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := leader.Mesh.Peer(mydcp.Identity(provider.Identity.Public))
	entry, found := members.Entry(peer.ID)
	if !ok || !found || entry.Peer.Key != provider.Identity.Actor() || entry.Peer.Voter || !members.WorkKey(provider.Identity.Public) {
		t.Fatal("existing Git provider is not the installed working non-voter")
	}
	if _, ok := leader.gitCredentials["tenant/rq8-provider-read"]; ok {
		t.Fatal("non-voter-only profile was also installed on the leader")
	}
	if _, ok := provider.gitCredentials["tenant/git-read"]; ok {
		t.Fatal("leader-only profile was also installed on the non-voter")
	}
	mesh, err := mydcp.NewTransport(original.Self, original.Cluster, func(key mydcp.Identity) (mydcp.Peer, bool) {
		if key == ingress.Key {
			return ingress, true
		}
		return peer, key == peer.Key
	})
	if err != nil {
		t.Fatal(err)
	}
	defer mesh.Close()
	client := original
	client.Mesh, client.Peers = mesh, []mydcp.Peer{ingress, peer}
	create := func(id string, operations []string) access.Session {
		t.Helper()
		key, err := identity.Ephemeral()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(key.Private)
		change(id+"-user", "put-user", 0, access.User{ID: id, Username: id, Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true, Operations: operations}}})
		change(id+"-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: id, Role: access.Manager, Enabled: true})
		// Login stays on the original actual voter issuer. Probe alone is pinned
		// to the non-voter holding the installation-local Git profile.
		session, err := client.Login(ctx, ingress, id, key.Private)
		if err != nil {
			t.Fatal("current Manager provider-probe login", err)
		}
		return session
	}
	operator := create("rq8-provider-operator", nil)
	limited := create("rq8-provider-ceiling", []string{"service-call"})
	query.Credential = "rq8-provider-read"
	baseline := fingerprint()
	unchanged := func() {
		t.Helper()
		if fingerprint() != baseline {
			t.Fatal("non-voter diagnostic changed original app/CD/candidate/Binding/native state")
		}
	}
	positive := func() {
		t.Helper()
		before := source.Stats()
		result, err := client.ProbeCD(ctx, peer, operator, "tenant", query)
		after := source.Stats()
		if err != nil || !result.Valid() || result.Code != "" || result.Node != peer.ID || result.Commit != commit || result.Size != size || after.Advertisements <= before.Advertisements || after.Packs <= before.Packs {
			t.Fatal("actual non-voter Git probe did not consume its original profile/source", result, err)
		}
		unchanged()
	}
	noProfile := func(target mydcp.Peer, q deployment.GitProbeRequest) {
		t.Helper()
		before := source.Stats()
		result, err := client.ProbeCD(ctx, target, operator, "tenant", q)
		if err != nil || !result.Valid() || result.Code != "no-credential" || result.Node != target.ID || result.Commit != "" || result.Size != 0 || !reflect.DeepEqual(before, source.Stats()) {
			t.Fatal("probe borrowed another provider/profile or reached the source", result, err)
		}
		unchanged()
	}
	denied := func(session access.Session, tenant string) {
		t.Helper()
		before := source.Stats()
		result, err := client.ProbeCD(ctx, peer, session, tenant, query)
		var refusal *userauth.Error
		if !errors.As(err, &refusal) || refusal.Code != "denied" || refusal.Phase != mydcp.Completed || result.Commit != "" || result.Size != 0 || !reflect.DeepEqual(before, source.Stats()) {
			t.Fatal("current non-voter probe authority refusal reached Git or returned data", result, err)
		}
		unchanged()
	}
	// The installed learner is not automatically a tenant execution/provider
	// node. Prove the current refusal before the ordinary administrator grant.
	catalog, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, exists := catalog.Tenant("tenant")
	if !exists || slices.Contains(tenant.AllowedNodes, peer.ID) {
		t.Fatal("provider assignment negative control missing")
	}
	denied(operator, "tenant")
	change("rq8-provider-assignment", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: append(slices.Clone(tenant.AllowedNodes), peer.ID)})
	positive()
	noProfile(ingress, query) // Leader cannot consume the non-voter's profile.
	wrong := query
	wrong.Credential = "git-read"
	noProfile(peer, wrong) // Non-voter cannot silently relay to the leader.
	wrong = query
	wrong.Repository += "/other.git"
	noProfile(peer, wrong) // The profile is pinned to its exact repository.
	denied(limited, "tenant")
	denied(operator, "rq8-other") // Existing foreign tenant from the same root.
	before := source.Stats()
	_, err = provider.probeCD(ctx, control.CDProbeRead{Session: operator, Tenant: "tenant", Query: query, Epoch: view.State.ModuleEpoch() - 1})
	if err == nil || !reflect.DeepEqual(before, source.Stats()) {
		t.Fatal("non-voter probe admitted a stale original epoch", err)
	}
	setRole := func(id string, role access.Role) {
		t.Helper()
		catalog, err := p.Catalog(read().State)
		if err != nil {
			t.Fatal(err)
		}
		member, ok := catalog.Membership("tenant", operator.User)
		if !ok {
			t.Fatal("original non-voter probe membership missing")
		}
		change(id, "set-membership", member.Revision, access.Membership{Tenant: "tenant", User: operator.User, Role: role, Enabled: true})
	}
	// Hold the actual HTTPS pack response, withdraw Deploy while I/O is in
	// flight, then require the provider's post-I/O current check to suppress it.
	gate := source.HoldNextPack()
	defer gate.Release()
	type outcome struct {
		result deployment.GitProbeResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := client.ProbeCD(ctx, peer, operator, "tenant", query)
		completed <- outcome{result, err}
	}()
	select {
	case <-gate.Entered:
	case got := <-completed:
		t.Fatal("non-voter probe did not enter the original held Git pack", got.result, got.err)
	case <-ctx.Done():
		t.Fatal("non-voter probe original source entry", ctx.Err())
	}
	setRole("rq8-provider-withdraw", access.Viewer)
	gate.Release()
	select {
	case got := <-completed:
		var refusal *userauth.Error
		if !errors.As(got.err, &refusal) || refusal.Code != "denied" || refusal.Phase != mydcp.Completed || got.result.Commit != "" || got.result.Size != 0 {
			t.Fatal("non-voter post-I/O probe disclosed data after current membership withdrawal", got.result, got.err)
		}
	case <-ctx.Done():
		t.Fatal("non-voter post-I/O probe response", ctx.Err())
	}
	if _, err := client.Query(ctx, peer, operator, "apps", "tenant"); err != nil {
		t.Fatal("current Viewer lost ordinary Read", err)
	}
	denied(operator, "tenant")
	setRole("rq8-provider-restore", access.Manager)
	positive()
	unchanged()
}
