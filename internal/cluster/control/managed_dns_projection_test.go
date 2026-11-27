// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// Configuration/install observations below are injected algorithm facts. No
// real Raft configuration, peer installation, DB, socket or native effect.
func managedDNSProjectionFixture(t *testing.T) (*backupCoreFixture, ed25519.PrivateKey, services.ManagedDNSDefinition) {
	t.Helper()
	f := newBackupCore(t)
	b := joinTestNodeB(t, f)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageNetwork, access.ManageServices)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant("tenant")
	f.apply("dns-two-nodes", "set-nodes", tenant.Revision, NodeChangeTo("tenant", tenant.AllowedNodes, []string{"node-a", "node-b"}), state.Applied)
	for _, scope := range []string{"", "tenant"} {
		for _, node := range []string{"node-a", "node-b"} {
			f.apply("dns-two-limit-"+scope+node, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: node, Capacity: workload.Resources{CPU: 8, Memory: 80}, Networks: 4, MaxConsumers: 8, PacketQueuePackets: 4, PacketQueueBytes: 8192}, state.Applied)
		}
	}
	network := tenancy.TUNDefinition{Tenant: "tenant", Name: "services", Members: []tenancy.TUNNode{
		{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.80.1.0/24"), Gateway: netip.MustParseAddr("10.80.1.1"), MTU: 1280}}},
		{Node: "node-b", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.80.2.0/24"), Gateway: netip.MustParseAddr("10.80.2.1"), MTU: 1280}}},
	}}
	managedDNSChange(t, f, "dns-two-network", "create-tun-network", 0, network, state.Applied)
	definition := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "services", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "apps.sfc.test.", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 4, RequestTimeoutMS: 1000}}
	managedDNSChange(t, f, "dns-two-policy", "configure-network-dns", 0, definition, state.Applied)
	return f, b, definition
}

// joinTestNodeB makes node-b a full member of the fixture's cluster.
func joinTestNodeB(t *testing.T, f *backupCoreFixture) ed25519.PrivateKey {
	t.Helper()
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{125}, 32))
	bkey := [32]byte(b.Public().(ed25519.PublicKey))
	akey := [32]byte(f.node.Public().(ed25519.PublicKey))
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	peer := config.Peer{ID: "node-b", Key: hex.EncodeToString(bkey[:]), Endpoint: "127.0.0.1:8002"}
	d, err = d.Invite(peer, "mock-join-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := d.Entry("node-b")
	d, err = d.Dispatch("node-b", entry.Revision, entry.Job.Pending.ID, 10, akey)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = d.Entry("node-b")
	d, err = d.Observe("node-b", entry.Revision, entry.Job.Pending.ID, 12, peer)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = d.Entry("node-b")
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: "node-b", JoinID: entry.JoinID, Key: bkey, ConfigurationIndex: 12, AppliedIndex: 13}
	ack.Signature = ed25519.Sign(b, membership.AckBytes(ack))
	d, err = d.Installed(ack, entry.Revision)
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "mock-members", Key: MembersKey, Value: "fixture"}, nil, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func managedDNSCoreReport(t *testing.T, f *backupCoreFixture, key ed25519.PrivateKey) NetworkDNSProgress {
	t.Helper()
	owner := [32]byte(key.Public().(ed25519.PublicKey))
	updates, err := f.p.ManagedDNSUpdates(f.s, owner)
	if err != nil || len(updates) != 1 {
		t.Fatal("original derived update", len(updates), err)
	}
	r := updates[0]
	r.Signature = ed25519.Sign(key, NetworkDNSProgressBytes(r))
	return r
}

func applyDNSCoreReport(t *testing.T, f *backupCoreFixture, r NetworkDNSProgress, want state.Code) state.Command {
	t.Helper()
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal("projection commit", result, want, err)
	}
	f.s = next
	return cmd
}

func TestManagedDNSProjectionCoreOwnersCASAndFrozenSnapshot(t *testing.T) {
	f, b, _ := managedDNSProjectionFixture(t)
	first, second := managedDNSCoreReport(t, f, f.node), managedDNSCoreReport(t, f, b)
	command := applyDNSCoreReport(t, f, first, state.Applied)
	before := f.s.Object(AppsKey)
	applyDNSCoreReport(t, f, second, state.ConditionFailed)
	if f.s.Object(AppsKey) != before {
		t.Fatal("CAS loser republished source/serial")
	}
	applyDNSCoreReport(t, f, first, state.Applied)
	if f.s.Object(AppsKey) != before {
		t.Fatal("same report replay changed state")
	}
	if result, found := f.s.LookupResult(command); !found || result.Code != state.Applied {
		t.Fatal("original report receipt missing")
	}
	apps, err := f.p.Apps(f.s)
	if err != nil || len(apps.entries) != 0 || apps.network == nil || len(apps.network.Groups) != 1 {
		t.Fatal("management projection became a fake app", err)
	}
	group := apps.network.Groups[0]
	if !group.Managed || group.App != "" || group.Source != 1 || group.Serial != 1 || len(group.Owners) != 2 {
		t.Fatal("not one atomic logical view")
	}
	for _, key := range []ed25519.PrivateKey{f.node, b} {
		owner := [32]byte(key.Public().(ed25519.PublicKey))
		authority, rows, known := apps.NetworkDNS(owner)
		if !known || len(rows) != 1 || rows[0].Managed == nil || rows[0].Reference == ([32]byte{}) {
			t.Fatal("exact owner not bound")
		}
		ref, found := authority.ReferenceConsumer(rows[0].Reference)
		if !found || ref.Local.Owner != owner || ref.DesiredSource != 1 || ref.Serial != 1 || len(ref.Members) != 2 {
			t.Fatal("reference authority lost members")
		}
		updates, err := f.p.ManagedDNSUpdates(f.s, owner)
		if err != nil || len(updates) != 0 {
			t.Fatal("unchanged state produced another report", err)
		}
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.p.Apps(restored)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := apps.network.encode()
	y, _ := read.network.encode()
	if !bytes.Equal(x, y) {
		t.Fatal("shared scope changed at Snapshot boundary")
	}
	for _, mutate := range []func(*AppDNSOwner){func(r *AppDNSOwner) { r.Managed = nil }, func(r *AppDNSOwner) { r.Managed.Node = "other" }, func(r *AppDNSOwner) { r.Managed.Bridge.Key = "control/network-sources/bridge/other/services/node-a" }} {
		copy, err := decodeAppNetwork(x, f.p.Cluster)
		if err != nil {
			t.Fatal(err)
		}
		mutate(&copy.Groups[0].Owners[0])
		copy.Groups[0].Digest = appDNSDigest(copy.Groups[0].Owners)
		if _, err := copy.encode(); err == nil {
			t.Fatal("foreign owner metadata accepted despite recomputed digest")
		}
	}
}

func TestManagedDNSProjectionCoreRejectsSourceDigestAndOwnerScope(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	original := managedDNSCoreReport(t, f, f.node)
	for _, item := range []struct {
		name   string
		mutate func(*NetworkDNSProgress)
	}{
		{"source-revision", func(r *NetworkDNSProgress) { r.Source.Revision++ }},
		{"source-generation", func(r *NetworkDNSProgress) { r.Source.Generation++ }},
		{"digest", func(r *NetworkDNSProgress) { r.Digest[0] ^= 1 }},
		{"epoch", func(r *NetworkDNSProgress) { r.Epoch++ }},
		{"group-CAS", func(r *NetworkDNSProgress) { r.Expected++ }},
	} {
		t.Run(item.name, func(t *testing.T) {
			r := original
			item.mutate(&r)
			r.Signature = ed25519.Sign(f.node, NetworkDNSProgressBytes(r))
			cmd, err := r.Command()
			if err != nil {
				t.Fatal(err)
			}
			before := f.s.Object(AppsKey)
			next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
			if err != nil || result.Code == state.Applied || next.Object(AppsKey) != before {
				t.Fatal("stale/foreign projection changed state", result, err)
			}
		})
	}
	foreign := original
	foreign.Reporter = [32]byte(f.admin.Public().(ed25519.PublicKey))
	foreign.Signature = ed25519.Sign(f.admin, NetworkDNSProgressBytes(foreign))
	cmd, _ := foreign.Command()
	if f.p.AdmitModule(f.s, cmd) {
		t.Fatal("user/admin key became an installed DNS owner")
	}
}

func TestManagedDNSProjectionCorePolicyChangesKeepLifetimeAndLegacyBytes(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	apps, _ := f.p.Apps(f.s)
	_, rows, _ := apps.NetworkDNS(owner)
	original := rows[0]
	ref, _ := apps.network.Authority.ReferenceConsumer(original.Reference)
	definition.Policy.TTL = 45
	managedDNSChange(t, f, "dns-hot-policy", "configure-network-dns", original.Source.Revision, definition, state.Applied)
	if _, _, err := f.p.AppDNSMaterial(f.s, owner, "tenant", original.Config.ID); err == nil {
		t.Fatal("unprojected new source admitted as the old view")
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, _ = f.p.Apps(f.s)
	authority, rows, _ := apps.NetworkDNS(owner)
	updated := rows[0]
	current, _ := authority.ReferenceConsumer(updated.Reference)
	if updated.Reference != original.Reference || current.Lifetime != ref.Lifetime || current.Generation != ref.Generation || updated.Config.Serial != 2 || updated.Config.Source != 2 || updated.Config.TTL != 45 || updated.Source.Generation != original.Source.Generation || updated.Source.Revision <= original.Source.Revision {
		t.Fatal("hot policy replaced original lifetime or lost shared floor")
	}
	material, actual, err := f.p.AppDNSMaterial(f.s, owner, "tenant", updated.Config.ID)
	if err != nil || actual.Reference != updated.Reference || material.Bridge != updated.Managed.Bridge.Key || material.BridgeGeneration != updated.Managed.Bridge.Generation {
		t.Fatal("owner material not tied to original bridge", err)
	}
	permit, err := f.p.NativePermit(f.s, owner, NativeRequest{Source: updated.Source, DNS: updated.Config.ID})
	if err != nil || permit.Spec != AppDNSNativeDigest(updated) || permit.DNS != updated.Config.ID {
		t.Fatal("exact read-only current permission", err)
	}
	if _, err = f.p.NativePermit(f.s, owner, NativeRequest{Source: updated.Source}); err == nil {
		t.Fatal("ambiguous pool selector accepted")
	}
	// Explicitly model the old schema1 encoder shape, not a new signed source.
	cfg := updated.Config
	cfg.ID = dnsServiceID("tenant", "frozen", "services")
	cfg.Source, cfg.Serial = 1, 1
	projection, _ := f.p.ProjectResources(f.s)
	catalog, _ := f.p.Catalog(f.s)
	legacyAuthority, err := services.NewAuthority(f.p.Cluster, projection.Addresses)
	if err != nil {
		t.Fatal(err)
	}
	legacyAuthority, consumer, err := legacyAuthority.GrantDNSInstance(catalog, projection.Resources.Networks, "admin", 0, cfg)
	if err != nil {
		t.Fatal(err)
	}
	legacyOwner := AppDNSOwner{Source: deployment.ObjectRef{Key: deployment.ResourceKey("dns", "tenant", "frozen", "services/node-a"), Generation: 400, Revision: 400}, Config: cfg, Reference: consumer.ID}
	legacyGroup := appDNSGroup{Tenant: "tenant", App: "frozen", Network: "services", Source: 1, Serial: 1, Owners: []AppDNSOwner{legacyOwner}}
	legacyGroup.Digest = appDNSDigest(legacyGroup.Owners)
	legacy := appNetworkState{Revision: 1, Authority: legacyAuthority, Groups: []appDNSGroup{legacyGroup}}
	encoded, err := legacy.encode()
	if err != nil {
		t.Fatal("legacy shape", err)
	}
	if bytes.Contains(encoded, []byte(`"Managed"`)) {
		t.Fatal("optional scope changed old bytes")
	}
	decoded, err := decodeAppNetwork(encoded, f.p.Cluster)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.encode()
	if !bytes.Equal(encoded, again) {
		t.Fatal("old checkpoint rewritten")
	}
	var oldShape struct {
		Schema    uint8
		Cluster   [32]byte
		Revision  uint64
		Authority json.RawMessage
		Groups    []struct {
			Tenant, App, Network string
			Source               uint64
			Serial               uint32
			Digest               [32]byte
			Owners               []struct {
				Source    deployment.ObjectRef
				Config    services.DNSConfig
				Reference [32]byte
			}
		}
	}
	if json.Unmarshal(encoded, &oldShape) != nil {
		t.Fatal("old schema decoder")
	}
	oldBytes, _ := json.Marshal(oldShape)
	if !bytes.Equal(encoded, oldBytes) {
		t.Fatal("wire order/shape changed")
	}
	apps, _ = f.p.Apps(f.s)
	group, _, err := f.p.managedDNSProjection(f.s, projection, updated.Source.Key)
	if err != nil {
		t.Fatal(err)
	}
	group.Owners[0].Config.NegativeTTL++
	group.Digest = appDNSDigest(group.Owners)
	apps.network.Groups[0].Serial = ^uint32(0)
	if _, code := f.p.publishDNSGroup(f.s, catalog, projection, "admin", apps, group); code != state.ConditionFailed {
		t.Fatal("shared serial wrapped", code)
	}
}

func TestManagedDNSClosureCoreRequiresDisabledOriginalSignedFacts(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	apps, _ := f.p.Apps(f.s)
	authority, rows, _ := apps.NetworkDNS(owner)
	row := rows[0]
	consumer, _ := authority.ReferenceConsumer(row.Reference)
	// Injected native facts test only the real reducer's verification. A live
	// collector must inspect/Stop/Wait/TTL its original journal before signing.
	proof := services.ReferenceClose{Cluster: f.p.Cluster, Consumer: consumer.ID, Generation: consumer.Generation, Lifetime: consumer.Lifetime, Owner: owner, Boot: [32]byte{8}, At: 200, Native: "mock-stopped-dns-instance", Fenced: true, Settled: true, TTLExpired: true}
	proof.Signature = ed25519.Sign(f.node, services.ReferenceCloseBytes(proof))
	if _, err := f.p.ManagedDNSClosure(f.s, owner, proof, 200); err == nil {
		t.Fatal("an enabled server was closed by owner report")
	}
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "dns-close-policy", "configure-network-dns", row.Source.Revision, definition, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	for _, item := range []struct {
		name   string
		mutate func(*services.ReferenceClose)
	}{
		{"queries", func(p *services.ReferenceClose) { p.PendingQueries = 1 }},
		{"ttl", func(p *services.ReferenceClose) { p.TTLExpired = false }},
		{"generation", func(p *services.ReferenceClose) { p.Generation++ }},
		{"lifetime", func(p *services.ReferenceClose) { p.Lifetime.Token++ }},
		{"unsettled", func(p *services.ReferenceClose) { p.Settled = false }},
	} {
		t.Run(item.name, func(t *testing.T) {
			bad := proof
			item.mutate(&bad)
			bad.Signature = ed25519.Sign(f.node, services.ReferenceCloseBytes(bad))
			if _, err := f.p.ManagedDNSClosure(f.s, owner, bad, 200); err == nil {
				t.Fatal("incomplete/different original closure accepted")
			}
		})
	}
	request, err := f.p.ManagedDNSClosure(f.s, owner, proof, 200)
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = ed25519.Sign(f.node, NetworkDNSProgressBytes(request))
	command := applyDNSCoreReport(t, f, request, state.Applied)
	apps, _ = f.p.Apps(f.s)
	authority, rows, _ = apps.NetworkDNS(owner)
	closed, _ := authority.ReferenceConsumer(row.Reference)
	if closed.Closed == nil || closed.ID != consumer.ID || closed.Lifetime != consumer.Lifetime || rows[0].Config.Enabled {
		t.Fatal("not the original settled consumer")
	}
	before := f.s.Object(AppsKey)
	applyDNSCoreReport(t, f, request, state.Applied)
	if f.s.Object(AppsKey) != before {
		t.Fatal("original report replay changed state")
	}
	if _, err := f.p.ManagedDNSClosure(f.s, owner, proof, 201); err == nil {
		t.Fatal("already settled facts produced another root write")
	}
	result, found := f.s.LookupResult(command)
	if !found || result.Code != state.Applied {
		t.Fatal("original close receipt missing")
	}
}

func TestManagedDNSLifetimeCoreDisabledAndReenable(t *testing.T) {
	f, b, definition := managedDNSProjectionFixture(t)
	key := services.ManagedDNSKey(definition.Tenant, definition.Network)
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "never-published-disable", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	updates, err := f.p.ManagedDNSUpdates(f.s, owner)
	if err != nil || len(updates) != 0 {
		t.Fatal("initially disabled policy requested a native lifetime", err)
	}
	// A malicious owner cannot bypass the controller hint and grant one.
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	group, _, err := f.p.managedDNSProjection(f.s, projection, key)
	if err != nil {
		t.Fatal(err)
	}
	o := f.s.Object(key)
	report := NetworkDNSProgress{Schema: 1, Kind: "network-dns", Cluster: f.p.Cluster, Reporter: owner, Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}, Digest: group.Digest, Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(AppsKey).Revision}
	report.Signature = ed25519.Sign(f.node, NetworkDNSProgressBytes(report))
	applyDNSCoreReport(t, f, report, state.ConditionFailed)
	apps, _ := f.p.Apps(f.s)
	if apps.network != nil {
		t.Fatal("disabled policy allocated shared instance state")
	}
	definition.Policy.Enabled = true
	managedDNSChange(t, f, "first-enable", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, _ = f.p.Apps(f.s)
	first := apps.network.Groups[0]
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "retiring-disable", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	definition.Policy.Enabled = true
	managedDNSChange(t, f, "enable-before-disabled-publication", "configure-network-dns", f.s.Object(key).Revision, definition, state.ConditionFailed)
	definition.Policy.Enabled = false
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	for index, signer := range []ed25519.PrivateKey{f.node, b} {
		apps, _ = f.p.Apps(f.s)
		who := [32]byte(signer.Public().(ed25519.PublicKey))
		authority, rows, _ := apps.NetworkDNS(who)
		ref, _ := authority.ReferenceConsumer(rows[0].Reference)
		// Mock positive native facts; no sockets/TTL were observed here.
		proof := services.ReferenceClose{Cluster: f.p.Cluster, Consumer: ref.ID, Generation: ref.Generation, Lifetime: ref.Lifetime, Owner: who, Boot: [32]byte{8}, At: 200, Native: "mock-stopped-dns", Fenced: true, Settled: true, TTLExpired: true}
		proof.Signature = ed25519.Sign(signer, services.ReferenceCloseBytes(proof))
		report, err := f.p.ManagedDNSClosure(f.s, who, proof, 200)
		if err != nil {
			t.Fatal(err)
		}
		report.Signature = ed25519.Sign(signer, NetworkDNSProgressBytes(report))
		applyDNSCoreReport(t, f, report, state.Applied)
		if index == 0 {
			definition.Policy.Enabled = true
			managedDNSChange(t, f, "one-owner-still-live", "configure-network-dns", f.s.Object(key).Revision, definition, state.ConditionFailed)
			definition.Policy.Enabled = false
			definition.Policy.TTL++
			managedDNSChange(t, f, "disabled-input-replacement-while-live", "configure-network-dns", f.s.Object(key).Revision, definition, state.ConditionFailed)
			definition.Policy.TTL--
		}
	}
	definition.Policy.TTL++
	managedDNSChange(t, f, "disabled-update-after-closure", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	updates, err = f.p.ManagedDNSUpdates(f.s, owner)
	if err != nil || len(updates) != 0 {
		t.Fatal("closed disabled policy granted a replacement lifetime", err)
	}
	definition.Policy.Enabled = true
	managedDNSChange(t, f, "reenable-after-all-closed", "configure-network-dns", f.s.Object(key).Revision, definition, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, _ = f.p.Apps(f.s)
	next := apps.network.Groups[0]
	if next.Serial <= first.Serial || next.Source <= first.Source || len(next.Owners) != 2 {
		t.Fatal("reenable reset shared version floor")
	}
	for i, row := range next.Owners {
		old, _ := apps.network.Authority.ReferenceConsumer(first.Owners[i].Reference)
		current, _ := apps.network.Authority.ReferenceConsumer(row.Reference)
		if old.Closed == nil || current.Closed != nil || old.ID == current.ID || old.Lifetime == current.Lifetime || current.Generation <= old.Generation {
			t.Fatal("reenable reused the irreversibly closed lifetime")
		}
	}
}
