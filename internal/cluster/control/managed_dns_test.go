// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/workload"
)

// These adapter/transaction tests belong to the E4 final verification bundle.
// The new reusable services core has its own early algorithm counterexamples.
func managedDNSChange(t *testing.T, f *backupCoreFixture, id, action string, expected uint64, payload any, want state.Code) (state.Command, state.Result) {
	t.Helper()
	raw, _ := json.Marshal(payload)
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: id, RootRevision: f.s.Object(CommandKey(action)).Revision, Change: Change{Schema: 1, Principal: "admin", Action: action, Expected: expected, Payload: raw}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	command, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != want {
		t.Fatal(id, result, want, err)
	}
	f.s = next
	return command, result
}

func TestIsolatedDNSOwnerRejectsNewPolicyAndRetainsDisableIdentity(t *testing.T) {
	f, _, definition := managedDNSProjectionFixture(t)
	key := services.ManagedDNSKey(definition.Tenant, definition.Network)
	original := f.s.Object(key)
	isolateVolumeCore(t, f)
	replacement := definition
	replacement.Policy.TTL++
	managedDNSChange(t, f, "deny-isolated-dns-replacement", "configure-network-dns", original.Revision, replacement, state.Forbidden)
	if f.s.Object(key) != original {
		t.Fatal("denied DNS change replaced original source")
	}
	definition.Policy.Enabled = false
	managedDNSChange(t, f, "disable-original-isolated-dns", "configure-network-dns", original.Revision, definition, state.Applied)
	closed := f.s.Object(key)
	if !closed.Present || closed.Generation != original.Generation || closed.Revision <= original.Revision {
		t.Fatal("disable changed the original DNS generation")
	}
}

func TestManagedDNSDisableRetainsReservedMembersDuringTenantRetirement(t *testing.T) {
	f, second, definition := managedDNSProjectionFixture(t)
	key := services.ManagedDNSKey(definition.Tenant, definition.Network)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	projection, err := f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range projection.Resources.Networks.AllNetworks() {
		if row.Tenant != definition.Tenant || row.Logical != definition.Network {
			continue
		}
		target := row
		target.Generation, target.Revision, target.PendingChange, target.Owner = 0, 0, 0, [32]byte{}
		managedDNSChange(t, f, "reserve-dns-retire-"+row.Node, "plan-network-change", row.Revision, NetworkChangePlan{Tenant: row.Tenant, ID: row.ID, Change: "retire-" + row.Node, Target: target}, state.Applied)
	}
	original := f.s.Object(key)
	// Enabled policy still cannot replace members with a reserved candidate.
	replacement := definition
	replacement.Policy.TTL++
	managedDNSChange(t, f, "reserved-enabled-denied", "configure-network-dns", original.Revision, replacement, state.ConditionFailed)
	c, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := c.Tenant(definition.Tenant)
	managedDNSChange(t, f, "begin-reserved-dns-tenant", "begin-tenant-retirement", tenant.Revision, TenantRetirementSelection{Tenant: tenant.ID, Operation: "retire-dns-tenant"}, state.Applied)
	definition.Policy.Enabled = false
	oldCommand, oldResult := managedDNSChange(t, f, "historical-reserved-disable", "configure-network-dns", original.Revision, definition, state.ConditionFailed)
	definition.RetainReserved = true
	managedDNSChange(t, f, "reserved-cleanup-disable", "configure-network-dns", original.Revision, definition, state.Applied)
	if receipt, found := f.s.LookupResult(oldCommand); !found || receipt != oldResult {
		t.Fatal("explicit new cleanup replaced the historical refusal")
	}
	closed := f.s.Object(key)
	if closed.Generation != original.Generation || closed.Revision <= original.Revision {
		t.Fatal("disable replaced original DNS lifetime")
	}
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	if err != nil || apps.network == nil || managedDNSGroupEnabled(apps.network.Groups[0]) {
		t.Fatal("disabled original owners were not projected", err)
	}
	projection, err = f.p.ProjectResources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range projection.Resources.Networks.AllNetworks() {
		if row.Tenant == definition.Tenant && row.Logical == definition.Network {
			managedDNSChange(t, f, "drain-original-dns-"+row.Node, "drain-network", row.Revision, NetworkSelection{Tenant: row.Tenant, ID: row.ID}, state.Applied)
		}
	}
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []ed25519.PrivateKey{f.node, second} {
		owner := [32]byte(signer.Public().(ed25519.PublicKey))
		_, rows, _ := apps.NetworkDNS(owner)
		if len(rows) != 1 {
			t.Fatal("original disabled owner lost")
		}
		material, _, err := f.p.AppDNSMaterial(f.s, owner, definition.Tenant, rows[0].Config.ID)
		if err != nil || material.Config.Enabled || material.BridgeGeneration != rows[0].Managed.Bridge.Generation {
			t.Fatal("parent drain blocked exact original DNS cleanup", err)
		}
		if _, err = f.p.NativePermit(f.s, owner, NativeRequest{Source: rows[0].Source, DNS: rows[0].Config.ID}); err == nil {
			t.Fatal("cleanup material granted fresh native use")
		}
	}
}

func TestManagedDNSConfigurationUsesExactTenantCASAndRelatedSource(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageNetwork, access.ManageServices)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	for _, scope := range []string{"", "tenant"} {
		f.apply("dns-quota-"+scope, "set-node-quota", 0, tenancy.NodeLimit{Tenant: scope, Node: "node-a", Capacity: workload.Resources{CPU: 8, Memory: 80}, Networks: 4, MaxConsumers: 4}, state.Applied)
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "services", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.75.1.0/24"), Gateway: netip.MustParseAddr("10.75.1.1"), MTU: 1280}}}}}
	managedDNSChange(t, f, "prepare-dns-network", "create-tun-network", 0, definition, state.Applied)
	dns := services.ManagedDNSDefinition{Schema: 1, Tenant: "tenant", Network: "services", Policy: services.ManagedDNSPolicy{Enabled: true, Zone: "apps.sfc.test.", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}, Upstreams: []netip.AddrPort{}, MaxQueries: 8, MaxCacheEntries: 8, MaxResponseBytes: 4096, MaxConnections: 4, RequestTimeoutMS: 1000}}
	before := f.s
	command, result := managedDNSChange(t, f, "configure-dns", "configure-network-dns", 0, dns, state.Applied)
	key := services.ManagedDNSKey(dns.Tenant, dns.Network)
	source := f.s.Object(key)
	if !source.Present || source.Generation != result.Index || source.Revision != result.Index || before.Object(key).Present {
		t.Fatal("source was not committed atomically")
	}
	rows, err := f.p.ManagedDNS(f.s)
	if err != nil || len(rows) != 1 || rows[key].Principal != "admin" || rows[key].Definition.Policy.Zone != dns.Policy.Zone {
		t.Fatal("not the original management policy", err)
	}
	if !f.p.AdmitAppPatch(before, command, []string{key}) || f.p.AdmitAppPatch(before, command, []string{key, VaultKey}) || f.p.AdmitAppPatch(before, command, []string{key + "/other"}) {
		t.Fatal("related namespace authority expanded")
	}
	projection, err := f.p.ProjectResources(f.s)
	// The lone member's Bridge and TUN; the DNS policy adds no native source.
	if err != nil || len(projection.Goals) != 0 || len(projection.ManagedSources) != 2 {
		t.Fatal("server policy became an app/native allocation", err)
	}
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(raw)
	if err != nil || restored.Object(key) != source {
		t.Fatal("snapshot changed source", err)
	}
	if _, err = f.p.ManagedDNS(restored); err != nil {
		t.Fatal(err)
	}
	managedDNSChange(t, f, "stale-dns", "configure-network-dns", 0, dns, state.ConditionFailed)
	if f.s.Object(key) != source {
		t.Fatal("stale CAS rewrote source")
	}
	resources, _ := f.p.Resources(f.s)
	limit, _ := resources.Quotas.Limit("", "node-a")
	expected := limit.Revision
	limit.Revision = 0
	limit.MaxConsumers++
	f.apply("unrelated-dns-quota", "set-node-quota", expected, limit, state.Applied)
	if f.s.Object(key) != source {
		t.Fatal("unrelated root churn rewrote server source")
	}
	dns.Policy.Enabled = false
	managedDNSChange(t, f, "disable-dns", "configure-network-dns", source.Revision, dns, state.Applied)
	updated := f.s.Object(key)
	if !updated.Present || updated.Generation != source.Generation || updated.Revision <= source.Revision {
		t.Fatal("disable deleted/replaced source identity")
	}
	rows, err = f.p.ManagedDNS(f.s)
	if err != nil || rows[key].Definition.Policy.Enabled {
		t.Fatal("disable not retained", err)
	}
}

func TestManagedDNSInputRequiresExplicitReplacement(t *testing.T) {
	raw := `Schema: 1
Tenant: tenant
Network: services
Policy:
  Enabled: true
  Zone: apps.sfc.test.
  TTL: 30
  NegativeTTL: 5
  Transports: [udp, tcp]
  Upstreams: []
  MaxQueries: 8
  MaxCacheEntries: 8
  MaxResponseBytes: 4096
  MaxConnections: 4
  RequestTimeoutMS: 1000
`
	if _, err := InputChange(changeInput("configure-network-dns", 0, yamlPayload(t, raw)), "admin"); err != nil {
		t.Fatal("typed management input", err)
	}
	for _, bad := range []string{
		strings.Replace(raw, "  Enabled: true\n", "", 1),
		strings.Replace(raw, "  Upstreams: []\n", "", 1),
		strings.Replace(raw, "  MaxCacheEntries: 8\n", "", 1),
		strings.Replace(raw, "Network: services", "Network: services\nPrincipal: another", 1),
	} {
		if _, err := InputChange(changeInput("configure-network-dns", 0, yamlPayload(t, bad)), "admin"); err == nil {
			t.Fatal("implicit reset/private authority accepted", bad)
		}
	}
}
