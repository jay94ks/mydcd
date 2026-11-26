// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload"
)

// These cases exercise the real deterministic module transaction, not native
// Docker/TUN readiness. They run with the other P0 boundaries at P0's end.
func TestP0ManagedNetworkTypedTransactionSourceScopeAndNativePermit(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageNetwork)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	for _, tenant := range []string{"", "tenant"} {
		f.apply("network-quota-"+tenant, "set-node-quota", 0, tenancy.NodeLimit{Tenant: tenant, Node: "node-a", Owner: owner, Capacity: workload.Resources{CPU: 8, Memory: 80}, Networks: 4, MaxConsumers: 4, PacketQueuePackets: 4, PacketQueueBytes: 8192}, state.Applied)
	}
	d := tenancy.TUNDefinition{Tenant: "tenant", Name: "services", Members: []tenancy.TUNNode{{Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.71.1.0/24"), Gateway: netip.MustParseAddr("10.71.1.1"), MTU: 1280}}, Addresses: []netip.Prefix{netip.MustParsePrefix("10.72.0.1/32")}}}}
	raw, _ := json.Marshal(d)
	op := UserOperation{Schema: 1, Session: f.session, At: 2, Epoch: f.s.ModuleEpoch(), RequestID: "named-network", RootRevision: f.s.Object(ResourcesKey).Revision, Change: Change{Schema: 1, Principal: "admin", Action: "create-tun-network", Expected: 0, Payload: raw}}
	op.Signature = ed25519.Sign(f.admin, OperationBytes(op))
	cmd, err := op.Command()
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.Reduce(f.s, cmd)
	if code != state.Applied {
		t.Fatal("typed reducer", code)
	}
	var sourceKey string
	var sourceKeys []string
	for key := range writes {
		if strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix) {
			sourceKeys = append(sourceKeys, key)
			if strings.HasPrefix(key, tenancy.ManagedNetworkSourcePrefix+"bridge/") {
				sourceKey = key
			}
		}
	}
	if sourceKey == "" || len(sourceKeys) != 2 || !f.p.AdmitAppPatch(f.s, cmd, sourceKeys) || f.p.AdmitAppPatch(f.s, cmd, []string{sourceKey}) || f.p.AdmitAppPatch(f.s, cmd, []string{VolumesKey}) || f.p.AdmitAppPatch(f.s, cmd, append(sourceKeys, VaultKey)) {
		t.Fatal("related namespace authority is not exact")
	}
	before := f.s
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("atomic native source transaction", result, err)
	}
	f.s = next
	projection, err := f.p.ProjectResources(next)
	if err != nil || !projection.Compatible || len(projection.ManagedSources) != 2 || len(projection.Goals) != 0 || len(projection.Resources.Networks.AllNetworks()) != 1 {
		t.Fatal("source became an app Goal or second reservation", err)
	}
	source := next.Object(sourceKey)
	if before.Object(sourceKey).Present || !source.Present || source.Generation != result.Index || source.Revision != result.Index {
		t.Fatal("source generation is not the actual committed ordinal")
	}
	request := NativeRequest{}
	request.Source.Key, request.Source.Generation, request.Source.Revision = sourceKey, source.Generation, source.Revision
	permit, err := f.p.NativePermit(next, owner, request)
	if err != nil || permit.Kind != "bridge" || permit.Source != request.Source || permit.MaxConsumers != 4 {
		t.Fatal("current exact owner native permit", err)
	}
	if projection.ManagedSources[sourceKey].Bridge == nil || permit.Consumers == nil || !permit.Consumers.Valid() || permit.Consumers.Scope.Tenant != "tenant" || permit.Consumers.Scope.Node != "node-a" || permit.Consumers.Scope.Owner != projection.ManagedSources[sourceKey].Bridge.Owner || permit.Consumers.NodeMaxConsumers != 4 || permit.Consumers.TenantMaxConsumers != 4 {
		t.Fatal("native permission omitted original scope/global/tenant budget", permit.Consumers)
	}
	managed := projection.ManagedSources[sourceKey]
	if managed.Network.GatewayMode != network.ManagedGatewayMode || managed.Bridge.GatewayMode != network.ManagedGatewayMode || managed.Bridge.Internal {
		t.Fatal("new managed network did not persist delegated firewall/native mode")
	}
	if _, err := f.p.NativePermit(next, [32]byte{99}, request); err == nil {
		t.Fatal("foreign owner permit")
	}
	stale := request
	stale.Source.Generation++
	if _, err := f.p.NativePermit(next, owner, stale); err == nil {
		t.Fatal("stale source permit")
	}
	checkpoint, err := state.Encode(next)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(checkpoint)
	if err != nil || restored.Object(sourceKey) != source {
		t.Fatal("snapshot changed source", err)
	}
	if _, err = f.p.ProjectResources(restored); err != nil {
		t.Fatal(err)
	}
	// Unrelated quota/root churn must not revise a borrowed source object.
	resources, _ := f.p.Resources(next)
	limit, _ := resources.Quotas.Limit("", "node-a")
	expected := limit.Revision
	limit.Revision = 0
	limit.MaxConsumers++
	f.apply("quota-update", "set-node-quota", expected, limit, state.Applied)
	if f.s.Object(sourceKey) != source {
		t.Fatal("unrelated checkpoint rewrote the native source")
	}
	// The typed patch hook does not weaken the FSM's native namespace ban.
	malicious := func(state.State, state.Command) (map[string][]byte, state.Code) {
		return map[string][]byte{ResourcesKey: writes[ResourcesKey], "network/bridge/tenant/foreign/node-a": []byte("foreign")}, state.Applied
	}
	bad, rejected, err := state.ApplyTransactional(before, before.Index()+1, cmd, nil, malicious, f.p.AdmitModule, nil, f.p.AdmitAppPatch)
	if err != nil || rejected.Code != state.Invalid || bad.Object(sourceKey).Present || bad.Object("network/bridge/tenant/foreign/node-a").Present {
		t.Fatal("native namespace/partial patch escaped", rejected, err)
	}
}

func TestP0ManagedNetworkInputIsTypedResourcesChange(t *testing.T) {
	raw := `Tenant: tenant
Name: services
Members:
  - Node: node-a
    Pools:
      - ID: pool
        Prefix: 10.71.1.0/24
        Gateway: 10.71.1.1
        MTU: 1280
    Addresses: [10.72.0.1/32]
`
	change, err := InputChange(changeInput("create-tun-network", 0, yamlPayload(t, raw)), "admin")
	if err != nil || CommandKey(change.Action) != ResourcesKey {
		t.Fatal("typed logical network input", err)
	}
	if _, err := InputChange(changeInput("create-tun-network", 0, yamlPayload(t, strings.Replace(raw, "Name: services", "Name: services\nUnknown: ignored", 1))), "admin"); err == nil {
		t.Fatal("unknown field accepted")
	}
}
