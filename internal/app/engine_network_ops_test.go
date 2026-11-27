// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/tenancy"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/engineops"
	"github.com/jay94ks/seafield/internal/network"
)

// The purpose 36 structs decode the engine's canonical JSON (maps {},
// slices [], no tags) and the answers carry the hook's result.
func TestEngineNetworkOpsAnswerThroughTheTable(t *testing.T) {
	owner := strings.Repeat("01", 32) + "/" + strings.Repeat("02", 32)
	r := &Runtime{engineNetwork: &network.EngineHooks{Owner: owner}}
	table, err := r.newEngineOps()
	if err != nil {
		t.Fatal(err)
	}
	call := func(q any) map[string]any {
		raw, _ := json.Marshal(q)
		a := table.Serve(context.Background(), engineops.Network, raw)
		out := a.Body
		if len(a.Files) != 0 || a.Stream != nil {
			t.Fatal("network op sent descriptors")
		}
		var answer map[string]any
		if err := json.Unmarshal(out, &answer); err != nil {
			t.Fatal(string(out), err)
		}
		return answer
	}
	create := engineNetworkCreate{Request: engineops.Request{Schema: 1, Op: "create", OpID: "op1", BootID: "boot9"}, NetworkID: "n1", Name: "sfc-bridge-x",
		Labels: map[string]string{"org.sfc.owner": owner}, Options: map[string]string{}, IPAM: []engineNetworkIPAM{{Subnet: "10.254.2.0/24", Gateway: "10.254.2.1/24"}}}
	if a := call(create); a["Result"] != engineops.NotApplied || a["Reason"] != engineops.NotOwner {
		t.Fatal("create without a dispatch:", a)
	}
	join := engineNetworkJoin{Request: engineops.Request{Schema: 1, Op: "join", OpID: "op2", BootID: "boot9"}, NetworkID: "n1", Endpoint: "e1", ContainerID: "c", ContainerName: "c",
		ContainerLabels: map[string]string{"org.sfc.owner": owner}, Addresses: []string{"10.254.2.130/24"}}
	if a := call(join); a["Result"] != engineops.NotApplied || a["Reason"] != engineops.NotReady || a["Allow"] != false {
		t.Fatal("join on an unknown network:", a)
	}
	bad := create
	bad.OpID, bad.IPAM = "op3", []engineNetworkIPAM{{Subnet: "nonsense", Gateway: "10.254.2.1"}}
	if a := call(bad); a["Reason"] != engineops.Invalid {
		t.Fatal("bad IPAM:", a)
	}
	leave := engineNetworkLeave{Request: engineops.Request{Schema: 1, Op: "leave", OpID: "op4", BootID: "boot9"}, NetworkID: "n1", Endpoint: "e1", ContainerID: "c", Addresses: []string{}}
	if a := call(leave); a["Result"] != engineops.Applied {
		t.Fatal("leave:", a)
	}
	off := &Runtime{}
	table, _ = off.newEngineOps()
	raw, _ := json.Marshal(leave)
	out := table.Serve(context.Background(), engineops.Network, raw).Body
	if !strings.Contains(string(out), `"not-ready"`) {
		t.Fatal("network module off:", string(out))
	}
}

// The system bridge admits only what clusterAppJoin allows: with no
// cluster-app owner, nothing joins it, not even a container holding a
// workload lease name.
func TestEngineNetworkAdmitAsksClusterAppsOnTheSystemBridge(t *testing.T) {
	r := &Runtime{network: &network.Manager{}, installation: &managedInstallation{}}
	r.installation.record.Root.Self.ID = "n1"
	key := (tenancy.SourceIdentity{Kind: "bridge", Network: tenancy.SystemNetwork, Node: "n1"}).Key()
	for _, labels := range []map[string]string{{"org.sfc.cluster-app": "web"}, {}} {
		if err := r.engineNetworkAdmit(network.EngineAdmit{Key: key, Generation: 1, NetworkID: "n", ContainerName: "sfc-cluster-app-web", Labels: labels, Addresses: []netip.Prefix{netip.MustParsePrefix("10.254.0.9/16")}}); err == nil {
			t.Fatal("joined the system bridge without a cluster-app owner", labels)
		}
	}
}

// libnetwork prints IPAM and readback gateways with the pool mask.
func TestEngineGatewayTakesTheMaskedForm(t *testing.T) {
	for _, s := range []string{"10.254.2.1/24", "10.254.2.1"} {
		if a, err := engineGateway(s); err != nil || a != netip.MustParseAddr("10.254.2.1") {
			t.Fatal(s, a, err)
		}
	}
	if _, err := engineGateway("nonsense"); err == nil {
		t.Fatal("nonsense gateway parsed")
	}
}
