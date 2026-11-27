// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/userauth"
)

func TestRQ13RealIngressOperationsCLIAndOriginalRecovery(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppIngressOperations, true, false, true)
}

// Reuses the existing private Engine/managed app/CLI/rollback and same-DB
// recovery. This hook neither deploys an extra proxy nor constructs observations.
func prepareIngressOperationsNative(t *testing.T, ctx context.Context, r *Runtime, root string, user userauth.Client, peer sfcp.Peer, session access.Session, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), wait func(string, func() bool)) func(*Runtime) {
	t.Helper()
	cli := &fixedAppNativeFixture{home: filepath.Join(root, "cli-home"), profile: filepath.Join(root, "cli.yaml"), binary: os.Getenv("SFC_TEST_CLI")}
	call := func(want int, args ...string) map[string]json.RawMessage { return cli.cli(t, ctx, want, args...) }
	write := func(name string, payload any) string {
		t.Helper()
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(root, name+".json")
		if err = os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return file
	}
	q := control.IngressQuery{Tenant: "tenant", App: "app", Node: "node-a"}
	var original control.IngressMapping
	wait("original ingress owner before RQ13 actions", func() bool {
		page, e := user.Ingresses(ctx, peer, session, q)
		if e != nil || len(page.Mappings) != 1 || !page.Mappings[0].Ready {
			return false
		}
		original = page.Mappings[0]
		return original.Runtime != nil && len(original.Spec.Routes) > 0
	})
	taskKey := deployment.ResourceKey("task", "tenant", "app", "web")
	native, err := r.workload.Status(ctx, taskKey)
	if err != nil || !native.Ready {
		t.Fatal("original app container", err)
	}
	source, sourceID, known := r.ingress.NativeSource(original.Key, original.Generation)
	if !known {
		t.Fatal("original ingress native source missing")
	}
	unchanged := func() {
		t.Helper()
		current, e := r.workload.Status(ctx, taskKey)
		same, id, ok := r.ingress.NativeSource(original.Key, original.Generation)
		if e != nil || current.NativeID != native.NativeID || !current.Ready || !ok || id != sourceID || ingress.ManagedNativeID(original.Key, original.Generation, same) != ingress.ManagedNativeID(original.Key, original.Generation, source) || read().State.Object(original.Key).Generation != original.Generation {
			t.Fatal("ingress management recreated container/native source", e)
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.5:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	endpoint := netip.MustParseAddrPort(address)
	gateway := ingress.Gateway{Enabled: true, Addresses: []netip.Addr{endpoint.Addr()}, Ports: []uint16{endpoint.Port()}, Listeners: []ingress.Listener{{ID: "rq13-external", Address: address}}}
	gatewayFile := write("rq13-gateways", control.NodeGatewaysChange{Node: "node-a", External: &gateway})
	call(0, "ingress", "set-gateways", gatewayFile, "--cluster-scope", "--expected-revision", "0", "--request-id", "rq13-gateways")
	gatewayPage := func() control.IngressPage {
		page, e := user.Ingresses(ctx, peer, session, control.IngressQuery{Node: "node-a", Part: "gateways"})
		if e != nil {
			t.Fatal(e)
		}
		return page
	}
	wait("cluster gateway desired revision actually applied", func() bool {
		page := gatewayPage()
		return len(page.NodeGateways) == 1 && page.NodeGateways[0].Source == "cluster" && page.NodeGateways[0].Revision == 1 && page.NodeGateways[0].AppliedRevision == 1 && page.NodeGateways[0].Error == ""
	})
	// The owner reads its own interfaces into the reply; the gateway's
	// address is among them.
	if local := gatewayPage().NodeGateways[0].LocalAddresses; !slices.ContainsFunc(local, func(a ingress.LocalAddress) bool {
		return a.Prefix.Addr() == endpoint.Addr() && a.Interface != "" && a.Scope != ""
	}) {
		t.Fatal("owner did not report its gateway address among its own addresses", endpoint, local)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		t.Fatal("configured gateway did not open actual listener", err)
	}
	_ = connection.Close()
	unchanged()
	call(3, "ingress", "set-gateways", gatewayFile, "--cluster-scope", "--expected-revision", "0", "--request-id", "rq13-stale-gateways")
	badGateway := gateway
	badGateway.Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.231")}
	badGateway.Listeners = []ingress.Listener{{ID: "rq13-external", Address: "192.0.2.231:443"}}
	badGateway.Ports = []uint16{443}
	call(1, "ingress", "set-gateways", write("rq13-unowned-gateway", control.NodeGatewaysChange{Node: "node-a", External: &badGateway}), "--cluster-scope", "--expected-revision", "1", "--request-id", "rq13-unowned-gateway")
	route := original.Spec.Routes[0].ID
	balance := control.IngressBalanceChange{Tenant: "tenant", App: "app", Route: route, Balance: ingress.Balance{Method: "hash", Key: "cookie:session"}}
	balanceFile := write("rq13-balance", balance)
	call(0, "ingress", "balance", balanceFile, "--tenant", "tenant", "--expected-revision", "0", "--request-id", "rq13-balance")
	mapping := func() control.IngressMapping {
		page, e := user.Ingresses(ctx, peer, session, q)
		if e != nil || len(page.Mappings) != 1 {
			t.Fatal("original ingress mapping unavailable", e)
		}
		return page.Mappings[0]
	}
	wait("effective route policy reaches original runtime", func() bool {
		row := mapping()
		book, e := p.IngressManagement(read().State)
		return e == nil && row.Runtime != nil && row.Runtime.ControlRevision == book.Revision && row.Spec.Routes[0].BalanceRevision == 1 && row.Spec.Routes[0].Balance != nil && row.Spec.Routes[0].Balance.Method == "hash"
	})
	call(3, "ingress", "balance", balanceFile, "--tenant", "tenant", "--expected-revision", "0", "--request-id", "rq13-stale-balance")
	invalidBalance := balance
	invalidBalance.Balance = ingress.Balance{Method: "invalid"}
	rejected := call(3, "ingress", "balance", write("rq13-invalid-balance", invalidBalance), "--tenant", "tenant", "--expected-revision", "1", "--request-id", "rq13-invalid-balance")
	var invalid state.Code
	if json.Unmarshal(rejected["Code"], &invalid) != nil || invalid != state.Invalid {
		t.Fatal("invalid balance lacked meaningful Invalid code")
	}
	drain := control.IngressDrainChange{Tenant: "tenant", App: "app", Node: "node-a"}
	drainFile := write("rq13-drain", drain)
	call(0, "ingress", "drain", drainFile, "--tenant", "tenant", "--expected-revision", "0", "--request-id", "rq13-drain")
	wait("original app mapping drains without container recreation", func() bool {
		row := mapping()
		return row.Draining && row.LastMapping && row.DrainDeadline == row.DrainStartedAt+30 && row.Runtime != nil && row.Runtime.Draining
	})
	unchanged()
	call(0, "ingress", "undrain", drainFile, "--tenant", "tenant", "--expected-revision", "1", "--request-id", "rq13-undrain")
	wait("original app mapping resumes without generation change", func() bool {
		row := mapping()
		return !row.Draining && row.Ready && row.Runtime != nil && !row.Runtime.Draining
	})
	unchanged()
	block := ingress.Block{ID: "rq13-block", Scope: "instance", Tenant: "tenant", App: "app", Node: "node-a", Key: original.Key, Response: "503"}
	call(0, "ingress", "block", write("rq13-block", block), "--tenant", "tenant", "--request-id", "rq13-block")
	call(0, "ingress", "unblock", block.ID, "--tenant", "tenant", "--expected-revision", "1", "--request-id", "rq13-unblock")
	var history control.IngressPage
	raw, _ := json.Marshal(call(0, "ingress", "history", "--tenant", "tenant", "--app", "app"))
	if json.Unmarshal(raw, &history) != nil || len(history.History) != 5 {
		t.Fatal("scope history omitted accepted balance/drain/block originals")
	}
	for _, row := range history.History {
		if row.Tenant != "tenant" || row.App != "app" || row.Action == "set-node-gateways" {
			t.Fatal("app history leaked system/foreign scope")
		}
	}
	// A real Read-only principal cannot operate the gateway or mutate a route.
	key, err := identity.Create(filepath.Join(root, "rq13-viewer"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key.Private)
	change("rq13-viewer-create", "put-user", 0, access.User{ID: "rq13-viewer", Username: "rq13-viewer", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: key.Public, Enabled: true}}})
	change("rq13-viewer-membership", "set-membership", 0, access.Membership{Tenant: "tenant", User: "rq13-viewer", Role: access.Viewer, Enabled: true})
	viewer, err := user.Login(ctx, peer, "rq13-viewer", key.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = user.Ingresses(ctx, peer, viewer, control.IngressQuery{Part: "gateways", Node: "node-a"}); err == nil {
		t.Fatal("viewer read system gateway configuration")
	}
	payload, _ := control.ChangeBytes("set-ingress-balance", viewer.User, 1, balance)
	var changeInput control.Change
	_ = json.Unmarshal(payload, &changeInput)
	denied, err := user.Prepare(ctx, peer, viewer, "rq13-viewer-denied", changeInput)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := user.Operation(ctx, peer, denied, false)
	if err == nil && (reply.Result == nil || reply.Result.Code != state.Forbidden) {
		t.Fatal("viewer changed route balance")
	}
	// Keep the original signed evidence and accepted ID for result-only replay.
	before := gatewayPage().NodeGateways[0]
	call(0, "ingress", "set-gateways", gatewayFile, "--cluster-scope", "--expected-revision", "0", "--request-id", "rq13-gateways")
	if after := gatewayPage().NodeGateways[0]; after.Revision != before.Revision || !reflect.DeepEqual(after.Configuration, before.Configuration) {
		t.Fatal("same gateway operation ID created a second revision")
	}
	return func(next *Runtime) {
		r = next
		wait("cluster gateway wins over initial file on daemon reopen", func() bool {
			page := gatewayPage()
			return len(page.NodeGateways) == 1 && page.NodeGateways[0].Revision == 1 && page.NodeGateways[0].AppliedRevision == 1
		})
		unchanged()
		disabled := ingress.Gateway{}
		call(0, "ingress", "set-gateways", write("rq13-disable-gateway", control.NodeGatewaysChange{Node: "node-a", External: &disabled}), "--cluster-scope", "--expected-revision", "1", "--request-id", "rq13-disable-gateway")
		wait("original gateway closes after explicit disable", func() bool {
			connection, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
			if e == nil {
				connection.Close()
			}
			return e != nil
		})
		t.Log(fmt.Sprintf("RQ13 original ingress %s retained generation %d across policy/drain/recovery", original.Key, original.Generation))
	}
}
