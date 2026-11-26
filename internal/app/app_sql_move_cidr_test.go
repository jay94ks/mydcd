// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/moby/moby/client"
)

func rejectSQLMoveOverlappingCIDR(t *testing.T, ctx context.Context, a *Runtime, user userauth.Client, peer mydcp.Peer, session access.Session, source *engine.Client, read func() cluster.View) {
	t.Helper()
	before := read()
	resources, err := a.controlPolicy.Resources(before.State)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := a.controlPolicy.Catalog(before.State)
	if err != nil {
		t.Fatal(err)
	}
	original, found := resources.Networks.NamedNetwork("tenant", "app-services", "node-a")
	if !found || len(original.Pools) != 1 {
		t.Fatal("original managed SQL CIDR required")
	}
	definition := tenancy.TUNDefinition{Tenant: "tenant", Name: "sql-overlap-rejected", Members: []tenancy.TUNNode{{Node: original.Node, Owner: original.Owner, Pools: append([]tenancy.Subnet(nil), original.Pools...), Addresses: []netip.Prefix{netip.MustParsePrefix("198.19.81.250/32")}}}}
	// Prove current placement, quota, syntax and CAS are sufficient with only
	// the conflicting subnet changed. This candidate performs no I/O/commit.
	valid := definition
	valid.Members = append([]tenancy.TUNNode(nil), definition.Members...)
	valid.Members[0].Pools = append([]tenancy.Subnet(nil), definition.Members[0].Pools...)
	valid.Members[0].Pools[0].Prefix = netip.MustParsePrefix("198.19.80.240/28")
	valid.Members[0].Pools[0].Gateway = netip.MustParseAddr("198.19.80.241")
	if _, err := resources.Networks.CreateTUN(catalog, resources.Quotas, "admin", resources.Networks.Revision(), valid); err != nil {
		t.Fatal("CIDR rejection premise: non-overlap candidate must otherwise be valid", err)
	}
	if _, err := resources.Networks.CreateTUN(catalog, resources.Quotas, "admin", resources.Networks.Revision(), definition); err == nil {
		t.Fatal("overlapping candidate accepted")
	}
	networks, err := resources.Networks.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := control.ChangeBytes("create-tun-network", "admin", resources.Networks.Revision(), definition)
	if err != nil {
		t.Fatal(err)
	}
	var change control.Change
	if err := json.Unmarshal(raw, &change); err != nil {
		t.Fatal(err)
	}
	op, err := user.Prepare(ctx, peer, session, "sql-overlap-rejected", change)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := user.Operation(ctx, peer, op, false)
	if err != nil || reply.Result == nil || reply.Result.Code != state.ConditionFailed {
		t.Fatal("authenticated current-CAS CIDR overlap rejection", err, reply.Result)
	}
	after, err := a.controlPolicy.Resources(read().State)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := after.Networks.Encode()
	if err != nil || !bytes.Equal(networks, encoded) {
		t.Fatal("rejected overlapping management CIDR changed original networks", err)
	}
	registry, err := a.controlPolicy.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	native, found := registry.Native("tenant", "app", "data")
	if !found || native.Owner.Node != "node-b" {
		t.Fatal("CIDR rejection changed original SQL owner")
	}
	containers, err := source.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", native.Owner.Native)})
	if err != nil || len(containers.Items) != 1 {
		t.Fatal("CIDR rejection lost original SQL source", err)
	}
	actual, err := source.API.ContainerInspect(ctx, containers.Items[0].ID, client.ContainerInspectOptions{})
	if err != nil || actual.Container.State == nil || !actual.Container.State.Running {
		t.Fatal("CIDR rejection stopped original SQL native", err)
	}
	t.Log("current placement/quota/CAS valid -> actual authenticated overlapping management CIDR rejected -> original managed network bytes and SQL native Running/owner retained; app still borrows the original named network")
}
