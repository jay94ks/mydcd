// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/jay94ks/seafield/internal/userauth"
)

const testNetwork = `version: 1
name: shop-net
members:
  node-a: {subnet: 10.240.10.0/24, dynamic: 10.240.10.0/25}
dns:
  zone: shop.sfc.test
  ttl: 30s
`

func TestParseNetworkFile(t *testing.T) {
	spec, err := parseNetworkFile([]byte(testNetwork))
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Members[0]
	if spec.Name != "shop-net" || m.Node != "node-a" || m.Pools[0].Gateway != netip.MustParseAddr("10.240.10.1") || m.Pools[0].MTU != defaultMTU ||
		m.Pools[0].IPAM.Dynamic != netip.MustParsePrefix("10.240.10.0/25") || len(m.Addresses) != 0 || spec.DNS.TTL != 30*time.Second {
		t.Fatalf("%+v", spec)
	}
	two := strings.Replace(testNetwork, "members:\n", "members:\n  node-b: {subnet: 10.240.20.0/24}\n", 1)
	tun, err := parseNetworkFile([]byte(two))
	if err != nil || tun.Members[0].Pools[0].MTU != defaultTUNMTU {
		t.Fatal("two servers did not get the TUN default MTU", err)
	}
	if w := mtuWarning(tun); w != "" {
		t.Fatal("the default TUN MTU does not fit a 1500 server network:", w)
	}
	if sfcp.TUNUnderlayMTU(defaultTUNMTU) > 1500 {
		t.Fatal("defaultTUNMTU too large", sfcp.TUNUnderlayMTU(defaultTUNMTU))
	}
	big, err := parseNetworkFile([]byte(strings.Replace(two, "members:\n", "mtu: 1500\nmembers:\n", 1)))
	if err != nil || !strings.Contains(mtuWarning(big), "at least 1625") {
		t.Fatal("mtu 1500 on two servers gave no warning", err, mtuWarning(big))
	}
	for _, bad := range []string{
		strings.Replace(testNetwork, "version: 1", "version: 2", 1),
		strings.Replace(testNetwork, "ttl: 30s", "ttl: 30s\n  unknown: 1", 1),
		strings.Replace(testNetwork, "dynamic:", "tunnel: 10.240.30.1, dynamic:", 1), // the tunnel address is sfcd's
		strings.Replace(testNetwork, "dynamic: 10.240.10.0/25", "dynamic: 10.9.0.0/25", 1),
		strings.Replace(testNetwork, "members:\n", "gateway: bridge\nmembers:\n", 1),
		"version: 1\nname: x\nmembers: {}\n",
	} {
		if _, err := parseNetworkFile([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

// nextNetworkStep walks plan -> drain -> fence -> commit for every member,
// and reconfigure when servers change.
func TestNextNetworkStep(t *testing.T) {
	spec, err := parseNetworkFile([]byte(strings.Replace(testNetwork, "10.240.10.0/25", "10.240.10.0/26", 1)))
	if err != nil {
		t.Fatal(err)
	}
	cur := tenancy.Network{Tenant: "shop", ID: "m1", Node: "node-a", Logical: "shop-net", Revision: 7, Generation: 3,
		Pools:           []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.240.10.0/24"), Gateway: netip.MustParseAddr("10.240.10.1"), MTU: defaultMTU}},
		TunnelAddresses: []netip.Prefix{netip.MustParsePrefix("10.240.30.1/32")}}
	v := &netState{Tenant: "shop", Name: "shop-net", Networks: 40, Members: []netMember{{Source: cur}}}
	step, err := nextNetworkStep(v, &spec)
	if err != nil || step.Action != "plan-network-change" || step.Expected != 7 {
		t.Fatal(step, err)
	}
	plan := step.Payload.(control.NetworkChangePlan)
	if plan.Target.Pools[0].ID != "pool" || plan.Target.Pools[0].IPAM.Dynamic != netip.MustParsePrefix("10.240.10.0/26") || plan.Change != step.Key {
		t.Fatalf("%+v", plan)
	}
	for _, c := range []struct {
		phase  tenancy.ChangePhase
		action string
	}{{tenancy.ChangeReserved, "drain-network"}, {tenancy.ChangeDraining, "fence-network-change"}, {tenancy.ChangeFenced, "commit-network-change"}} {
		v.Members[0].Change = &control.NetworkChangeStatus{ID: "x", Generation: 9, Revision: 11, Phase: c.phase}
		if step, err = nextNetworkStep(v, &spec); err != nil || step.Action != c.action {
			t.Fatal(c.phase, step, err)
		}
	}
	// A new server needs a reconfigure with the whole new member list.
	two, err := parseNetworkFile([]byte(strings.Replace(testNetwork, "members:\n", "members:\n  node-b: {subnet: 10.240.20.0/24}\n", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if step, err = nextNetworkStep(v, &two); err != nil || step.Action != "reconfigure-tun-network" {
		t.Fatal(step, err)
	}
	if r := step.Payload.(control.NetworkReconfigure); len(r.Target.Members) != 2 || r.Target.Members[0].Pools[0].ID != "pool" || r.Target.Members[1].Pools[0].ID != "main" {
		t.Fatalf("%+v", r)
	}
	// Delete: DNS goes off first.
	policy, _ := wantDNS(nil, &dnsFile{Zone: "shop.sfc.test"})
	v.DNS = &control.DNSPolicyView{Revision: 2, Policy: policy}
	if step, err = nextNetworkStep(v, nil); err != nil || step.Action != "configure-network-dns" || step.Expected != 2 {
		t.Fatal(step, err)
	}
	// Then each server drains and leaves; the last to leave removes the
	// network. A server mid-change finishes its change first.
	v.DNS = nil
	v.Members[0].Change = nil
	v.Members = append(v.Members, netMember{Source: tenancy.Network{Tenant: "shop", ID: "m2", Node: "node-b", Logical: "shop-net", Revision: 8}})
	if step, err = nextNetworkStep(v, nil); err != nil || step.Action != "drain-network" || step.Expected != 7 {
		t.Fatal(step, err)
	}
	v.Members[0].Source.Draining = true
	if step, err = nextNetworkStep(v, nil); err != nil || step.Action != "leave-tun-network" || step.Closure != &v.Members[0] {
		t.Fatal(step, err)
	}
	v.Members = v.Members[1:]
	if step, err = nextNetworkStep(v, nil); err != nil || step.Action != "drain-network" || step.Expected != 8 {
		t.Fatal(step, err)
	}
	if step, err = nextNetworkStep(&netState{Tenant: "shop", Name: "shop-net"}, nil); err != nil || !step.Done {
		t.Fatal(step, err)
	}
}

// Adding or removing servers, with the staying servers unchanged, goes one
// server at a time: join, or drain then leave. The others keep their device.
func TestNextNetworkStepAddsAndRemovesOneServerAtATime(t *testing.T) {
	spec := func(extra string) networkSpec {
		s, err := parseNetworkFile([]byte(strings.Replace(testNetwork, "members:\n", "members:\n"+extra, 1)))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	nodeB := "  node-b: {subnet: 10.240.20.0/24}\n"
	nodeC := "  node-c: {subnet: 10.240.40.0/24}\n"
	one, two := spec(""), spec(nodeB)
	source := func(w tenancy.TUNNode, rev uint64) netMember {
		return netMember{Source: tenancy.Network{Tenant: "shop", ID: "id-" + w.Node, Node: w.Node, Logical: "shop-net", Revision: rev, Generation: 3, Pools: slices.Clone(w.Pools), TunnelAddresses: slices.Clone(w.Addresses)}}
	}
	// A lone server at the one-server MTU must lower it to add a second:
	// that is an MTU change, so the fenced path.
	v := &netState{Tenant: "shop", Name: "shop-net", Networks: 40, Members: []netMember{source(one.Members[0], 7)}}
	if step, err := nextNetworkStep(v, &two); err != nil || step.Action != "plan-network-change" {
		t.Fatal(step, err)
	}
	// Two servers at the TUN MTU: adding node-c is one join.
	v.Members = []netMember{source(two.Members[0], 7), source(two.Members[1], 9)}
	step, err := nextNetworkStep(v, ptr(spec(nodeB+nodeC)))
	if err != nil || step.Action != "join-tun-network" || step.Expected != 40 {
		t.Fatal(step, err)
	}
	if j := step.Payload.(control.NetworkJoin); j.Tenant != "shop" || j.Name != "shop-net" || j.Member.Node != "node-c" || j.Member.Pools[0].MTU != defaultTUNMTU {
		t.Fatalf("%+v", j)
	}
	// Removing node-b keeps the current MTU: drain it, then leave on its
	// closure.
	if step, err = nextNetworkStep(v, &one); err != nil || step.Action != "drain-network" || step.Expected != 9 {
		t.Fatal(step, err)
	}
	v.Members[1].Source.Draining = true
	if step, err = nextNetworkStep(v, &one); err != nil || step.Action != "leave-tun-network" || step.Closure == nil || step.Closure.Source.Node != "node-b" {
		t.Fatal(step, err)
	}
	// While node-b drains, replacing it with node-c finishes node-b first.
	if step, err = nextNetworkStep(v, ptr(spec(nodeC))); err != nil || step.Action != "leave-tun-network" {
		t.Fatal(step, err)
	}
	// Otherwise the new server joins first.
	v.Members[1].Source.Draining = false
	if step, err = nextNetworkStep(v, ptr(spec(nodeC))); err != nil || step.Action != "join-tun-network" || step.Payload.(control.NetworkJoin).Member.Node != "node-c" {
		t.Fatal(step, err)
	}
}

func ptr[T any](v T) *T { return &v }

// cliFixture runs new-frame commands against one managed node.
type cliFixture struct {
	t    *testing.T
	m    *managedNode
	home string
}

func newCLIFixture(t *testing.T) *cliFixture {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	m := newManagedNode(t, ctx, root, "node-a", admin)
	m.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	f := &cliFixture{t: t, m: m, home: home}
	open := func(g *globals, c *cli.Context) (*session, error) { return managedSession(t, m, home), nil }
	oldOpen, oldOp := openSession, openOpSession
	openSession = open
	openOpSession = func(g *globals, c *cli.Context, op cli.Op) (*session, error) {
		h := *g
		if h.tenant == "" {
			h.tenant = op.Tenant
		}
		return open(&h, c)
	}
	t.Cleanup(func() { openSession, openOpSession = oldOpen, oldOp })
	return f
}

// run executes a command line and checks its exit code.
func (f *cliFixture) run(want int, args ...string) string {
	f.t.Helper()
	var out, diagnostic bytes.Buffer
	code := cli.Execute(newRoot(&globals{}), append([]string{"-y", "--timeout", "20s"}, args...), cli.Env{Context: f.m.ctx, In: strings.NewReader(""), Out: &out, Err: &diagnostic})
	if code != want {
		f.t.Fatalf("sfcli %v: exit %d (want %d)\n%s%s", args, code, want, out.String(), diagnostic.String())
	}
	return out.String()
}

func (f *cliFixture) json(v any, args ...string) {
	f.t.Helper()
	if err := json.Unmarshal([]byte(f.run(0, append(args, "-o", "json")...)), v); err != nil {
		f.t.Fatal(args, err)
	}
}

func TestTenantAndUserCommands(t *testing.T) {
	f := newCLIFixture(t)
	f.run(0, "tenant", "create", "shop", "--nodes", "node-a")
	tenant, ok := f.m.Catalog().Tenant("shop")
	if !ok || len(tenant.AllowedNodes) != 1 || tenant.AllowedNodes[0] != "node-a" {
		t.Fatalf("%+v", tenant)
	}
	f.run(1, "tenant", "create", "shop") // exists
	f.run(2, "tenant", "create", "Bad_Name")

	alice, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	f.run(0, "user", "create", "alice", "--public-key", alice.Actor())
	var shown access.PublicUser
	f.json(&shown, "user", "show", "alice")
	if shown.ID != "alice" || len(shown.Credentials) != 1 || !shown.Credentials[0].Enabled {
		t.Fatalf("%+v", shown)
	}
	second, _ := identity.Ephemeral()
	f.run(0, "user", "key", "add", "alice", "second", "--public-key", second.Actor())
	f.run(0, "user", "key", "disable", "alice", "key")
	u, _ := f.m.Catalog().User("alice")
	if len(u.Credentials) != 2 || u.Credentials[0].Enabled == u.Credentials[1].Enabled {
		t.Fatalf("%+v", u.Credentials)
	}
	var users []access.PublicUser
	f.json(&users, "user", "list")
	if len(users) != 2 {
		t.Fatal(users)
	}

	f.run(0, "tenant", "member", "set", "shop", "alice", "--role", "viewer")
	f.run(0, "tenant", "member", "set", "shop", "alice", "--role", "manager")
	if m, ok := f.m.Catalog().Membership("shop", "alice"); !ok || m.Role != access.Manager || !m.Enabled {
		t.Fatalf("%+v", m)
	}
	var members []access.TenantMember
	f.json(&members, "tenant", "members", "shop")
	found := false
	for _, m := range members {
		found = found || m.Username == "alice" && m.Role == access.Manager
	}
	if !found {
		t.Fatal(members)
	}
	f.run(0, "tenant", "member", "remove", "shop", "alice")
	if m, _ := f.m.Catalog().Membership("shop", "alice"); m.Enabled {
		t.Fatal("membership still enabled")
	}
	f.run(0, "tenant", "set", "shop", "--nodes", "")
	if tenant, _ = f.m.Catalog().Tenant("shop"); len(tenant.AllowedNodes) != 0 {
		t.Fatal(tenant.AllowedNodes)
	}
	f.run(0, "tenant", "set", "shop", "--nodes", "node-a")

	// Image sources the tenant trusts (a new tenant starts with docker.io/**).
	tenant, _ = f.m.Catalog().Tenant("shop")
	base := len(tenant.ImageSources)
	f.run(0, "tenant", "trust", "add", "shop", "registry.example:5000/smoke/web")
	f.run(0, "tenant", "trust", "add", "shop", "ghcr.io/**")
	if out := f.run(0, "tenant", "trust", "add", "shop", "ghcr.io/**"); !strings.Contains(out, "already trusts") {
		t.Fatal(out)
	}
	f.run(2, "tenant", "trust", "add", "shop", "no-repository")
	if tenant, _ = f.m.Catalog().Tenant("shop"); len(tenant.ImageSources) != base+2 {
		t.Fatal(tenant.ImageSources)
	}
	var rules []access.TrustRule
	f.json(&rules, "tenant", "trust", "list", "shop")
	if len(rules) != base+2 || !slices.Contains(rules, access.TrustRule{Registry: "ghcr.io", Repository: "**"}) {
		t.Fatal(rules)
	}
	f.run(0, "tenant", "trust", "remove", "shop", "ghcr.io/**")
	if tenant, _ = f.m.Catalog().Tenant("shop"); len(tenant.ImageSources) != base+1 || !slices.Contains(tenant.ImageSources, access.TrustRule{Registry: "registry.example:5000", Repository: "smoke/web"}) {
		t.Fatal(tenant.ImageSources)
	}

	// Limits stay within the node-wide limit.
	// Without an administrator limit the server's default one holds: all
	// its CPU and memory, the default packet queue (256).
	f.run(1, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1", "--memory", "1GiB", "--packet-queue", "100000", "--packet-queue-bytes", "64KiB")
	var def tenancy.NodeLimit
	f.json(&def, "node", "quota", "show", "node-a")
	if !def.Default || def.Revision != 0 || def.Capacity != tenancy.DefaultCapacity {
		t.Fatalf("default limit %+v", def)
	}
	f.run(2, "node", "quota", "set", "node-a", "--cpu", "4")
	f.run(0, "node", "quota", "set", "node-a", "--cpu", "4", "--memory", "8GiB", "--networks", "8", "--consumers", "16")
	f.run(0, "node", "quota", "set", "node-a", "--memory", "8GiB")
	var limit tenancy.NodeLimit
	f.json(&limit, "node", "quota", "show", "node-a")
	if limit.Capacity.CPU != 4*cpuUnit || limit.Capacity.Memory != 8<<30 || limit.Networks != 8 || limit.MaxConsumers != 16 || limit.PacketQueuePackets != tenancy.NewNodeLimit.PacketQueuePackets || limit.Revision == 0 {
		t.Fatalf("%+v", limit)
	}
	f.run(2, "node", "quota", "set", "node-a", "--packet-queue", "0")
	f.run(1, "tenant", "quota", "set", "shop", "node-a", "--cpu", "5", "--memory", "1GiB")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB")
	var res resourcesView
	f.json(&res, "tenant", "resources", "shop")
	rows := res.Items
	// the tenant's limit and the system range row
	if res.QuotaRevision == 0 || len(rows) != 2 || rows[1].System == nil || rows[0].Limit == nil || rows[0].Limit.Capacity.CPU != 1.5*cpuUnit || rows[0].Limit.Capacity.Memory != 2<<30 {
		t.Fatalf("%+v", rows)
	}
	// Connections: kept by default, set with --consumers up to the server's.
	f.run(1, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--consumers", "17")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--consumers", "3")
	f.json(&res, "tenant", "resources", "shop")
	if rows = res.Items; len(rows) != 2 || rows[0].Limit == nil || rows[0].Limit.MaxConsumers != 3 {
		t.Fatalf("%+v", rows)
	}
	// Packet queue: both flags together, within the server's own.
	f.run(2, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--packet-queue", "8")
	f.run(1, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--packet-queue", "100000", "--packet-queue-bytes", "64KiB")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--packet-queue", "0", "--packet-queue-bytes", "0")
	res = resourcesView{} // omitempty: a 0 field must not keep the old value
	f.json(&res, "tenant", "resources", "shop")
	if rows = res.Items; len(rows) != 2 || rows[0].Limit == nil || rows[0].Limit.PacketQueuePackets != 0 || rows[0].Limit.PacketQueueBytes != 0 {
		t.Fatalf("%+v", rows)
	}
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1.5", "--memory", "2GiB", "--packet-queue", "8", "--packet-queue-bytes", "64KiB")
	f.json(&res, "tenant", "resources", "shop")
	if rows = res.Items; len(rows) != 2 || rows[0].Limit == nil || rows[0].Limit.PacketQueuePackets != 8 || rows[0].Limit.PacketQueueBytes != 64<<10 || rows[0].Limit.MaxConsumers != 3 {
		t.Fatalf("%+v", rows)
	}

	var tenants []userauth.TenantView
	f.json(&tenants, "tenant", "list")
	var view tenantView
	f.json(&view, "tenant", "show", "shop")
	if view.Name != "shop" || len(view.Servers) != 1 {
		t.Fatalf("%+v", view)
	}

	// Deleting an empty tenant: begin, then finish once its servers report.
	f.run(0, "tenant", "create", "old")
	out := f.run(0, "tenant", "delete", "old", "--id", "del-old", "--no-wait")
	if !strings.Contains(out, "sfcli op resume del-old") {
		t.Fatal(out)
	}
	if tenant, _ := f.m.Catalog().Tenant("old"); tenant.Phase != access.TenantRetiring {
		t.Fatal(tenant.Phase)
	}
	var status control.TenantRetirementStatus
	f.json(&status, "tenant", "status", "old")
	if status.Tenant.ID != "old" || status.Tenant.Phase != access.TenantRetiring {
		t.Fatalf("%+v", status)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var op cli.Op
		f.json(&op, "op", "resume", "del-old")
		if op.State == cli.Done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deletion did not finish: %+v", op)
		}
		time.Sleep(500 * time.Millisecond)
	}
	if tenant, _ := f.m.Catalog().Tenant("old"); tenant.Phase != access.TenantDeleted {
		t.Fatal(tenant.Phase)
	}
}

func TestNetworkAndRouteCommands(t *testing.T) {
	f := newCLIFixture(t)
	f.run(0, "tenant", "create", "shop", "--nodes", "node-a")
	f.run(0, "tenant", "create", "db", "--nodes", "node-a")
	f.run(0, "node", "quota", "set", "node-a", "--cpu", "4", "--memory", "8GiB", "--networks", "8", "--consumers", "16")
	f.run(0, "tenant", "quota", "set", "shop", "node-a", "--cpu", "1", "--memory", "1GiB")
	f.run(0, "tenant", "quota", "set", "db", "node-a", "--cpu", "1", "--memory", "1GiB")
	file := filepath.Join(f.home, "network.yaml")
	if err := os.WriteFile(file, []byte(testNetwork), 0o600); err != nil {
		t.Fatal(err)
	}
	f.run(0, "--tenant", "shop", "network", "create", "-f", file)
	f.run(1, "--tenant", "shop", "network", "create", "-f", file) // exists
	var v networkView
	f.json(&v, "--tenant", "shop", "network", "show", "shop-net")
	if v.Kind != "tun" || len(v.Members) != 1 || v.Members[0].Subnet != "10.240.10.0/24" || v.Members[0].Dynamic != "10.240.10.0/25" || v.DNS == nil || v.DNS.Zone != "shop.sfc.test" || !v.DNS.Enabled {
		t.Fatalf("%+v %+v", v, v.DNS)
	}
	// The same file again changes nothing.
	if out := f.run(0, "--tenant", "shop", "network", "update", "-f", file); !strings.Contains(out, "up to date") {
		t.Fatal(out)
	}
	// A DNS-only change applies at once.
	if err := os.WriteFile(file, []byte(strings.Replace(testNetwork, "ttl: 30s", "ttl: 1m", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	f.run(0, "--tenant", "shop", "network", "update", "-f", file)
	f.json(&v, "--tenant", "shop", "network", "show", "shop-net")
	if v.DNS.TTL != "1m0s" {
		t.Fatal(v.DNS)
	}
	var list []networkView
	f.json(&list, "--tenant", "shop", "network", "list")
	if len(list) != 1 || list[0].Name != "shop-net" {
		t.Fatal(list)
	}
	var users []control.PublicResourceUser
	f.json(&users, "--tenant", "shop", "network", "users", "shop-net")

	// A route from shop to db, approved by both.
	dbNet := filepath.Join(f.home, "db.yaml")
	if err := os.WriteFile(dbNet, []byte("version: 1\nname: db-net\nmembers:\n  node-a: {subnet: 10.241.10.0/24}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.run(0, "--tenant", "db", "network", "create", "-f", dbNet)
	var endpoints []control.PublicRouteEndpoint
	f.json(&endpoints, "route", "endpoints", "db")
	if len(endpoints) != 1 || endpoints[0].Network != "db-net" {
		t.Fatal(endpoints)
	}
	f.run(0, "--tenant", "shop", "route", "propose", "to-db", "--from", "shop/shop-net@node-a", "--to", "db/db-net@node-a", "--tcp", "3306")
	f.run(0, "--tenant", "shop", "route", "approve", "to-db")
	f.run(0, "--tenant", "db", "route", "approve", "to-db")
	var routes []routeView
	f.json(&routes, "--tenant", "db", "route", "list")
	if len(routes) != 1 || routes[0].Ports != "3306" || len(routes[0].Approvals) != 2 {
		t.Fatalf("%+v", routes)
	}
	f.run(0, "--tenant", "db", "route", "withdraw", "to-db")

	// Changing addresses plans and drains every member, then waits for each
	// server to report that nothing uses it. This fixture has no native
	// network owner to sign that report, so the update stops there; the
	// fence and commit steps are covered by TestNextNetworkStep.
	if err := os.WriteFile(file, []byte(strings.Replace(testNetwork, "10.240.10.0/25", "10.240.10.0/26", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	out := f.run(0, "--tenant", "shop", "network", "update", "-f", file, "--id", "net-up", "--no-wait")
	if !strings.Contains(out, "sfcli op resume net-up") {
		t.Fatal(out)
	}
	f.json(&v, "--tenant", "shop", "network", "show", "shop-net")
	if v.Members[0].Change != string(tenancy.ChangeDraining) {
		t.Fatalf("%+v", v)
	}
	var op cli.Op
	f.json(&op, "op", "show", "net-up")
	if op.State != cli.Accepted || op.Kind != "network-update" {
		t.Fatalf("%+v", op)
	}
	// The file is kept for the resume.
	if path, err := specPath("net-up"); err != nil {
		t.Fatal(err)
	} else if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

// Toggles: a file that names one changes it with set-network-toggle, before
// the servers change when the new value allows the current servers, after
// them otherwise.
func TestNextNetworkStepSetsTogglesAroundServerChanges(t *testing.T) {
	spec := func(extra, toggles string) networkSpec {
		s, err := parseNetworkFile([]byte(strings.Replace(testNetwork, "members:\n", toggles+"mtu: 1280\nmembers:\n"+extra, 1)))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, bad := range []string{"toggles: {local: true}\nmembers:\n  node-b: {subnet: 10.240.20.0/24}\n", "toggles: {nope: true}\nmembers:\n"} {
		if _, err := parseNetworkFile([]byte(strings.Replace(testNetwork, "members:\n", bad, 1))); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	nodeB := "  node-b: {subnet: 10.240.20.0/24}\n"
	source := func(w tenancy.TUNNode, rev uint64, toggles ...tenancy.NetworkToggle) netMember {
		return netMember{Source: tenancy.Network{Tenant: "shop", ID: "id-" + w.Node, Node: w.Node, Logical: "shop-net", Revision: rev, Generation: 3, Pools: slices.Clone(w.Pools), TunnelAddresses: slices.Clone(w.Addresses), Toggles: toggles}}
	}
	one := spec("", "")
	v := &netState{Tenant: "shop", Name: "shop-net", Networks: 40, Members: []netMember{source(one.Members[0], 7, tenancy.ToggleLocal)}}
	// Adding a server to a local network without naming the toggle is an error.
	if _, err := nextNetworkStep(v, ptr(spec(nodeB, ""))); err == nil {
		t.Fatal("a server was added to a local network")
	}
	// local: false comes first, then the join.
	step, err := nextNetworkStep(v, ptr(spec(nodeB, "toggles: {local: false}\n")))
	if err != nil || step.Action != "set-network-toggle" || step.Expected != 40 || step.Payload.(control.NetworkToggleSet) != (control.NetworkToggleSet{Tenant: "shop", Name: "shop-net", Toggle: tenancy.ToggleLocal}) {
		t.Fatal(step, err)
	}
	v.Members[0].Source.Toggles = nil
	if step, err = nextNetworkStep(v, ptr(spec(nodeB, "toggles: {local: false}\n"))); err != nil || step.Action != "join-tun-network" {
		t.Fatal(step, err)
	}
	// local: true with two servers waits for the removal, then turns on.
	two := spec(nodeB, "")
	v.Members = []netMember{source(two.Members[0], 7), source(two.Members[1], 9)}
	local := ptr(spec("", "toggles: {local: true}\n"))
	if step, err = nextNetworkStep(v, local); err != nil || step.Action != "drain-network" {
		t.Fatal(step, err)
	}
	v.Members = v.Members[:1]
	if step, err = nextNetworkStep(v, local); err != nil || step.Action != "set-network-toggle" || !step.Payload.(control.NetworkToggleSet).On {
		t.Fatal(step, err)
	}
	v.Members[0].Source.Toggles = []tenancy.NetworkToggle{tenancy.ToggleLocal}
	if step, err = nextNetworkStep(v, local); err != nil || !step.Done && step.Action != "configure-network-dns" {
		t.Fatal(step, err)
	}
}
