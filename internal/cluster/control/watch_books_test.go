// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/ingress"
)

// The certificate book names each certificate and domain; a write moves the
// book's root revision, and the diff names only what changed.
func TestWatchRecordsCertificateBook(t *testing.T) {
	f := newNodeStorageFixture(t)
	read := func() (WatchRecords, uint64) {
		t.Helper()
		r, err := f.p.WatchRecords(f.s, CertificatesKey)
		if err != nil {
			t.Fatal(err)
		}
		return r, WatchBookRevision(f.s, CertificatesKey)
	}
	empty, rev0 := read()
	if len(empty) != 0 {
		t.Fatal("empty book has records", empty)
	}
	v := controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 0, CertificatePut{v}, state.Applied)
	one, rev1 := read()
	if rev1 == rev0 {
		t.Fatal("root revision did not move")
	}
	got := WatchDiff(empty, one)
	if len(got) != 1 || got[0].WatchKey != (WatchKey{Kind: "certificate", Tenant: "", Name: v.Metadata.ID.String()}) {
		t.Fatal("certificate refs", got)
	}
	c, _ := f.p.Certificates(f.s)
	f.apply("admin", "add-domain", c.Revision, DomainChange{Name: "shop.example"}, state.Applied)
	two, _ := read()
	got = WatchDiff(one, two)
	// The new domain links the certificate, so both change.
	names := map[WatchKey]bool{}
	for _, r := range got {
		names[r.WatchKey] = true
	}
	if !names[WatchKey{Kind: "domain", Tenant: "", Name: "shop.example"}] {
		t.Fatal("domain refs", got)
	}
}

// A prefix book's revision stays when none of its rows moves.
func TestWatchBookRevisionPrefix(t *testing.T) {
	f := newNodeStorageFixture(t)
	const prefix = "control/network-services/dns/"
	a := WatchBookRevision(f.s, prefix)
	if b := WatchBookRevision(f.s, prefix); a != b {
		t.Fatal("unchanged prefix moved")
	}
}

// Ingress records are named by their part and carry their tenant; a
// cluster part has none.
func TestIngressWatchRecordNames(t *testing.T) {
	b := IngressManagement{
		Blocks:              []IngressBlockRecord{{Block: ingress.Block{ID: "x", Tenant: "a"}, Revision: 1}},
		Balances:            []IngressBalanceRecord{{IngressBalanceChange: IngressBalanceChange{Tenant: "a", App: "web", Route: "r"}}},
		Drains:              []IngressDrainRecord{{IngressDrainChange: IngressDrainChange{Tenant: "a", App: "web", Node: "n1"}}},
		NodeGatewaysRecords: []NodeGatewaysRecord{{Node: "n1"}},
		ClusterAppRoutes:    []ClusterAppRouteRecord{{App: "sfc-web"}},
		History:             []IngressHistoryRecord{{Tenant: "a", Order: 1}, {Tenant: "a", Order: 2}},
	}
	out := WatchRecords{}
	if !b.watchRecords(out) {
		t.Fatal("watch records failed")
	}
	want := []WatchKey{
		{Kind: "ingress", Tenant: "a", Name: "block/x"}, {Kind: "ingress", Tenant: "a", Name: "balance/web/r"},
		{Kind: "ingress", Tenant: "a", Name: "drain/web/n1"}, {Kind: "ingress", Tenant: "", Name: "gateway/n1"}, {Kind: "ingress", Tenant: "", Name: "cluster-app-route/sfc-web"}, {Kind: "ingress", Tenant: "a", Name: "history"},
	}
	if len(out) != len(want) {
		t.Fatal("records", out)
	}
	for _, k := range want {
		if _, ok := out[k]; !ok {
			t.Fatal("missing", k, out)
		}
	}
	before := out[WatchKey{Kind: "ingress", Tenant: "a", Name: "history"}]
	b.History = append(b.History, IngressHistoryRecord{Tenant: "a", Order: 3})
	again := WatchRecords{}
	b.watchRecords(again)
	if again[WatchKey{Kind: "ingress", Tenant: "a", Name: "history"}] == before {
		t.Fatal("a new history row did not change the history record")
	}
}

// The node shell book always names its policy; an empty VPS book names
// nothing.
func TestWatchRecordsNodeShellAndVPS(t *testing.T) {
	f := newNodeStorageFixture(t)
	shell, err := f.p.WatchRecords(f.s, NodeShellKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := shell[WatchKey{Kind: "node-shell", Name: "policy"}]; !ok || len(shell) != 1 {
		t.Fatal("node shell records", shell)
	}
	v, err := f.p.WatchRecords(f.s, VPSKey)
	if err != nil || len(v) != 0 {
		t.Fatal("vps records", v, err)
	}
}

// Node shell refs follow the read gate: managers hear of everything, a
// shell-scoped session of the policy and its own sessions, others nothing.
func TestNodeShellWatchGate(t *testing.T) {
	f := newNodeStorageFixture(t)
	p, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	shell := f.sessions["manager"]
	shell.ID = "session-shell"
	shell.Scopes = []access.Scope{{Tenant: "*", Actions: []access.Action{access.NodeShell}}}
	shell.Signature = ed25519.Sign(f.node, access.SessionBytes(shell))
	policy := WatchRef{WatchKey: WatchKey{Kind: "node-shell", Name: "policy"}}
	node := WatchRef{WatchKey: WatchKey{Kind: "node-shell", Name: "node/node-a"}}
	mine := WatchRef{WatchKey: WatchKey{Kind: "node-shell-session", Name: "s1", User: "manager"}}
	other := WatchRef{WatchKey: WatchKey{Kind: "node-shell-session", Name: "s2", User: "admin"}}
	allowed := func(s access.Session, r WatchRef) bool {
		return NodeShellWatchAllowed(c, s, p.Cluster, p.Issuer(s.Issuer), 2, r)
	}
	for _, r := range []WatchRef{policy, node, mine, other} {
		if !allowed(f.sessions["admin"], r) {
			t.Fatal("admin denied", r)
		}
		if allowed(f.sessions["manager"], r) {
			t.Fatal("unscoped manager allowed", r)
		}
	}
	if !allowed(shell, policy) || allowed(shell, node) || !allowed(shell, mine) || allowed(shell, other) {
		t.Fatal("shell-scoped session gate")
	}
}
