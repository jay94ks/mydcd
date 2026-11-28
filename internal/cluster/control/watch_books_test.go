// SPDX-License-Identifier: Apache-2.0

package control

import (
	"fmt"
	"testing"

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
	if len(got) != 1 || got[0].WatchKey != (WatchKey{"certificate", "", v.Metadata.ID.String()}) {
		t.Fatal("certificate refs", got)
	}
	c, _ := f.p.Certificates(f.s)
	f.apply("admin", "add-domain", c.Revision, DomainChange{"shop.example"}, state.Applied)
	two, _ := read()
	got = WatchDiff(one, two)
	// The new domain links the certificate, so both change.
	names := map[WatchKey]bool{}
	for _, r := range got {
		names[r.WatchKey] = true
	}
	if !names[WatchKey{"domain", "", "shop.example"}] {
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
		HostPolicies:        []IngressHostPolicyRecord{{Tenant: "a", Revision: 1}},
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
		{"ingress", "a", "block/x"}, {"ingress", "a", "host-policy"}, {"ingress", "a", "balance/web/r"},
		{"ingress", "a", "drain/web/n1"}, {"ingress", "", "gateway/n1"}, {"ingress", "", "cluster-app-route/sfc-web"}, {"ingress", "a", "history"},
	}
	if len(out) != len(want) {
		t.Fatal("records", out)
	}
	for _, k := range want {
		if _, ok := out[k]; !ok {
			t.Fatal("missing", k, out)
		}
	}
	before := out[WatchKey{"ingress", "a", "history"}]
	b.History = append(b.History, IngressHistoryRecord{Tenant: "a", Order: 3})
	again := WatchRecords{}
	b.watchRecords(again)
	if again[WatchKey{"ingress", "a", "history"}] == before {
		t.Fatal("a new history row did not change the history record")
	}
}
