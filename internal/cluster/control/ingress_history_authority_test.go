// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/ingress"
)

// Original user signatures, reducers, checkpoints, session checks and public
// paging are real. Time and the fixture's installed node are modeled inputs;
// this test creates no HTTP/native effects or alternative history algorithm.
func ingressHistoryAuthorityFixture(t *testing.T) *nodeStorageFixture {
	t.Helper()
	f := newNodeStorageFixture(t)
	f.apply("admin", "create-tenant", 0, TenantID{ID: "other"}, state.Applied)
	f.apply("admin", "set-ingress-host-policy", 0, IngressHostPolicyChange{Tenant: "other", Policy: ingress.HostPolicy{LocalHosts: []string{"other.test"}}}, state.Applied)
	f.apply("admin", "ingress-block", 0, IngressBlockChange{Block: ingress.Block{ID: "global-node", Scope: "node", Node: "node-a", Response: "503"}}, state.Applied)
	for i := 0; i < 12; i++ {
		f.apply("admin", "ingress-block", 0, IngressBlockChange{Block: ingress.Block{ID: fmt.Sprintf("original-node-%d", i), Scope: "source", Tenant: "tenant", Node: "node-a", Source: "198.51.100.0/24", Response: "503"}}, state.Applied)
	}
	for i := 0; i < 11; i++ {
		f.apply("admin", "set-ingress-host-policy", uint64(i), IngressHostPolicyChange{Tenant: "tenant", Policy: ingress.HostPolicy{LocalHosts: []string{fmt.Sprintf("tenant-%d.test", i)}}}, state.Applied)
	}
	return f
}

func readIngressHistoryAuthorityPages(t *testing.T, f *nodeStorageFixture, session access.Session, q IngressQuery) []IngressHistoryView {
	t.Helper()
	var out []IngressHistoryView
	seen := map[string]bool{}
	for page := 0; page < 16; page++ {
		current, err := f.p.IngressPage(f.s, session, 2, q)
		if err != nil {
			t.Fatal("original public history page", err)
		}
		for _, row := range current.History {
			if seen[row.Request] {
				t.Fatal("history continuation duplicated an original operation", row.Request)
			}
			seen[row.Request] = true
			out = append(out, row)
		}
		if current.Next == "" {
			return out
		}
		if len(current.History) == 0 || current.Next == q.After {
			t.Fatal("history continuation did not advance")
		}
		q.After = current.Next
	}
	t.Fatal("bounded fixture history failed to terminate")
	return nil
}

func TestIngressHistoryFiltersCurrentNodeAuthorityAndKeepsOriginalRows(t *testing.T) {
	f := ingressHistoryAuthorityFixture(t)
	q := IngressQuery{Part: "history", Tenant: "tenant"}
	manager := f.sessions["manager"]
	before := readIngressHistoryAuthorityPages(t, f, manager, q)
	if len(before) != 23 {
		t.Fatal("fixture lacks both original node-specific and tenant-wide history", len(before))
	}
	book, err := f.p.IngressManagement(f.s)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := json.Marshal(book)
	catalog, err := f.p.Catalog(f.s)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := catalog.Tenant("tenant")
	f.apply("admin", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{}}, state.Applied)
	policy, err := f.p.Current(f.s)
	if err != nil {
		t.Fatal("current policy after node allocation revocation", err)
	}
	current, err := policy.Catalog(f.s)
	if err != nil {
		t.Fatal("current catalog after node allocation revocation", err)
	}
	broadRead := current.AuthorizeSession(manager, policy.Cluster, policy.Issuer(manager.Issuer), 2, "tenant", access.Read, "")
	nodeRead := current.AuthorizeSession(manager, policy.Cluster, policy.Issuer(manager.Issuer), 2, "tenant", access.Read, "node-a")
	if broadRead != nil || nodeRead == nil {
		t.Fatal("fixture did not revoke only node allocation while preserving broad tenant Read", "broad Read", broadRead, "node Read", nodeRead)
	}
	after := readIngressHistoryAuthorityPages(t, f, manager, q)
	var expected []IngressHistoryView
	for _, row := range before {
		if row.Node == "" {
			expected = append(expected, row)
		}
	}
	if len(expected) != 11 || !reflect.DeepEqual(after, expected) {
		t.Fatal("historical node rows escaped current node Read, or tenant-wide rows were lost", after)
	}
	for _, query := range []IngressQuery{{Part: "history"}, {Part: "history", Tenant: "other"}, {Part: "history", Tenant: "tenant", Node: "node-a"}} {
		if _, err := f.p.IngressPage(f.s, manager, 2, query); !errors.Is(err, access.ErrDenied) {
			t.Fatal("unallocated node/global/other-tenant history was readable", query, err)
		}
	}
	global := readIngressHistoryAuthorityPages(t, f, f.sessions["admin"], IngressQuery{Part: "history"})
	if len(global) != len(book.History) {
		t.Fatal("system administrator lost global original history", len(global), len(book.History))
	}
	unchanged, err := f.p.IngressManagement(f.s)
	raw, _ := json.Marshal(unchanged)
	if err != nil || !bytes.Equal(original, raw) {
		t.Fatal("current read authorization rewrote original rows/signatures", err)
	}
}

func TestIngressHistoryCursorBindsCurrentActorSessionCatalogAndScope(t *testing.T) {
	f := ingressHistoryAuthorityFixture(t)
	manager := f.sessions["manager"]
	q := IngressQuery{Part: "history", Tenant: "tenant"}
	original := readIngressHistoryAuthorityPages(t, f, manager, q)
	first, err := f.p.IngressPage(f.s, manager, 2, q)
	if err != nil || len(first.History) != 8 || first.Next == "" {
		t.Fatal("bounded original history page", err)
	}
	q.After = first.Next
	// A new ingress record changes the Raft index/book but not current read
	// authority. Its newer order must not invalidate or enter this continuation.
	f.apply("admin", "set-ingress-host-policy", 11, IngressHostPolicyChange{Tenant: "tenant", Policy: ingress.HostPolicy{LocalHosts: []string{"later.test"}}}, state.Applied)
	continued := append(append([]IngressHistoryView{}, first.History...), readIngressHistoryAuthorityPages(t, f, manager, q)...)
	if !reflect.DeepEqual(original, continued) {
		t.Fatal("same-authority continuation skipped/duplicated originals or included a newer row")
	}
	if _, err := f.p.IngressPage(f.s, f.sessions["admin"], 2, q); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("another current authorized actor reused the history cursor", err)
	}
	otherSession := manager
	otherSession.ID = "another-manager-session"
	otherSession.Signature = ed25519.Sign(f.node, access.SessionBytes(otherSession))
	if _, err := f.p.IngressPage(f.s, otherSession, 2, q); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("another authorized session reused the history cursor", err)
	}
	for _, query := range []IngressQuery{{Part: "history", Tenant: "tenant", App: "different", After: first.Next}, {Part: "history", Tenant: "tenant", Node: "node-a", After: first.Next}} {
		if _, err := f.p.IngressPage(f.s, manager, 2, query); !errors.Is(err, access.ErrInvalid) {
			t.Fatal("history cursor crossed an authorized query scope", query, err)
		}
	}
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant("tenant")
	f.apply("admin", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{}}, state.Applied)
	if _, err := f.p.IngressPage(f.s, manager, 2, q); !errors.Is(err, access.ErrInvalid) {
		t.Fatal("cursor survived a changed current catalog authority", err)
	}
}
