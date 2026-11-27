// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/observability"
)

func TestRegistryPullProjectionFiltersBeforePagingAndRetainsActualCompletion(t *testing.T) {
	f := newBackupCore(t)
	sign := func(tenant, code string, at, sequence uint64) observability.Report {
		r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: [32]byte(f.node.Public().(ed25519.PublicKey)), Index: f.s.Index(), At: at, RegistryPull: &observability.RegistryPull{Tenant: tenant, Authority: "registry.example", Source: "private", Stage: "load", Code: code, CompletedAt: 9000, Sequence: sequence}}
		r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
		if !r.Valid() {
			t.Fatal("pull fixture")
		}
		return r
	}
	own := sign("tenant", "OK", 10000, 2)
	old := sign("tenant", "UNAUTHORIZED", 10500, 1) // late replication cannot replace seq 2
	foreign := sign("other", "IMAGE_LOAD_FAILED", 10000, 1)
	tampered := own
	tampered.RegistryPull = &observability.RegistryPull{Tenant: "tenant", Authority: "hidden.example", Source: "private", Stage: "load", Code: "OK", CompletedAt: 9000, Sequence: 1}
	page, err := f.p.RegistryPulls(f.s, f.session, 11, "tenant", "", []observability.Report{own, old, foreign, tampered})
	if err != nil || len(page.Rows) != 1 || page.Rows[0].Code != "OK" || page.Rows[0].CompletedAt != 9000 {
		t.Fatal(page, err)
	}
	same, err := f.p.RegistryPulls(f.s, f.session, 12, "tenant", "", []observability.Report{own})
	if err != nil || same.Root != page.Root {
		t.Fatal("hidden rows changed public root", same, err)
	}
	raw, _ := json.Marshal(page)
	if bytes.Contains(raw, []byte("other")) || bytes.Contains(raw, []byte("Signature")) || bytes.Contains(raw, []byte("hidden.example")) {
		t.Fatal("foreign/private observation leak", string(raw))
	}
	if _, err = f.p.RegistryPulls(f.s, f.session, 11, "missing", "", []observability.Report{own}); err == nil {
		t.Fatal("unknown tenant authorized")
	}
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageMembers)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("pull-reader", "put-user", 0, access.User{ID: "pullreader", Username: "pullreader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(f.admin.Public().(ed25519.PublicKey)), Enabled: true}}}, state.Applied)
	f.apply("pull-member", "set-membership", 0, access.Membership{Tenant: "tenant", User: "pullreader", Role: access.Viewer, Enabled: true}, state.Applied)
	catalog, _ := f.p.Catalog(f.s)
	user, _ := catalog.User("pullreader")
	reader := f.session
	reader.User = "pullreader"
	reader.AccountRevision = user.Revision
	reader.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	reader.Signature = ed25519.Sign(f.node, access.SessionBytes(reader))
	if _, err = f.p.RegistryPulls(f.s, reader, 11, "tenant", "", []observability.Report{own}); err != nil {
		t.Fatal("read-only public observations denied", err)
	}
	if _, err = f.p.RegistryPulls(f.s, reader, 11, "other", "", []observability.Report{foreign}); err == nil {
		t.Fatal("cross tenant observations authorized")
	}
}

func TestRegistryPullPagePinsVisibleResultAndCursor(t *testing.T) {
	f := newBackupCore(t)
	reports := make([]observability.Report, 9)
	for i := range reports {
		reports[i] = observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: [32]byte(f.node.Public().(ed25519.PublicKey)), Index: f.s.Index(), At: 10000, RegistryPull: &observability.RegistryPull{Tenant: "tenant", Authority: fmt.Sprintf("registry%d.example", i), Source: "private", Stage: "load", Code: "OK", CompletedAt: 9000, Sequence: 1}}
		reports[i].Signature = ed25519.Sign(f.node, observability.SigningBytes(reports[i]))
	}
	first, err := f.p.RegistryPulls(f.s, f.session, 11, "tenant", "", reports)
	if err != nil || len(first.Rows) != 8 || !first.Valid("tenant", "") || first.Next == "" {
		t.Fatal(first, err)
	}
	next, err := f.p.RegistryPulls(f.s, f.session, 11, "tenant", first.Next, reports)
	if err != nil || len(next.Rows) != 1 || next.Next != "" || !next.Valid("tenant", first.Next) || next.Root != first.Root {
		t.Fatal(next, err)
	}
	reports[8].RegistryPull.Code = "IMAGE_LOAD_FAILED"
	reports[8].RegistryPull.Sequence++
	reports[8].Signature = ed25519.Sign(f.node, observability.SigningBytes(reports[8]))
	if _, err = f.p.RegistryPulls(f.s, f.session, 11, "tenant", first.Next, reports); err == nil {
		t.Fatal("changed result used old page")
	}
	first.Next = "forged"
	if first.Valid("tenant", "") {
		t.Fatal("foreign cursor accepted")
	}
}
