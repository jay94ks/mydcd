// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/userauth"
)

// The store in mydcd's real shape: ID-keyed pages with links and states,
// protected input receipt, put / disable / delete with Expected 0.
func TestCertificatesReal(t *testing.T) {
	f, clk := newTestFake(t)
	f.SetIdleTimeout(0)
	admin := passwordLogin(t, f, "admin", "admin")
	alice := passwordLogin(t, f, "alice", "alice")

	list := func() control.CertificatePage {
		t.Helper()
		p, err := admin.QueryCertificates(ctx, control.CertificateQuery{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	byHost := func(p control.CertificatePage, host string) []certstore.PublicEntry {
		return certstore.LookupPublic(p.Certificates, host)
	}
	run := func(action string, payload any, id string) Result {
		t.Helper()
		ch := Change{Action: action, Payload: mustPayload(t, payload)}
		var op SignedOp
		var err error
		if id != "" {
			op, err = admin.PrepareRequest(ctx, id, ch, rootFor(t, admin, action))
		} else {
			op, err = admin.Prepare(ctx, ch, rootFor(t, admin, action))
		}
		if err != nil {
			t.Fatal(err)
		}
		res, err := admin.Submit(ctx, op)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	p := list()
	if len(p.Certificates) != 4 || p.Revision == 0 || p.Next != "" || len(p.Domains) != 2 {
		t.Fatalf("seed %+v", p)
	}
	states := map[string]int{}
	for _, e := range p.Certificates {
		states[e.State]++
	}
	if states[certstore.StateLinked] != 2 || states[certstore.StatePendingDestroy] != 1 || states[certstore.StateUnlinked] != 1 {
		t.Fatalf("seed states %v", states)
	}
	shop := byHost(p, "shop.example.com")
	if len(shop) != 1 {
		t.Fatal("shop.example.com link")
	}
	if _, err := alice.QueryCertificates(ctx, control.CertificateQuery{}); err == nil {
		t.Fatal("tenant user read the store")
	}
	one, err := admin.QueryCertificates(ctx, control.CertificateQuery{ID: shop[0].Metadata.ID.String()})
	if err != nil || len(one.Certificates) != 1 || len(one.Chain) == 0 {
		t.Fatalf("one %+v %v", one, err)
	}

	// Protected input → receipt → put-certificate signed with its Request.
	now := clk.now()
	chain, key, err := NewTestCertificate([]string{"shop.example.com"}, now.Add(-time.Hour), now.Add(90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	in := userauth.CertificateInput{Request: "cert-shop-1", Chain: chain, Key: key}
	receipt, err := admin.WriteCertificate(ctx, in)
	if err != nil || receipt.Request != "cert-shop-1" || receipt.Metadata.UploadedBy != "u-admin" {
		t.Fatalf("receipt %+v %v", receipt.Metadata, err)
	}
	if again, err := admin.WriteCertificate(ctx, userauth.CertificateInput{Request: "cert-shop-1", Recover: true}); err != nil || again.Digest() != receipt.Digest() {
		t.Fatalf("recover %v", err)
	}
	_, otherKey, _ := NewTestCertificate([]string{"shop.example.com"}, now.Add(-time.Hour), now.Add(time.Hour))
	in2 := in
	in2.Key = otherKey
	_, err = admin.WriteCertificate(ctx, in2)
	wantCode(t, err, CodeConflict)
	if _, err := alice.WriteCertificate(ctx, userauth.CertificateInput{Request: "r", Chain: chain, Key: key}); err == nil {
		t.Fatal("tenant user wrote a certificate")
	}
	if res := run(ActionPutCertificate, control.CertificatePut{Certificate: receipt}, "other-id"); res.Code != ResultInvalid {
		t.Fatalf("put with another request ID %v", res.Code)
	}
	if res := run(ActionPutCertificate, control.CertificatePut{Certificate: receipt}, receipt.Request); res.Code != ResultApplied {
		t.Fatalf("put %v", res.Code)
	}
	// A stored chain is refused at the input.
	_, err = admin.WriteCertificate(ctx, userauth.CertificateInput{Request: "cert-shop-2", Chain: chain, Key: key})
	wantCode(t, err, CodeConflict)
	if got := byHost(list(), "shop.example.com"); len(got) != 1 || got[0].Metadata.ID != receipt.Metadata.ID {
		t.Fatal("the later NotAfter did not take the link")
	}
	// Dynamic loading: the ingress observations follow the link.
	obs, err := alice.QueryIngresses(ctx, control.IngressQuery{Tenant: "shop", Node: "node-a"})
	if err != nil || len(obs.Mappings) != 1 || obs.Mappings[0].Runtime.Certificates[0].Fingerprint != receipt.Metadata.ID {
		t.Fatalf("ingress observation after put %+v %v", obs.Mappings, err)
	}

	// Delete is refused while linked; disable moves the link back.
	sel := control.CertificateSelection{ID: receipt.Metadata.ID}
	if res := run(ActionDeleteCertificate, sel, ""); res.Code != ResultConditionFailed {
		t.Fatalf("delete linked %v", res.Code)
	}
	if res := run(ActionDisableCertificate, sel, ""); res.Code != ResultApplied {
		t.Fatalf("disable %v", res.Code)
	}
	if got := byHost(list(), "shop.example.com"); len(got) != 1 || got[0].Metadata.ID != shop[0].Metadata.ID {
		t.Fatal("disabled link did not move back")
	}
	if res := run(ActionDeleteCertificate, sel, ""); res.Code != ResultApplied {
		t.Fatalf("delete disabled %v", res.Code)
	}

	// An incident's put: the receipt's Request plus reason metadata.
	spareChain, spareKey, _ := NewTestCertificate([]string{"spare.example.org"}, now.Add(-time.Hour), now.Add(time.Hour))
	spare, err := admin.WriteCertificate(ctx, userauth.CertificateInput{Request: "cert-spare", Chain: spareChain, Key: spareKey})
	if err != nil {
		t.Fatal(err)
	}
	op, err := admin.PrepareRequestReason(ctx, spare.Request, Change{Action: ActionPutCertificate, Payload: mustPayload(t, control.CertificatePut{Certificate: spare})},
		rootFor(t, admin, ActionPutCertificate), OperationReason{Reason: "renew", Incident: "inc-9"})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := admin.Submit(ctx, op); err != nil || res.Code != ResultApplied {
		t.Fatalf("put spare %+v %v", res, err)
	}
	if r, ok, err := SignedReason(op); err != nil || !ok || r.Incident != "inc-9" {
		t.Fatalf("reason %+v %v %v", r, ok, err)
	}
	if res := run(ActionDeleteCertificate, control.CertificateSelection{ID: spare.Metadata.ID}, ""); res.Code != ResultApplied {
		t.Fatalf("delete unlinked %v", res.Code)
	}
}
