// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/web/acme"
	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/seal"
)

func acmeFixture(t *testing.T) (*fixture, *dns.FakeWorld, *acme.FakeCA, *mydc.Fake) {
	f, fake := newFakeFixture(t)
	world := dns.NewFakeWorld()
	dreg := &dns.Registry{}
	dreg.Register(dns.FakeVendor(world))
	box, _ := seal.Open(t.TempDir(), bytes.Repeat([]byte{3}, seal.KeySize))
	f.srv.opt.DNS, f.srv.opt.Seal = dreg, box
	ca := acme.NewFakeCA()
	ca.Lookup = f.srv.TXTLookup
	reg := &acme.Registry{}
	reg.Register(ca)
	f.srv.opt.ACME = reg
	f.srv.opt.Resolver = &zoneResolver{f: f}
	f.srv.opt.ACMEPropagation = time.Second
	f.srv.acme.storeRetry = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	addExampleDomain(t, f)
	fakeLogin(t, f, "admin")
	return f, world, ca, fake
}

// zoneResolver plays the domain's authoritative name server: it answers
// TXT from the fake provider's zone, after lag queries.
type zoneResolver struct {
	f   *fixture
	mu  sync.Mutex
	lag int
	txt int
}

func (z *zoneResolver) Query(ctx context.Context, server, fqdn, rtype string, recurse bool) (dns.Answer, error) {
	if rtype == "NS" {
		return dns.Answer{Values: []string{"ns1.fake-dns.test"}}, nil
	}
	if recurse || server != "ns1.fake-dns.test:53" {
		return dns.Answer{}, errors.New("unexpected query to " + server)
	}
	z.mu.Lock()
	z.txt++
	lagging := z.txt <= z.lag
	z.mu.Unlock()
	if lagging {
		return dns.Answer{}, nil
	}
	vals, err := z.f.srv.TXTLookup(ctx, fqdn)
	return dns.Answer{Values: vals}, err
}

func journalCount(fake *mydc.Fake, action string) int {
	n := 0
	for _, e := range fake.Journal() {
		if e.Action == action {
			n++
		}
	}
	return n
}

func newAccount(t *testing.T, f *fixture) string {
	t.Helper()
	if code, _ := f.do("POST", "/api/v1/acme/accounts", map[string]any{"ca": "fake"}); code != 422 {
		t.Fatal("account without accepting the terms")
	}
	code, out := f.do("POST", "/api/v1/acme/accounts", map[string]any{"ca": "fake", "email": "ops@example.com", "agreeTos": true})
	if code != 201 {
		t.Fatalf("account: %d %v", code, out)
	}
	return out["account"].(map[string]any)["id"].(string)
}

func waitCert(t *testing.T, f *fixture, name string) map[string]any {
	t.Helper()
	f.srv.WaitOrders()
	_, out := f.do("GET", "/api/v1/acme/certs/"+name, nil)
	return out
}

func lastOrder(out map[string]any) map[string]any {
	return out["orders"].([]any)[0].(map[string]any)
}

func TestACMEIssueThroughDNS01(t *testing.T) {
	f, _, ca, fake := acmeFixture(t)
	acct := newAccount(t, f)
	if code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "shop", "names": []string{"shop.other.org"}, "account": acct}); code != 422 || errCode(out) != "no-domain" {
		t.Fatalf("name outside a connected domain: %d %v", code, out)
	}
	code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "shop", "names": []string{"shop.example.com", "*.shop.example.com"}, "account": acct})
	if code != 201 || out["certificate"].(map[string]any)["autoRenew"] != true {
		t.Fatalf("add cert: %d %v", code, out)
	}

	if code, out := f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opA}); code != 202 {
		t.Fatalf("issue: %d %v", code, out)
	}
	out = waitCert(t, f, "shop")
	c := out["certificate"].(map[string]any)
	o := lastOrder(out)
	if o["state"] != "done" || o["storeOp"] != "acme-"+opA || c["fingerprint"] == nil || c["keyType"] != "ec256" {
		t.Fatalf("issued cert: %v", out)
	}
	if ca.Issued() != 1 || journalCount(fake, mydc.ActionPutCertificate) != 1 {
		t.Fatalf("issued %d, journal %v", ca.Issued(), fake.Journal())
	}
	// challenge TXT records are gone
	if vals, _ := f.srv.TXTLookup(context.Background(), "_acme-challenge.shop.example.com"); len(vals) != 0 {
		t.Fatalf("TXT left: %v", vals)
	}
	// the signed original is the clicking user's op; it holds no key
	if code, out := f.do("GET", "/api/v1/ops/acme-"+opA, nil); code != 200 || out["op"].(map[string]any)["state"] != "applied" || out["op"].(map[string]any)["action"] != "put-certificate" {
		t.Fatalf("store op: %d %v", code, out)
	}
	ops, _ := f.store.ListOps("u-admin", "", 0)
	certs, _ := f.store.ListACMECerts()
	orders, _ := f.store.ListACMEOrders("shop", 0)
	if raw := mustString([]any{ops, certs, orders}); strings.Contains(raw, "PRIVATE KEY") {
		t.Fatal("private key in bbolt")
	}
	for _, op := range ops {
		if bytes.Contains(op.Signed, []byte("PRIVATE KEY")) {
			t.Fatal("private key in the signed original")
		}
	}
	// the cluster store serves it to ingress
	var serving string
	issued := c["fingerprint"]
	_ = withAdminConn(t, fake, func(c mydc.Conn) error {
		all, err := certAll(context.Background(), c)
		for _, e := range all {
			if e.Metadata.ID.String() == issued && slices.ContainsFunc(e.Links, func(l certstore.Link) bool { return l.Host == "shop.example.com" }) {
				serving = e.Metadata.ID.String()
			}
		}
		return err
	})
	if serving != c["fingerprint"] {
		t.Fatalf("store has %q, web %v", serving, c["fingerprint"])
	}
	// the same opId does not issue again
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opA})
	f.srv.WaitOrders()
	if ca.Issued() != 1 {
		t.Fatalf("same opId issued again: %d", ca.Issued())
	}
	// public chain download
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/acme/certs/shop/chain", nil)
	resp, _ := f.hc.Do(req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") || strings.Contains(string(body), "PRIVATE") {
		t.Fatalf("chain: %s", body)
	}

	// revoke needs the name typed and turns renewal off
	if code, _ := f.do("POST", "/api/v1/acme/certs/shop/revoke", map[string]any{"confirm": "x"}); code != 400 {
		t.Fatal("revoke without confirm")
	}
	if code, out := f.do("POST", "/api/v1/acme/certs/shop/revoke", map[string]any{"confirm": "shop"}); code != 200 || out["certificate"].(map[string]any)["autoRenew"] != false {
		t.Fatalf("revoke: %d %v", code, out)
	}
	if code, _ := f.do("DELETE", "/api/v1/acme/accounts/"+acct, nil); code != 409 {
		t.Fatal("account in use deleted")
	}
}

// A lost put-certificate reply is settled only by resending the same
// original with the same key; still unknown after the retries ends the order
// store-unknown, and the op cannot be resumed without the key.
func TestACMEStoreLostReply(t *testing.T) {
	f, _, _, fake := acmeFixture(t)
	acct := newAccount(t, f)
	f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "shop", "names": []string{"shop.example.com"}, "account": acct})

	// first reply lost after commit: the resend gets the same result
	fake.LoseNextReply("submit", true)
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opA})
	out := waitCert(t, f, "shop")
	if o := lastOrder(out); o["state"] != "done" {
		t.Fatalf("after one lost reply: %v", out)
	}
	first := out["certificate"].(map[string]any)["fingerprint"]
	if n := journalCount(fake, mydc.ActionPutCertificate); n != 1 {
		t.Fatalf("committed %d times", n)
	}
	_, n := f.do("GET", "/api/v1/notifications", nil)
	if strings.Contains(mustString(n), "결과 확인 필요") {
		t.Fatalf("unknown notice for a settled retry: %v", n)
	}

	// every reply lost before commit: 1 send + 3 resends, then store-unknown
	for range 4 {
		fake.LoseNextReply("submit", false)
	}
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opB})
	out = waitCert(t, f, "shop")
	o := lastOrder(out)
	if o["state"] != "failed" || o["errorCode"] != "store-unknown" || o["storeOp"] != "acme-"+opB {
		t.Fatalf("lost replies: %v", o)
	}
	if out["certificate"].(map[string]any)["fingerprint"] != first {
		t.Fatalf("unknown store changed the public state: %v", out)
	}
	code, op := f.do("GET", "/api/v1/ops/acme-"+opB, nil)
	if code != 200 || op["op"].(map[string]any)["state"] != "unknown" {
		t.Fatalf("store op: %d %v", code, op)
	}
	if code, out := f.do("POST", "/api/v1/ops/acme-"+opB+"/result", nil); code != 202 || out["op"].(map[string]any)["resultFound"] != false {
		t.Fatalf("result: %d %v", code, out)
	}
	if n := journalCount(fake, mydc.ActionPutCertificate); n != 1 {
		t.Fatalf("committed %d times", n)
	}
	_, n = f.do("GET", "/api/v1/notifications", nil)
	if !strings.Contains(mustString(n), "결과 확인 필요") {
		t.Fatalf("no unknown notice: %v", n)
	}
	// The original holds only the sealed receipt, so it can be resumed
	// without the key; it commits once.
	if code, out := f.do("POST", "/api/v1/ops/acme-"+opB+"/resume", nil); code != 200 || out["op"].(map[string]any)["state"] != "applied" {
		t.Fatalf("resume: %d %v", code, out)
	}
	if n := journalCount(fake, mydc.ActionPutCertificate); n != 2 {
		t.Fatalf("committed %d times", n)
	}
}

func TestACMECAABlocksAndRenewal(t *testing.T) {
	f, world, ca, _ := acmeFixture(t)
	acct := newAccount(t, f)
	f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "shop", "names": []string{"shop.example.com"}, "account": acct, "keyTypes": []string{"rsa4096", "ec384"}})
	world.SetRecord("example.com", dns.RRSet{Name: "@", Type: "CAA", TTL: 3600, Records: []dns.Record{{Content: `0 issue "letsencrypt.org"`}}})
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opA})
	out := waitCert(t, f, "shop")
	if o := lastOrder(out); o["errorCode"] != "caa-blocked" || ca.Issued() != 0 {
		t.Fatalf("CAA: %v", o)
	}
	if out["certificate"].(map[string]any)["failures"] != float64(1) {
		t.Fatalf("failure not counted: %v", out)
	}
	_, n := f.do("GET", "/api/v1/notifications", nil)
	if !strings.Contains(mustString(n), "인증서 발급 실패") {
		t.Fatalf("no failure notification: %v", n)
	}

	// allow the fake CA; a manual issue falls back to the second key type
	world.SetRecord("example.com", dns.RRSet{Name: "@", Type: "CAA", TTL: 3600, Records: []dns.Record{{Content: `0 issue "mydc-fake-ca.invalid"`}}})
	f.do("POST", "/api/v1/acme/certs/shop/issue", map[string]any{"opId": opB})
	out = waitCert(t, f, "shop")
	if o := lastOrder(out); o["state"] != "done" || o["keyType"] != "ec384" || out["certificate"].(map[string]any)["failures"] != float64(0) {
		t.Fatalf("issue: %v", out)
	}
	_, n = f.do("GET", "/api/v1/notifications", nil)
	if !strings.Contains(mustString(n), "키 형식 바꿈") {
		t.Fatalf("no key type fallback notice: %v", n)
	}

	// renewal from the tick has no session to sign with: no order
	// runs, nothing counts as a failure, and the owner is told once
	c, _ := f.store.GetACMECert("shop")
	c.NextRenew = time.Now().Add(-time.Hour)
	f.store.PutACMECert(c)
	before := len(out["orders"].([]any))
	for range 2 {
		f.srv.acmeTick()
	}
	out = waitCert(t, f, "shop")
	if len(out["orders"].([]any)) != before || ca.Issued() != 1 || out["certificate"].(map[string]any)["failures"] != float64(0) {
		t.Fatalf("renewal ran: %v issued=%d", out, ca.Issued())
	}
	_, n = f.do("GET", "/api/v1/notifications", nil)
	if c := strings.Count(mustString(n), "인증서 직접 갱신 필요"); c != 1 {
		t.Fatalf("renewal notices %d: %v", c, n)
	}
}

// withAdminConn runs fn on a fresh admin login to the fake (what another
// mydc client would see).
func withAdminConn(t *testing.T, fake *mydc.Fake, fn func(mydc.Conn) error) error {
	t.Helper()
	ctx := context.Background()
	c, err := fake.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tk, err := c.CredentialChallenge(ctx, "admin", mydc.MethodPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.CredentialLogin(ctx, tk, []byte("admin")); err != nil {
		t.Fatal(err)
	}
	return fn(c)
}
