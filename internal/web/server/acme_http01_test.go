// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jay94ks/seafield/internal/web/provlog"
)

func TestACMEIssueThroughHTTP01(t *testing.T) {
	f, _, ca, _ := acmeFixture(t)
	l, _ := provlog.Open("", provlog.Options{})
	l.Enable("test")
	f.srv.opt.ProviderLog = l
	acct := newAccount(t, f)
	if code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "app", "names": []string{"app.other.org"}, "account": acct}); code != 422 || errCode(out) != "no-domain" {
		t.Fatalf("responder off: %d %v", code, out)
	}
	f.srv.opt.ACMEHTTP01 = true
	if code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "wild", "names": []string{"*.other.org"}, "account": acct}); code != 422 || errCode(out) != "no-domain" {
		t.Fatalf("a wildcard needs DNS-01: %d %v", code, out)
	}
	// the CA fetches through the responder handler, as ingress forwards it
	h := f.srv.ACMEHandler()
	ca.HTTPGet = func(_ context.Context, host, token string) (string, error) {
		req := httptest.NewRequest("GET", "http://"+host+"/.well-known/acme-challenge/"+token, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			return "", io.ErrUnexpectedEOF
		}
		return rec.Body.String(), nil
	}
	// one HTTP-01 name and one DNS-01 name in the same certificate
	code, out := f.do("POST", "/api/v1/acme/certs", map[string]any{"name": "app", "names": []string{"app.other.org", "shop.example.com"}, "account": acct})
	if code != 201 {
		t.Fatalf("add cert: %d %v", code, out)
	}
	_, out = f.do("GET", "/api/v1/acme/certs/app", nil)
	if m, rs := out["methods"].(map[string]any), out["methodReasons"].(map[string]any); m["shop.example.com"] != "dns-01" || m["app.other.org"] != nil || rs["app.other.org"] != "not-registered" {
		t.Fatalf("methods: %v %v", m, rs)
	}
	// app.other.org is not under a registered cluster domain: the order
	// stops before the CA is asked
	if code, out := f.do("POST", "/api/v1/acme/certs/app/issue", map[string]any{"opId": opA}); code != 202 {
		t.Fatalf("issue: %d %v", code, out)
	}
	out = waitCert(t, f, "app")
	if o := lastOrder(out); o["state"] != "failed" || o["errorCode"] != "not-registered" || ca.Issued() != 0 {
		t.Fatalf("unregistered HTTP-01 name: %v", o)
	}
	if code, out := f.do("POST", "/api/v1/dns/domains", map[string]any{"domain": "other.org"}); code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	if _, out := f.do("GET", "/api/v1/acme/certs/app", nil); out["methods"].(map[string]any)["app.other.org"] != "http-01" {
		t.Fatalf("methods after register: %v", out["methods"])
	}
	if code, out := f.do("POST", "/api/v1/acme/certs/app/issue", map[string]any{"opId": opB}); code != 202 {
		t.Fatalf("issue: %d %v", code, out)
	}
	out = waitCert(t, f, "app")
	if o := lastOrder(out); o["state"] != "done" {
		t.Fatalf("order: %v", o)
	}
	if ca.Issued() != 1 {
		t.Fatal("not issued")
	}
	if p := l.List(provlog.Filter{Provider: "acme:http-01", Op: "Respond"}, 0, 0); len(p.Entries) != 1 || p.Entries[0].Attrs["host"] != "app.other.org" {
		t.Fatalf("responder log: %+v", p)
	}
	// tokens are gone after the order
	f.srv.acmeHTTP.mu.Lock()
	n := len(f.srv.acmeHTTP.tokens)
	f.srv.acmeHTTP.mu.Unlock()
	if n != 0 {
		t.Fatalf("%d tokens left", n)
	}
}

func TestACMEHTTPResponder(t *testing.T) {
	f, _, _, _ := acmeFixture(t)
	f.srv.acmeHTTP.add("app.example.com", "tok1", "tok1.thumb")
	h := f.srv.ACMEHandler()
	for _, c := range []struct {
		method, url string
		code        int
		body        string
	}{
		{"GET", "http://app.example.com/.well-known/acme-challenge/tok1", 200, "tok1.thumb"},
		{"GET", "http://APP.example.com:80/.well-known/acme-challenge/tok1", 200, "tok1.thumb"},
		{"GET", "http://other.example.com/.well-known/acme-challenge/tok1", 404, ""},
		{"GET", "http://app.example.com/.well-known/acme-challenge/nope", 404, ""},
		{"POST", "http://app.example.com/.well-known/acme-challenge/tok1", 404, ""},
		{"GET", "http://app.example.com/api/v1/auth/session", 404, ""},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(c.method, c.url, nil))
		if rec.Code != c.code || (c.code == http.StatusOK && rec.Body.String() != c.body) {
			t.Errorf("%s %s: %d %q", c.method, c.url, rec.Code, rec.Body.String())
		}
	}
	f.srv.acmeHTTP.remove("tok1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://app.example.com/.well-known/acme-challenge/tok1", nil))
	if rec.Code != 404 {
		t.Fatal("removed token still answered")
	}
}
