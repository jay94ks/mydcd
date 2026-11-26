// SPDX-License-Identifier: Apache-2.0

package server

import (
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

func TestACMEAutoIssue(t *testing.T) {
	f, _, ca, fake := acmeFixture(t)
	acct := newAccount(t, f)
	makeAutomation(t, f, "mydc-web", "a1b2c3d4-0000-4000-8000-0000000000c1", true, true)

	code, out := f.do("GET", "/api/v1/acme/auto", nil)
	if code != 200 || out["enabled"] != false || out["revision"] != float64(0) || len(out["domains"].([]any)) != 1 {
		t.Fatalf("defaults: %d %v", code, out)
	}
	put := func(rev any, enabled bool, account, mode string) (int, map[string]any) {
		return f.do("PUT", "/api/v1/acme/auto", map[string]any{"enabled": false, "account": account, "keyTypes": []string{"ec256"}, "dualRsa": false,
			"notifyAfterMinutes": 1, "domains": []any{map[string]any{"domain": "example.com", "enabled": enabled, "mode": mode, "tenants": []string{"shop"}}}, "revision": rev})
	}
	if code, _ := put(0, true, "", "per-host"); code != 422 {
		t.Fatalf("no account: %d", code)
	}
	if code, _ := put(0, true, acct, "both"); code != 422 {
		t.Fatalf("bad mode: %d", code)
	}
	if code, out = put(0, true, acct, "per-host"); code != 200 || out["revision"] != float64(1) {
		t.Fatalf("put: %d %v", code, out)
	}
	if code, _ := put(0, true, acct, "per-host"); code != 409 {
		t.Fatalf("stale: %d", code)
	}

	var certs []certstore.PublicEntry
	if err := withAdminConn(t, fake, func(c mydc.Conn) (err error) { certs, err = certAll(t.Context(), c); return }); err != nil {
		t.Fatal(err)
	}
	var scanAs func(tenant string, hosts ...string)
	var iv *ingressView
	if err := withAdminConn(t, fake, func(c mydc.Conn) (err error) { iv, err = ingressRead(t.Context(), c, control.IngressQuery{}); return }); err != nil {
		t.Fatal(err)
	}
	if hs := acmeWatchedHosts(iv); len(hs) == 0 || hs[0].listen == "" {
		t.Fatalf("watched hosts: %v", hs)
	}
	scan := func(hosts ...string) { scanAs("shop", hosts...) }
	scanAs = func(tenant string, hosts ...string) {
		a, _ := f.store.GetACMEAuto()
		defs, _ := f.store.ListACMECerts()
		var hs []watchedHost
		for _, h := range hosts {
			hs = append(hs, watchedHost{h, tenant, "php-shop", "node-a", "0.0.0.0:443"})
		}
		f.srv.acmeAutoScan(a, hs, certs, defs, time.Now())
		f.srv.WaitOrders()
	}
	scan("shop.example.com", "files.shop.example.com", "grafana.internal")
	c, err := f.store.GetACMECert("files-shop-example-com")
	if err != nil || c.AutoIssued == nil || c.AutoIssued.Host != "files.shop.example.com" || c.Fingerprint == "" || ca.Issued() != 1 {
		t.Fatalf("auto definition: %+v %v issued=%d", c, err, ca.Issued())
	}
	if _, err := f.store.GetACMECert("shop-example-com"); err == nil {
		t.Fatal("covered host issued")
	}
	_, out = f.do("GET", "/api/v1/acme/certs", nil)
	if !strings.Contains(mustString(out), `"host":"files.shop.example.com"`) {
		t.Fatalf("certs: %v", out)
	}
	_, out = f.do("GET", "/api/v1/acme/auto", nil)
	w := out["waiting"].([]any)
	if len(w) != 1 || w[0].(map[string]any)["host"] != "grafana.internal" || w[0].(map[string]any)["reason"] != "no-domain" || w[0].(map[string]any)["app"] != "php-shop" {
		t.Fatalf("waiting: %v", out)
	}
	if d := out["domains"].([]any)[0].(map[string]any); d["enabled"] != true || !strings.Contains(mustString(d["tenants"]), "shop") {
		t.Fatalf("domain: %v", d)
	}

	// the same host again: the definition covers it, no second order
	scan("files.shop.example.com")
	if ca.Issued() != 1 {
		t.Fatalf("issued again: %d", ca.Issued())
	}

	// a name outside the workspace's assignment waits
	scan("blog.example.com", "grafana.internal")
	if _, out = f.do("GET", "/api/v1/acme/auto", nil); !strings.Contains(mustString(out["waiting"]), `"reason":"not-assigned"`) || ca.Issued() != 1 {
		t.Fatalf("not-assigned: %v", out)
	}

	// at most acmeAutoPerRound new definitions a round
	scan("a1.shop.example.com", "a2.shop.example.com", "a3.shop.example.com", "a4.shop.example.com")
	if ca.Issued() != 4 {
		t.Fatalf("per round: %d", ca.Issued())
	}
	scan("a1.shop.example.com", "a2.shop.example.com", "a3.shop.example.com", "a4.shop.example.com")
	if ca.Issued() != 5 {
		t.Fatalf("next round: %d", ca.Issued())
	}

	// wildcard mode bundles one label under the domain
	_, out = f.do("GET", "/api/v1/acme/auto", nil)
	put(out["revision"], true, acct, "wildcard")
	scanAs("", "docs.example.com", "grafana.internal")
	if c, err := f.store.GetACMECert("wild-example-com"); err != nil || c.Names[0] != "*.example.com" {
		t.Fatalf("wildcard: %+v %v", c, err)
	}

	// off: the host waits; ignore drops it
	_, out = f.do("GET", "/api/v1/acme/auto", nil)
	put(out["revision"], false, acct, "per-host")
	scanAs("", "a.b.example.com", "grafana.internal")
	_, out = f.do("GET", "/api/v1/acme/auto", nil)
	if s := mustString(out["waiting"]); !strings.Contains(s, `"reason":"auto-off"`) {
		t.Fatalf("auto-off: %s", s)
	}
	if code, out := f.do("POST", "/api/v1/acme/auto/ignore", map[string]any{"host": "grafana.internal"}); code != 200 || strings.Contains(mustString(out["waiting"]), "grafana") {
		t.Fatalf("ignore: %d %v", code, out)
	}
	if code, _ := f.do("POST", "/api/v1/acme/auto/ignore", map[string]any{"host": "grafana.internal"}); code != 404 {
		t.Fatalf("ignore again: %d", code)
	}
	scan("grafana.internal")
	if _, out = f.do("GET", "/api/v1/acme/auto", nil); len(out["waiting"].([]any)) != 0 {
		t.Fatalf("ignored host back: %v", out)
	}

	fakeLogin(t, f, "alice")
	if code, _ := f.do("GET", "/api/v1/acme/auto", nil); code != 403 {
		t.Fatalf("alice: %d", code)
	}
}
