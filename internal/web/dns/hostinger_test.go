// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/web/provlog"
)

// hostingerAPI is a stand-in for the Hostinger API with the response
// shapes of OpenAPI 3.9.2.
type hostingerAPI struct {
	mu       sync.Mutex
	zone     []hostingerSet
	calls    []string
	bodies   map[string]string
	fail429  int
	snapshot string
}

func (a *hostingerAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, r.Method+" "+r.URL.Path)
	b, _ := io.ReadAll(r.Body)
	if a.bodies == nil {
		a.bodies = map[string]string{}
	}
	a.bodies[r.Method+" "+r.URL.Path] = string(b)
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer good-token" {
		w.WriteHeader(401)
		io.WriteString(w, `{"message":"Unauthenticated","correlation_id":"c-401"}`)
		return
	}
	if a.fail429 > 0 {
		a.fail429--
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(429)
		io.WriteString(w, `{"message":"Too Many Attempts."}`)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /api/domains/v1/portfolio":
		io.WriteString(w, `[{"id":1,"domain":"example.com","type":"domain","status":"active"},{"id":2,"domain":"other.org","type":"domain","status":"active"},{"id":3,"domain":"gone.net","type":"domain","status":"expired"}]`)
	case "GET /api/domains/v1/portfolio/example.com":
		io.WriteString(w, `{"domain":"example.com","name_servers":{"ns1":"ns1.dns-parking.com","ns2":"ns2.dns-parking.com"}}`)
	case "GET /api/domains/v1/portfolio/other.org":
		io.WriteString(w, `{"domain":"other.org","name_servers":{"ns1":"ns1.cloudflare.com","ns2":"ns2.cloudflare.com"}}`)
	case "GET /api/dns/v1/zones/example.com":
		json.NewEncoder(w).Encode(a.zone)
	case "PUT /api/dns/v1/zones/example.com":
		var u hostingerUpdate
		json.Unmarshal(b, &u)
		for _, s := range u.Zone {
			a.drop(s.Name, s.Type)
			a.zone = append(a.zone, s)
		}
		a.snapshot = time.Now().UTC().Format(time.RFC3339)
		io.WriteString(w, `{"message":"Request accepted"}`)
	case "DELETE /api/dns/v1/zones/example.com":
		var d struct{ Filters []Key }
		json.Unmarshal(b, &d)
		for _, k := range d.Filters {
			a.drop(k.Name, k.Type)
		}
		io.WriteString(w, `{"message":"Request accepted"}`)
	case "POST /api/dns/v1/zones/example.com/validate":
		if strings.Contains(string(b), `"CNAME"`) {
			w.WriteHeader(422)
			io.WriteString(w, `{"message":"The zone is invalid.","errors":{"zone.0.records":["CNAME conflicts with other records"]},"correlation_id":"c-422"}`)
			return
		}
		io.WriteString(w, `{"message":"Request accepted"}`)
	case "GET /api/dns/v1/snapshots/example.com":
		out := `[{"id":10,"reason":"Zone records update request","created_at":"2025-02-27T11:54:22Z"}`
		if a.snapshot != "" {
			out += `,{"id":11,"reason":"Zone records update request","created_at":"` + a.snapshot + `"}`
		}
		io.WriteString(w, out+"]")
	case "POST /api/dns/v1/snapshots/example.com/10/restore":
		io.WriteString(w, `{"message":"Request accepted"}`)
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"message":"Not found"}`)
	}
}

func (a *hostingerAPI) drop(name, typ string) {
	kept := a.zone[:0]
	for _, s := range a.zone {
		if s.Name != name || s.Type != typ {
			kept = append(kept, s)
		}
	}
	a.zone = kept
}

func hostingerFixture(t *testing.T, token string) (*hostingerAPI, Provider, *provlog.Log) {
	api := &hostingerAPI{zone: []hostingerSet{
		{Name: "@", Type: "A", TTL: 3600, Records: []hostingerRecord{{Content: "198.51.100.7"}}},
		{Name: "www", Type: "CNAME", TTL: 3600, Records: []hostingerRecord{{Content: "example.com."}}},
		{Name: "@", Type: "MX", TTL: 3600, Records: []hostingerRecord{{Content: "10 mx1.hostinger.com."}, {Content: "20 mx2.hostinger.com."}}},
		{Name: "@", Type: "TXT", TTL: 3600, Records: []hostingerRecord{{Content: `"v=spf1 -all"`}, {Content: "off", IsDisabled: true}}},
		{Name: "@", Type: "SOA", TTL: 3600, Records: []hostingerRecord{{Content: "ns1.dns-parking.com. dns.hostinger.com. 1 10000 2400 604800 600"}}},
	}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	l, _ := provlog.Open("", provlog.Options{})
	l.Enable("test")
	reg := &Registry{Log: l, BaseURL: srv.URL}
	reg.Register(HostingerVendor())
	p, err := reg.Open("hostinger", "conn-1", token)
	if err != nil {
		t.Fatal(err)
	}
	return api, p, l
}

func TestHostingerZoneRoundTrip(t *testing.T) {
	api, p, l := hostingerFixture(t, "good-token")
	ctx := t.Context()
	z, err := p.GetZone(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	mx := z.Find(Key{"@", "MX"})
	if mx == nil || len(mx.Records) != 2 || mx.Records[0] != (Record{Content: "mx1.hostinger.com.", Priority: 10}) {
		t.Fatalf("MX priority must come from the content: %+v", mx)
	}
	txt := z.Find(Key{"@", "TXT"})
	if txt == nil || len(txt.Records) != 1 || txt.Records[0].Content != "v=spf1 -all" {
		t.Fatalf("TXT: quotes stripped, disabled left out: %+v", txt)
	}

	up := RRSet{Name: "_acme-challenge.shop", Type: "TXT", TTL: 60, Records: []Record{{Content: "tok1"}, {Content: "tok2"}}}
	mail := RRSet{Name: "@", Type: "MX", TTL: 300, Records: []Record{{Content: "mail.example.com.", Priority: 5}}}
	res, err := p.Apply(ctx, "example.com", ChangeSet{Upsert: []RRSet{up, mail}, Delete: []Key{{"www", "CNAME"}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Snapshot != "11" {
		t.Fatalf("snapshot of this change: %q", res.Snapshot)
	}
	put := api.bodies["PUT /api/dns/v1/zones/example.com"]
	if !strings.Contains(put, `"overwrite":true`) || !strings.Contains(put, `"content":"5 mail.example.com."`) {
		t.Fatalf("PUT body: %s", put)
	}
	if del := api.bodies["DELETE /api/dns/v1/zones/example.com"]; !strings.Contains(del, `"filters":[{"name":"www","type":"CNAME"}]`) {
		t.Fatalf("DELETE body: %s", del)
	}
	z, _ = p.GetZone(ctx, "example.com")
	if z.Find(Key{"www", "CNAME"}) != nil || Fingerprint(z.Find(up.Key())) != Fingerprint(&up) || Fingerprint(z.Find(mail.Key())) != Fingerprint(&mail) {
		t.Fatalf("zone after apply: %+v", z)
	}
	if z.Find(Key{"@", "A"}) == nil {
		t.Fatal("untouched sets must stay")
	}

	// every call is in the log, with the token kept out
	pg := l.List(provlog.Filter{Provider: "dns:hostinger"}, 0, 0)
	if len(pg.Entries) < 5 {
		t.Fatalf("log entries: %d", len(pg.Entries))
	}
	for _, e := range pg.Entries {
		raw, _ := json.Marshal(e)
		if strings.Contains(string(raw), "good-token") {
			t.Fatalf("token in the log: %s", raw)
		}
		if e.Conn != "conn-1" || e.Op == "" {
			t.Fatalf("entry without conn/op: %s", raw)
		}
	}
}

func TestHostingerDomainsAndCheck(t *testing.T) {
	_, p, l := hostingerFixture(t, "good-token")
	ds, err := p.ListDomains(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	want := []Domain{{Name: "example.com", HasZone: true}, {Name: "gone.net"}, {Name: "other.org"}}
	if len(ds) != 3 || ds[0] != want[0] || ds[1] != want[1] || ds[2] != want[2] {
		t.Fatalf("domains: %+v", ds)
	}
	if pg := l.List(provlog.Filter{Op: "ListDomains", Text: "cloudflare"}, 0, 0); len(pg.Entries) == 0 {
		t.Fatal("the zone check must log the name servers it saw")
	}
	acct, err := p.Check(t.Context())
	if err != nil || acct.Domains != 3 {
		t.Fatalf("check: %+v %v", acct, err)
	}
}

func TestHostingerErrors(t *testing.T) {
	_, bad, _ := hostingerFixture(t, "bad-token")
	_, err := bad.Check(t.Context())
	if KindOf(err) != AuthFailed || !strings.Contains(err.Error(), "c-401") {
		t.Fatalf("auth: %v", err)
	}
	api, p, _ := hostingerFixture(t, "good-token")
	api.fail429 = 1
	if _, err := p.GetZone(t.Context(), "example.com"); err != nil {
		t.Fatalf("one 429 with a short Retry-After is retried: %v", err)
	}
	api.fail429 = 2
	if _, err := p.GetZone(t.Context(), "example.com"); KindOf(err) != RateLimited {
		t.Fatalf("second 429: %v", err)
	}
	if _, err := p.GetZone(t.Context(), "nothere.com"); KindOf(err) != NotFound {
		t.Fatalf("404: %v", err)
	}
	v := p.(Validator)
	probs, err := v.Validate(t.Context(), "example.com", ChangeSet{Upsert: []RRSet{{Name: "@", Type: "CNAME", TTL: 300, Records: []Record{{Content: "x."}}}}})
	if err != nil || len(probs) != 1 || !strings.Contains(probs[0].Message, "CNAME conflicts") {
		t.Fatalf("validate: %+v %v", probs, err)
	}
	if probs, err := v.Validate(t.Context(), "example.com", ChangeSet{Upsert: []RRSet{{Name: "a", Type: "A", TTL: 300, Records: []Record{{Content: "192.0.2.1"}}}}}); err != nil || len(probs) != 0 {
		t.Fatalf("valid change: %+v %v", probs, err)
	}
	sn := p.(Snapshotter)
	ss, err := sn.ListSnapshots(t.Context(), "example.com")
	if err != nil || len(ss) != 1 || ss[0].ID != "10" {
		t.Fatalf("snapshots: %+v %v", ss, err)
	}
	if err := sn.RestoreSnapshot(t.Context(), "example.com", "10"); err != nil {
		t.Fatal(err)
	}
	if err := sn.RestoreSnapshot(t.Context(), "example.com", "../x"); KindOf(err) != Invalid {
		t.Fatalf("bad id: %v", err)
	}
}
