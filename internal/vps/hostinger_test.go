// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeHostinger answers in the shape of the public OpenAPI 5.1.0 and
// records every request it sees.
type fakeHostinger struct {
	mu   sync.Mutex
	seen []string
	keys []string
	srv  *httptest.Server
}

const fakeHostingerVM = `{"id":17923,"subscription_id":"Azz353Uhl1xC54pR0","data_center_id":17,"plan":"KVM 2","hostname":"srv17923.hstgr.cloud","state":"running","actions_lock":"unlocked","cpus":2,"memory":8192,"disk":102400,"bandwidth":8192000,"ipv4":[{"id":5,"address":"203.0.113.10","ptr":""}],"ipv6":null,"template":{"id":1121,"name":"Ubuntu 24.04 LTS","description":"","documentation":null},"created_at":"2026-11-01T07:25:36.00000Z"}`

func newFakeHostinger(t *testing.T) (*fakeHostinger, OwnedProvider) {
	f := &fakeHostinger{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.seen = append(f.seen, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer TOKEN-ab12" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"message":"Unauthenticated"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /api/vps/v1/virtual-machines":
			_, _ = io.WriteString(w, "["+fakeHostingerVM+"]")
		case "GET /api/vps/v1/virtual-machines/17923":
			_, _ = io.WriteString(w, fakeHostingerVM)
		case "POST /api/vps/v1/virtual-machines/17923/stop", "POST /api/vps/v1/virtual-machines/17923/start":
			_, _ = io.WriteString(w, `{"id":1,"name":"stop","state":"sent"}`)
		case "POST /api/vps/v1/virtual-machines/17923/ssh-keys":
			var body struct{ Keys []string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			f.keys = append(f.keys, body.Keys...)
			f.mu.Unlock()
			_, _ = io.WriteString(w, `{"id":2,"name":"ssh_keys_add","state":"sent"}`)
		case "GET /api/vps/v1/virtual-machines/17923/metrics":
			// 2026-11-01 00:00 UTC = 1793491200, 2026-11-02 = +86400.
			_, _ = io.WriteString(w, `{"outgoing_traffic":{"unit":"bytes","usage":{"1793491200":3000000,"1793494800":2000000,"1793577600":1000000}},"incoming_traffic":{"unit":"bytes","usage":{"1793491200":4000000}}}`)
		case "GET /api/billing/v1/subscriptions":
			_, _ = io.WriteString(w, `[{"id":"other","status":"active"},{"id":"Azz353Uhl1xC54pR0","name":"KVM 2","status":"not_renewing","billing_period":1,"billing_period_unit":"month","currency_code":"usd","total_price":899,"renewal_price":1199,"is_auto_renewed":false,"created_at":"2026-11-01T07:25:36Z","expires_at":"2026-12-01T07:25:36Z","next_billing_at":"2026-12-01T07:25:36Z"}]`)
		case "GET /api/vps/v1/virtual-machines/404":
			w.WriteHeader(http.StatusNotFound)
		case "POST /api/vps/v1/virtual-machines/423/stop":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = io.WriteString(w, `{"message":"bad","errors":{"virtualMachineId":["locked"]}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	t.Cleanup(f.srv.Close)
	now := func() time.Time { return time.Date(2026, 11, 28, 5, 0, 0, 0, time.UTC) }
	return f, HostingerVendor().NewOwned(Credential{AccessKey: "TOKEN-ab12"}, Env{BaseURL: f.srv.URL, Now: now})
}

func TestHostingerVendor(t *testing.T) {
	v := HostingerVendor()
	if v.Ownership != Owned || v.New != nil || v.NewOwned == nil || !v.TokenOnly || v.TrafficCounting != CountRXTX {
		t.Fatalf("vendor %+v", v)
	}
	if !v.Accepts(Credential{AccessKey: "T"}) || v.Accepts(Credential{AccessKey: "A", SecretKey: "S"}) {
		t.Fatal("token credential")
	}
	// Listed, but only as Owned: a managed path never makes a provider of it.
	if _, ok := LookupOwned("hostinger"); !ok {
		t.Fatal("hostinger not listed as owned")
	}
	if _, ok := LookupManaged("hostinger"); ok {
		t.Fatal("hostinger listed as managed")
	}
}

func TestHostingerReads(t *testing.T) {
	f, p := newFakeHostinger(t)
	ctx := context.Background()
	acc, err := p.Check(ctx)
	if err != nil || acc.Name != "token …ab12" {
		t.Fatalf("check %+v %v", acc, err)
	}
	list, err := p.Instances(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("instances %+v %v", list, err)
	}
	in := list[0]
	if in.ID != "17923" || in.Status != StatusActive || in.PublicIPv4 != "203.0.113.10" || in.Flavor != "KVM 2" || in.Image != "Ubuntu 24.04 LTS" ||
		in.SubscriptionID != "Azz353Uhl1xC54pR0" || in.TrafficPeriod != "MONTH" || in.IncludedGB != 8000 || in.Zone != "17" || in.Started.IsZero() {
		t.Fatalf("instance %+v", in)
	}
	one, err := p.Instance(ctx, "17923")
	if err != nil || one.ID != in.ID {
		t.Fatalf("instance %+v %v", one, err)
	}
	tr, err := p.MonthTraffic(ctx, "17923", 2026, 11)
	if err != nil || tr.DailyMB[1] != 9 || tr.DailyMB[2] != 1 || tr.TotalMB != 10 || tr.First != "2026-11-01" || tr.Last != "2026-11-02" {
		t.Fatalf("traffic %+v %v", tr, err)
	}
	sub, err := p.Subscription(ctx, "17923")
	if err != nil || sub.Status != "not_renewing" || sub.AutoRenew || sub.Currency != "USD" || sub.RenewalCost != 1199 ||
		!sub.ExpiresAt.Equal(time.Date(2026, 12, 1, 7, 25, 36, 0, time.UTC)) || !sub.NextBilling.IsZero() {
		t.Fatalf("subscription %+v %v", sub, err)
	}
	_ = f
}

func TestHostingerPowerAndKey(t *testing.T) {
	f, p := newFakeHostinger(t)
	ctx := context.Background()
	if err := p.Shutdown(ctx, "17923"); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(ctx, "17923"); err != nil {
		t.Fatal(err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfake sfc-main"
	if err := p.AttachSSHKey(ctx, "17923", key); err != nil {
		t.Fatal(err)
	}
	if len(f.keys) != 1 || f.keys[0] != key {
		t.Fatalf("keys %v", f.keys)
	}
	if KindOf(p.AttachSSHKey(ctx, "17923", "ssh-rsa AAAA")) != KindInvalid || KindOf(p.AttachSSHKey(ctx, "17923", key+"\nssh-ed25519 x")) != KindInvalid {
		t.Fatal("only one ed25519 key")
	}
}

func TestHostingerErrors(t *testing.T) {
	_, p := newFakeHostinger(t)
	ctx := context.Background()
	if _, err := p.Instance(ctx, "404"); KindOf(err) != KindNotFound {
		t.Fatalf("404 %v", err)
	}
	err := p.Shutdown(ctx, "423")
	var e *Error
	if KindOf(err) != KindInvalid || !asError(err, &e) || len(e.Fields) != 1 || e.Fields[0] != "virtualMachineId" || strings.Contains(err.Error(), "locked") {
		t.Fatalf("422 %v", err)
	}
	if _, err := p.Instance(ctx, "../billing"); KindOf(err) != KindInvalid {
		t.Fatalf("path id %v", err)
	}
	bad := HostingerVendor().NewOwned(Credential{AccessKey: "WRONG"}, Env{BaseURL: p.(*hostinger).base})
	if _, err := bad.Check(ctx); KindOf(err) != KindAuth {
		t.Fatalf("auth %v", err)
	}
}

// The adapter refuses, before sending, every request outside its
// allow-list: buying, rebuilding, restoring, renewing, changing
// auto-renewal, payment methods or firewalls, resetting the password.
func TestHostingerAllowList(t *testing.T) {
	f, p := newFakeHostinger(t)
	h := p.(*hostinger)
	ctx := context.Background()
	refused := []struct{ method, path string }{
		{http.MethodPost, "/api/vps/v1/virtual-machines"},
		{http.MethodPost, "/api/billing/v1/orders"},
		{http.MethodPost, "/api/vps/v1/virtual-machines/17923/recreate"},
		{http.MethodPost, "/api/vps/v1/virtual-machines/17923/setup"},
		{http.MethodPost, "/api/vps/v1/virtual-machines/17923/backups/1/restore"},
		{http.MethodPost, "/api/vps/v1/virtual-machines/17923/restart"},
		{http.MethodPut, "/api/vps/v1/virtual-machines/17923/root-password"},
		{http.MethodDelete, "/api/billing/v1/subscriptions/x/auto-renewal/disable"},
		{http.MethodPatch, "/api/billing/v1/subscriptions/x/auto-renewal/enable"},
		{http.MethodPost, "/api/billing/v1/subscriptions/x/renew"},
		{http.MethodPost, "/api/billing/v1/payment-methods/1"},
		{http.MethodPost, "/api/vps/v1/firewall/1/activate/17923"},
		{http.MethodDelete, "/api/vps/v1/virtual-machines/17923/ssh-keys"},
		{http.MethodGet, "/api/vps/v1/virtual-machines/17923/../../billing/v1/orders"},
	}
	for _, r := range refused {
		if err := h.do(ctx, r.method, r.path, nil, nil, nil); KindOf(err) != KindInvalid {
			t.Fatalf("%s %s: %v", r.method, r.path, err)
		}
	}
	if len(f.seen) != 0 {
		t.Fatalf("refused requests reached the vendor: %v", f.seen)
	}
}
