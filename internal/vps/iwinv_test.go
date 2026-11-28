// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIwinv checks signatures and answers from a route table.
type fakeIwinv struct {
	t      *testing.T
	secret string
	mu     sync.Mutex
	calls  []string
	bodies []string
	routes map[string]func(r *http.Request) (int, any)
}

func (f *fakeIwinv) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.RequestURI()
	m := hmac.New(sha256.New, []byte(f.secret))
	m.Write([]byte(r.Header.Get("X-iwinv-Timestamp") + uri))
	if r.Header.Get("X-iwinv-Credential") != "AK" || r.Header.Get("X-iwinv-Signature") != hex.EncodeToString(m.Sum(nil)) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"code":"0x7","error_code":"CHECK_SIGNATURE","message":"Check signature.","result":"error"}`)
		return
	}
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+uri)
	f.bodies = append(f.bodies, string(body))
	f.mu.Unlock()
	h := f.routes[r.Method+" "+r.URL.Path]
	if h == nil {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"code":"0x16","error_code":"ID_INVALID","message":"","result":"error"}`)
		return
	}
	code, v := h(r)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(result any, extra ...any) map[string]any {
	m := map[string]any{"code": "0x00", "error_code": "SUCCESS", "message": "", "result": result}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i].(string)] = extra[i+1]
	}
	return m
}

func newFake(t *testing.T) (*fakeIwinv, ManagedProvider) {
	f := &fakeIwinv{t: t, secret: "SK", routes: map[string]func(*http.Request) (int, any){}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	p := IwinvVendor().New(Credential{AccessKey: "AK", SecretKey: "SK"}, Env{BaseURL: srv.URL, Transport: srv.Client().Transport, Now: func() time.Time { return time.Unix(1800000000, 0) }})
	return f, p
}

func TestIwinvSignatureAndAuthError(t *testing.T) {
	f, p := newFake(t)
	f.routes["GET /v1/auth"] = func(*http.Request) (int, any) { return 200, ok(map[string]any{"name": "Jay", "id": "jay"}) }
	a, err := p.Check(context.Background())
	if err != nil || a.Name != "Jay" || a.ID != "jay" {
		t.Fatalf("check = %+v, %v", a, err)
	}
	f.secret = "other"
	if _, err := p.Check(context.Background()); KindOf(err) != KindAuth {
		t.Fatalf("wrong secret: %v", err)
	}
}

func TestIwinvErrorKinds(t *testing.T) {
	f, p := newFake(t)
	f.routes["POST /v1/instances"] = func(*http.Request) (int, any) {
		return 400, map[string]any{"code": "0xd", "error_code": "UNAVAILABLE_FLAVOR", "message": "x", "result": []string{"flavor_id"}}
	}
	f.routes["POST /v1/instances/INSTANCE-1/shutdown"] = func(*http.Request) (int, any) {
		return 400, map[string]any{"code": "0x13", "error_code": "DELETED_OR_WORKING_INSTANCE", "message": "", "result": "error"}
	}
	f.routes["GET /v1/zones"] = func(*http.Request) (int, any) { return 502, "gateway" }
	_, err := p.Create(context.Background(), CreateRequest{Zone: "KR1-Z01", Image: "PIMAGE-1", Flavor: "F"})
	var e *Error
	if KindOf(err) != KindUnavailable || !asError(err, &e) || e.Code != "UNAVAILABLE_FLAVOR" || len(e.Fields) != 1 || e.Fields[0] != "flavor_id" {
		t.Fatalf("create err = %#v", err)
	}
	if err := p.Shutdown(context.Background(), "INSTANCE-1"); KindOf(err) != KindBusy {
		t.Fatalf("shutdown err = %v", err)
	}
	if _, err := p.Zones(context.Background()); KindOf(err) != KindTransport {
		t.Fatalf("zones err = %v", err)
	}
	if err := p.Delete(context.Background(), "../auth"); KindOf(err) != KindInvalid {
		t.Fatalf("bad id err = %v", err)
	}
	if strings.Contains(err.Error(), "SK") {
		t.Fatal("secret in error")
	}
}

func asError(err error, out **Error) bool {
	e, ok := err.(*Error)
	*out = e
	return ok
}

func TestIwinvCreateBody(t *testing.T) {
	f, p := newFake(t)
	f.routes["POST /v1/instances"] = func(*http.Request) (int, any) {
		return 202, ok([]any{map[string]any{"instance_id": "INSTANCE-abc", "name": "vps-2", "zone_id": "KR1-Z01", "flavor_id": "F1", "status": "building"}})
	}
	in, err := p.Create(context.Background(), CreateRequest{Name: "vps-2", Zone: "KR1-Z01", Image: "PIMAGE-u", Flavor: "F1", SSHKeys: []string{"SSHKEY-b", "SSHKEY-a"}, Script: "USCRIPT-1"})
	if err != nil || in.ID != "INSTANCE-abc" || in.Status != StatusPending {
		t.Fatalf("create = %+v, %v", in, err)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(f.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	if body["ssh_key_id"] != "SSHKEY-a,SSHKEY-b" || body["user_script_id"] != "USCRIPT-1" || body["count"] != float64(1) || body["attach_public_ip"] != true {
		t.Fatalf("body = %v", body)
	}
}

func TestIwinvInstanceAndPaging(t *testing.T) {
	f, p := newFake(t)
	row := func(id string) map[string]any {
		return map[string]any{"instance_id": id, "name": "n", "description": "sfc:tag", "status": "off", "zone": map[string]any{"zone_id": "KR1-Z01"},
			"flavor":  map[string]any{"flavor_id": "F1"},
			"ip":      []any{map[string]any{"type": "default", "public": map[string]any{"address": "203.0.113.9", "attached": true}}},
			"traffic": map[string]any{"default": 2000, "period": "MONTH"}, "start_date": "2026-11-02 10:00:00"}
	}
	f.routes["GET /v1/instances"] = func(r *http.Request) (int, any) {
		page := r.URL.Query().Get("page_no")
		n := 50
		if page == "2" {
			n = 3
		}
		rows := []any{}
		for i := 0; i < n; i++ {
			rows = append(rows, row(fmt.Sprintf("INSTANCE-%s-%d", page, i)))
		}
		return 200, ok(rows, "count", n, "page_no", page)
	}
	all, err := p.Instances(context.Background())
	if err != nil || len(all) != 53 {
		t.Fatalf("instances = %d, %v", len(all), err)
	}
	in := all[0]
	if in.Status != StatusOff || in.Description != "sfc:tag" || in.PublicIPv4 != "203.0.113.9" || in.IncludedGB != 2000 || in.TrafficPeriod != "MONTH" || in.Started.IsZero() {
		t.Fatalf("instance = %+v", in)
	}
	if f.calls[0] != "GET /v1/instances?page_no=1&page_size=50" {
		t.Fatalf("signed uri = %s", f.calls[0])
	}
	f.routes["GET /v1/instances/INSTANCE-x"] = func(*http.Request) (int, any) { return 200, ok([]any{}) }
	if _, err := p.Instance(context.Background(), "INSTANCE-x"); KindOf(err) != KindNotFound {
		t.Fatalf("missing = %v", err)
	}
}

func TestIwinvFlavorsPrice(t *testing.T) {
	f, p := newFake(t)
	f.routes["GET /v1/flavors"] = func(r *http.Request) (int, any) {
		if r.URL.RawQuery != "image_id=PIMAGE-u&min_vcpu=1&page_no=1&page_size=50&type=SINGLE%2CMAXIO&zone_id=KR1-Z01" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		return 200, ok([]any{
			map[string]any{"flavor_id": "F1", "name": "small", "price": map[string]any{"full": map[string]any{"KRW": 11000, "type": "MONTH"}, "partial": map[string]any{"KRW": map[string]any{"price": 14, "vat": 1, "total": 15}, "type": "Hour"}},
				"provide": "dedicated", "supporting_images": []any{"os_linux"},
				"spec": map[string]any{"vcpu": 1, "memory": 1024, "disk": 25, "network": 1, "type": "SINGLE", "gpu": nil}, "zone_mappings": []any{map[string]any{"zone_id": "KR1-Z01", "use": true}, map[string]any{"zone_id": "KR1-Z02", "use": false}}},
		}, "total", 1)
	}
	fl, err := p.Flavors(context.Background(), FlavorQuery{Zones: []string{"KR1-Z01"}, Images: []string{"PIMAGE-u"}, CoreTypes: []string{"SINGLE", "MAXIO"}, MinVCPU: 1})
	if err != nil || len(fl) != 1 {
		t.Fatalf("flavors = %v, %v", fl, err)
	}
	x := fl[0]
	if x.Full != (Price{KRW: 11000, Per: "month"}) || x.Partial == nil || *x.Partial != (Price{KRW: 15, Per: "hour"}) || len(x.Zones) != 2 || x.MemoryMiB != 1024 ||
		x.Provide != ProvideDedicated || x.CoreType != "SINGLE" || x.GPU != nil || !x.AvailableIn("KR1-Z01") || x.AvailableIn("KR1-Z02") ||
		!x.Boots(Image{Kind: "os_linux"}) || x.Boots(Image{Kind: "os_windows"}) {
		t.Fatalf("flavor = %+v", x)
	}
	f.routes["GET /v1/flavors/F9"] = func(*http.Request) (int, any) { return 200, ok([]any{}) }
	if _, err := p.Flavor(context.Background(), "F9"); KindOf(err) != KindNotFound {
		t.Fatalf("missing flavor = %v", err)
	}
	if _, err := p.Flavor(context.Background(), ".."); KindOf(err) != KindInvalid {
		t.Fatalf("dot id = %v", err)
	}
	if _, err := p.Flavor(context.Background(), "../auth"); KindOf(err) != KindInvalid {
		t.Fatalf("bad id = %v", err)
	}
}

func TestIwinvTrafficAndBill(t *testing.T) {
	f, p := newFake(t)
	f.routes["GET /v1/monitoring/traffic/INSTANCE-1"] = func(r *http.Request) (int, any) {
		if r.URL.RawQuery != "month=11&year=2026" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		return 200, ok([]any{map[string]any{"year": 2026, "month": 11, "unit": "mb", "traffic": map[string]any{"1": map[string]any{"total": "4096", "international": "1"}, "2": map[string]any{"total": "1024"}},
			"usage": map[string]any{"total": 5120, "bill_usage": 5}, "usage_start": "2026-11-01", "usage_end": "2026-11-02"}})
	}
	tr, err := p.MonthTraffic(context.Background(), "INSTANCE-1", 2026, 11)
	if err != nil || tr.TotalMB != 5120 || tr.DailyMB[1] != 4096 || tr.DailyMB[2] != 1024 || tr.BilledUnits != 5 {
		t.Fatalf("traffic = %+v, %v", tr, err)
	}
	f.routes["GET /v1/monitoring/traffic/INSTANCE-2"] = func(*http.Request) (int, any) {
		return 200, map[string]any{"code": "0x14", "error_code": "EMPTY_SET", "message": "", "result": "error"}
	}
	if tr, err := p.MonthTraffic(context.Background(), "INSTANCE-2", 2026, 11); err != nil || tr.TotalMB != 0 {
		t.Fatalf("empty traffic = %+v, %v", tr, err)
	}
	f.routes["GET /v1/bill/live"] = func(*http.Request) (int, any) {
		return 200, ok([]any{map[string]any{"bill_id": "BILL-live", "currency": "KRW", "price": 23456, "start_date": "2026-11-01", "end_date": "2026-11-27"}})
	}
	if b, err := p.LiveBill(context.Background()); err != nil || b.KRW != 23456 || b.From != "2026-11-01" {
		t.Fatalf("bill = %+v, %v", b, err)
	}
}

func TestCredentialRedacted(t *testing.T) {
	c := Credential{AccessKey: "AK", SecretKey: "SK"}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprintf("%v", struct{ C Credential }{c})} {
		if strings.Contains(s, "SK") || strings.Contains(s, "AK") {
			t.Fatalf("leak: %s", s)
		}
	}
	if _, err := json.Marshal(c); err == nil {
		t.Fatal("credential encoded")
	}
}

func TestIwinvDailyAllowanceCeiling(t *testing.T) {
	gb, day := int64(20), "DAY"
	r := iwinvInstance{ID: "i"}
	r.Traffic = &struct {
		Default *int64  `json:"default"`
		Period  *string `json:"period"`
	}{&gb, &day}
	if in := r.instance(); in.IncludedGB != 20 || in.TrafficPeriod != "DAY" || in.IncludedMaxGB != 600 {
		t.Fatalf("instance = %+v", in)
	}
}

func TestIwinvFlavorAllowance(t *testing.T) {
	if a := (iwinvFlavor{ID: "f"}).flavor().Traffic; a == nil || *a != (Allowance{GB: 20, Period: "DAY", MaxGB: 600, Estimated: true}) {
		t.Fatalf("usual = %+v", a)
	}
	gb, month := int64(2000), "MONTH"
	r := iwinvFlavor{ID: "f"}
	r.Traffic = &struct {
		Default *int64  `json:"default"`
		Period  *string `json:"period"`
	}{&gb, &month}
	if a := r.flavor().Traffic; *a != (Allowance{GB: 2000, Period: "MONTH"}) {
		t.Fatalf("reported = %+v", a)
	}
}

func TestIwinvCountsTX(t *testing.T) {
	if IwinvVendor().TrafficCounting != CountTX {
		t.Fatal("iwinv counts outgoing traffic only")
	}
}
