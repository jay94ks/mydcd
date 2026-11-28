// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// iwinv adapter. Paths and fields follow the iwinv API v1.0 OpenAPI
// document (api.iwinv.kr/iwinv, updated 2026-10-18):
//
//	GET    /v1/auth                                 account check
//	GET    /v1/zones, /v1/images, /v1/flavors       catalogue
//	GET    /v1/auth/ssh_key, /v1/instances/script   SSH keys, user scripts
//	POST   /v1/instances                            create (billed at once)
//	GET    /v1/instances, /v1/instances/{id}        read
//	POST   /v1/instances/{id}/shutdown | /start     power
//	DELETE /v1/instances/{id}                       delete
//	GET    /v1/monitoring/traffic/{id}              daily traffic of a month
//	GET    /v1/bill/live                            this month's charge so far
//
// Requests are signed: X-iwinv-Signature = hex(HMAC-SHA256(secret,
// timestamp + "/v1/..." with the exact query string sent)). It has not been
// run against a real account yet.

// IwinvBaseURL is the production (KR1) address.
const IwinvBaseURL = "https://api-kr.iwinv.kr"

const iwinvPageSize = 50

// IwinvVendor is the iwinv adapter.
func IwinvVendor() Vendor {
	// iwinv counts outgoing traffic only (Jay 2026-11-27).
	return Vendor{ID: "iwinv", Name: "iwinv", Ownership: Managed, TrafficCounting: CountTX, OverageTiers: iwinvOverage, New: func(c Credential, env Env) ManagedProvider {
		base := strings.TrimRight(env.BaseURL, "/")
		if base == "" {
			base = IwinvBaseURL
		}
		now := env.Now
		if now == nil {
			now = time.Now
		}
		return &iwinv{cred: c, base: base, now: now, http: &http.Client{Transport: env.Transport, Timeout: 30 * time.Second}}
	}}
}

type iwinv struct {
	cred Credential
	base string
	now  func() time.Time
	http *http.Client
}

func (*iwinv) Kind() string { return "iwinv" }

// envelope is iwinv's common response shape.
type envelope struct {
	Code      string          `json:"code"`
	ErrorCode string          `json:"error_code"`
	Result    json.RawMessage `json:"result"`
	Count     int             `json:"count"`
	Total     *int            `json:"total"`
}

func (p *iwinv) sign(uri string) (string, string) {
	ts := strconv.FormatInt(p.now().Unix(), 10)
	m := hmac.New(sha256.New, []byte(p.cred.SecretKey))
	m.Write([]byte(ts + uri))
	return ts, hex.EncodeToString(m.Sum(nil))
}

// do sends one request. path starts with "/v1/"; query is encoded in key
// order so the signed URI equals the sent one.
func (p *iwinv) do(ctx context.Context, method, path string, query url.Values, body any) (envelope, error) {
	if !p.cred.Valid() || p.cred.SecretKey == "" {
		return envelope{}, &Error{Kind: KindAuth}
	}
	uri := path
	if len(query) > 0 {
		uri += "?" + query.Encode() // Encode sorts by key
	}
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return envelope{}, &Error{Kind: KindInvalid}
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+uri, rd)
	if err != nil {
		return envelope{}, &Error{Kind: KindInvalid}
	}
	ts, sig := p.sign(uri)
	req.Header.Set("X-iwinv-Timestamp", ts)
	req.Header.Set("X-iwinv-Credential", p.cred.AccessKey)
	req.Header.Set("X-iwinv-Signature", sig)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := p.http.Do(req)
	if err != nil {
		return envelope{}, &Error{Kind: KindTransport}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return envelope{}, &Error{Kind: KindTransport}
	}
	var env envelope
	if json.Unmarshal(raw, &env) != nil || env.ErrorCode == "" {
		if res.StatusCode >= 500 || res.StatusCode == http.StatusTooManyRequests {
			return envelope{}, &Error{Kind: KindTransport}
		}
		return envelope{}, &Error{Kind: KindProtocol}
	}
	if env.ErrorCode != "SUCCESS" {
		e := &Error{Kind: iwinvKind(env.ErrorCode, res.StatusCode), Code: env.ErrorCode}
		var fields []string
		if json.Unmarshal(env.Result, &fields) == nil {
			e.Fields = fields
		}
		return envelope{}, e
	}
	if res.StatusCode >= 300 {
		return envelope{}, &Error{Kind: KindProtocol}
	}
	return env, nil
}

func iwinvKind(code string, status int) Kind {
	switch code {
	case "CHECK_CREDENTIAL", "CHECK_SIGNATURE", "INVALID_SIGNATURE":
		return KindAuth
	case "CHECK_IP":
		return KindIPDenied
	case "DELETED_OR_WORKING_INSTANCE":
		return KindBusy
	case "UNAVAILABLE_FLAVOR", "UNAVAILABLE_COMBINATION", "UNAVAILABLE_SSH_KEY":
		return KindUnavailable
	case "LIMIT_EXCEEDED":
		return KindLimit
	case "EMPTY_SET":
		return KindEmpty
	case "CHECK_PARAM", "CHECK_PARAM_ENUM", "CHECK_LENGTH", "ID_INVALID", "CHECK_CONSOLE":
		return KindInvalid
	}
	if status >= 500 {
		return KindTransport
	}
	return KindProtocol
}

// list reads every page of a list endpoint into out (a pointer to a slice).
func list[T any](ctx context.Context, p *iwinv, path string, query url.Values) ([]T, error) {
	var all []T
	for page := 1; page <= 200; page++ {
		q := url.Values{}
		for k, v := range query {
			q[k] = v
		}
		q.Set("page_no", strconv.Itoa(page))
		q.Set("page_size", strconv.Itoa(iwinvPageSize))
		env, err := p.do(ctx, http.MethodGet, path, q, nil)
		if KindOf(err) == KindEmpty && page == 1 {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		var items []T
		if json.Unmarshal(env.Result, &items) != nil {
			return nil, &Error{Kind: KindProtocol}
		}
		all = append(all, items...)
		if len(items) < iwinvPageSize || env.Total != nil && len(all) >= *env.Total {
			return all, nil
		}
	}
	return nil, &Error{Kind: KindProtocol}
}

func one[T any](env envelope) (T, error) {
	var zero T
	var items []T
	if json.Unmarshal(env.Result, &items) == nil {
		if len(items) == 0 {
			return zero, &Error{Kind: KindNotFound}
		}
		return items[0], nil
	}
	var item T
	if json.Unmarshal(env.Result, &item) != nil {
		return zero, &Error{Kind: KindProtocol}
	}
	return item, nil
}

func (p *iwinv) Check(ctx context.Context) (Account, error) {
	env, err := p.do(ctx, http.MethodGet, "/v1/auth", nil, nil)
	if err != nil {
		return Account{}, err
	}
	a, err := one[struct {
		ID   any    `json:"id"`
		Name string `json:"name"`
	}](env)
	if err != nil {
		return Account{}, err
	}
	return Account{ID: anyString(a.ID), Name: a.Name}, nil
}

func (p *iwinv) Zones(ctx context.Context) ([]Zone, error) {
	env, err := p.do(ctx, http.MethodGet, "/v1/zones", nil, nil)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID     string `json:"zone_id"`
		Name   string `json:"zone_name"`
		Status string `json:"status"`
	}
	if json.Unmarshal(env.Result, &rows) != nil {
		return nil, &Error{Kind: KindProtocol}
	}
	out := make([]Zone, 0, len(rows))
	for _, r := range rows {
		out = append(out, Zone{ID: r.ID, Name: r.Name, Usable: r.Status == "available" || r.Status == "crowded"})
	}
	return out, nil
}

type iwinvImage struct {
	ID        string   `json:"image_id"`
	ImageType string   `json:"image_type"`
	Zone      []string `json:"zone"`
	OS        struct {
		Name   string `json:"name"`
		OSType string `json:"os_type"`
		Status string `json:"status"`
	} `json:"os"`
	Info *struct {
		Name string `json:"name"`
	} `json:"image_info"`
}

func (p *iwinv) Images(ctx context.Context, zone string) ([]Image, error) {
	q := url.Values{}
	if zone != "" {
		q.Set("zone_id", zone)
	}
	rows, err := list[iwinvImage](ctx, p, "/v1/images", q)
	if err != nil {
		return nil, err
	}
	out := make([]Image, 0, len(rows))
	for _, r := range rows {
		name := r.OS.Name
		if r.Info != nil && r.Info.Name != "" {
			name = r.Info.Name
		}
		out = append(out, Image{ID: r.ID, Name: name, Kind: r.ImageType, OS: r.OS.OSType, Linux: strings.HasSuffix(r.ImageType, "_linux"), Zones: r.Zone})
	}
	return out, nil
}

type iwinvPrice struct {
	KRW  json.RawMessage `json:"KRW"`
	Type string          `json:"type"`
}

func (r iwinvPrice) price() (Price, bool) {
	var n int64
	if json.Unmarshal(r.KRW, &n) != nil {
		var detail struct {
			Total int64 `json:"total"`
		}
		if json.Unmarshal(r.KRW, &detail) != nil || detail.Total == 0 {
			return Price{}, false
		}
		n = detail.Total
	}
	return Price{KRW: n, Per: strings.ToLower(r.Type)}, n > 0
}

type iwinvFlavor struct {
	ID      string `json:"flavor_id"`
	Name    string `json:"name"`
	Provide string `json:"provide"`
	Price   struct {
		Full    *iwinvPrice `json:"full"`
		Partial *iwinvPrice `json:"partial"`
	} `json:"price"`
	Spec struct {
		Disk    int64   `json:"disk"`
		Memory  int64   `json:"memory"`
		Network float64 `json:"network"`
		VCPU    int     `json:"vcpu"`
		Type    string  `json:"type"`
		GPU     *struct {
			Count  int    `json:"count"`
			Memory int64  `json:"memory"`
			Model  string `json:"model"`
		} `json:"gpu"`
	} `json:"spec"`
	Images  []string `json:"supporting_images"`
	Traffic *struct {
		Default *int64  `json:"default"`
		Period  *string `json:"period"`
	} `json:"traffic"`
	Zones []struct {
		ID  string `json:"zone_id"`
		Use bool   `json:"use"`
	} `json:"zone_mappings"`
}

func (r iwinvFlavor) flavor() Flavor {
	f := Flavor{ID: r.ID, Name: r.Name, CoreType: r.Spec.Type, VCPU: r.Spec.VCPU, MemoryMiB: r.Spec.Memory, DiskGB: r.Spec.Disk, NetworkGbps: r.Spec.Network, ImageKinds: r.Images}
	f.Traffic = iwinvAllowance(r.Traffic)
	switch p := strings.ToLower(r.Provide); p {
	case ProvideDedicated, ProvideShared, ProvideTest:
		f.Provide = p
	}
	if g := r.Spec.GPU; g != nil && g.Count > 0 {
		f.GPU = &GPU{Count: g.Count, MemoryGB: g.Memory, Model: g.Model}
	}
	if r.Price.Full != nil {
		f.Full, _ = r.Price.Full.price()
	}
	if r.Price.Partial != nil {
		if pr, ok := r.Price.Partial.price(); ok {
			f.Partial = &pr
		}
	}
	for _, z := range r.Zones {
		f.Zones = append(f.Zones, FlavorZone{ID: z.ID, Available: z.Use})
	}
	return f
}

func (q FlavorQuery) values() url.Values {
	v := url.Values{}
	join := func(k string, xs []string) {
		if len(xs) > 0 {
			v.Set(k, strings.Join(xs, ","))
		}
	}
	num := func(k string, n int64) {
		if n > 0 {
			v.Set(k, strconv.FormatInt(n, 10))
		}
	}
	join("zone_id", q.Zones)
	join("image_id", q.Images)
	join("type", q.CoreTypes)
	num("min_vcpu", int64(q.MinVCPU))
	num("max_vcpu", int64(q.MaxVCPU))
	num("min_memory", q.MinMemoryMiB)
	num("max_memory", q.MaxMemoryMiB)
	num("min_disk", q.MinDiskGB)
	num("max_disk", q.MaxDiskGB)
	num("min_gpu", int64(q.MinGPU))
	num("max_gpu", int64(q.MaxGPU))
	return v
}

func (p *iwinv) Flavors(ctx context.Context, q FlavorQuery) ([]Flavor, error) {
	rows, err := list[iwinvFlavor](ctx, p, "/v1/flavors", q.values())
	if err != nil {
		return nil, err
	}
	out := make([]Flavor, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.flavor())
	}
	return out, nil
}

func (p *iwinv) Flavor(ctx context.Context, id string) (Flavor, error) {
	if id == "" || id == "." || id == ".." || len(id) > 128 || strings.ContainsAny(id, "/?#%\x00") {
		return Flavor{}, &Error{Kind: KindInvalid}
	}
	env, err := p.do(ctx, http.MethodGet, "/v1/flavors/"+id, nil, nil)
	if KindOf(err) == KindEmpty {
		return Flavor{}, &Error{Kind: KindNotFound}
	}
	if err != nil {
		return Flavor{}, err
	}
	r, err := one[iwinvFlavor](env)
	if err != nil {
		return Flavor{}, err
	}
	return r.flavor(), nil
}

func (p *iwinv) SSHKeys(ctx context.Context) ([]SSHKey, error) {
	rows, err := list[struct {
		ID   string `json:"ssh_key_id"`
		Name string `json:"name"`
	}](ctx, p, "/v1/auth/ssh_key", nil)
	if err != nil {
		return nil, err
	}
	out := make([]SSHKey, 0, len(rows))
	for _, r := range rows {
		out = append(out, SSHKey{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

func (p *iwinv) Scripts(ctx context.Context) ([]Script, error) {
	rows, err := list[struct {
		ID   string `json:"script_id"`
		Name string `json:"name"`
	}](ctx, p, "/v1/instances/script", nil)
	if err != nil {
		return nil, err
	}
	out := make([]Script, 0, len(rows))
	for _, r := range rows {
		out = append(out, Script{ID: r.ID, Name: r.Name})
	}
	return out, nil
}

type iwinvInstance struct {
	ID     string  `json:"instance_id"`
	Name   string  `json:"name"`
	Memo   *string `json:"description"`
	Status string  `json:"status"`
	Zone   struct {
		ID string `json:"zone_id"`
	} `json:"zone"`
	Flavor struct {
		ID *string `json:"flavor_id"`
	} `json:"flavor"`
	IP []struct {
		Type   string `json:"type"`
		Public struct {
			Address  *string `json:"address"`
			Attached bool    `json:"attached"`
		} `json:"public"`
	} `json:"ip"`
	Traffic *struct {
		Default *int64  `json:"default"`
		Period  *string `json:"period"`
	} `json:"traffic"`
	Start *string `json:"start_date"`
}

var kst = time.FixedZone("KST", 9*3600)

// iwinvOverage is iwinv's outbound traffic price above the allowance,
// VAT excluded as published (Jay 2026-11-27): 70/60/50/40/30 KRW per GB
// per 1,000 GB. Domestic and overseas cost the same; inbound and
// iwinv-internal traffic is free.
var iwinvOverage = []OverageTier{{UpToGB: 1000, KRWPerGB: 70}, {UpToGB: 2000, KRWPerGB: 60}, {UpToGB: 3000, KRWPerGB: 50}, {UpToGB: 4000, KRWPerGB: 40}, {KRWPerGB: 30}}

// iwinvUsual is iwinv's usual allowance (Jay 2026-11-27), shown for a type
// whose catalogue row carries none.
var iwinvUsual = Allowance{GB: 20, Period: "DAY", MaxGB: 20 * iwinvAllowanceDays, Estimated: true}

func iwinvAllowance(t *struct {
	Default *int64  `json:"default"`
	Period  *string `json:"period"`
}) *Allowance {
	if t == nil || t.Default == nil || t.Period == nil {
		a := iwinvUsual
		return &a
	}
	a := Allowance{GB: *t.Default, Period: *t.Period}
	if a.Period == "DAY" {
		a.MaxGB = a.GB * iwinvAllowanceDays
	}
	return &a
}

// iwinvAllowanceDays is how many days of a daily traffic allowance a month
// holds at most.
const iwinvAllowanceDays = 30

func (r iwinvInstance) instance() Instance {
	in := Instance{ID: r.ID, Name: r.Name, Zone: r.Zone.ID}
	if r.Memo != nil {
		in.Description = *r.Memo
	}
	switch r.Status {
	case "active":
		in.Status = StatusActive
	case "pending":
		in.Status = StatusPending
	case "work":
		in.Status = StatusWorking
	case "off":
		in.Status = StatusOff
	default:
		in.Status = StatusError
	}
	if r.Flavor.ID != nil {
		in.Flavor = *r.Flavor.ID
	}
	for _, ip := range r.IP {
		if ip.Type == "default" && ip.Public.Address != nil && ip.Public.Attached {
			in.PublicIPv4 = *ip.Public.Address
		}
	}
	if r.Traffic != nil {
		if r.Traffic.Default != nil {
			in.IncludedGB = *r.Traffic.Default
		}
		if r.Traffic.Period != nil {
			in.TrafficPeriod = *r.Traffic.Period
		}
		if in.TrafficPeriod == "DAY" {
			// iwinv's daily allowance adds up to 30 days' worth a month
			// (20 GB/day → 600 GB/month, Jay 2026-11-27); the API does not
			// report the ceiling.
			in.IncludedMaxGB = in.IncludedGB * iwinvAllowanceDays
		}
	}
	if r.Start != nil {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", *r.Start, kst); err == nil {
			in.Started = t
		}
	}
	return in
}

func (p *iwinv) Instances(ctx context.Context) ([]Instance, error) {
	rows, err := list[iwinvInstance](ctx, p, "/v1/instances", nil)
	if err != nil {
		return nil, err
	}
	out := make([]Instance, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.instance())
	}
	return out, nil
}

func validInstanceID(id string) bool {
	if !strings.HasPrefix(id, "INSTANCE-") || len(id) > 64 {
		return false
	}
	for _, c := range id[len("INSTANCE-"):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return len(id) > len("INSTANCE-")
}

func (p *iwinv) Instance(ctx context.Context, id string) (Instance, error) {
	if !validInstanceID(id) {
		return Instance{}, &Error{Kind: KindInvalid}
	}
	env, err := p.do(ctx, http.MethodGet, "/v1/instances/"+id, nil, nil)
	if err != nil {
		return Instance{}, err
	}
	r, err := one[iwinvInstance](env)
	if err != nil {
		return Instance{}, err
	}
	return r.instance(), nil
}

func (p *iwinv) Create(ctx context.Context, r CreateRequest) (Instance, error) {
	if r.Zone == "" || r.Image == "" || r.Flavor == "" {
		return Instance{}, &Error{Kind: KindInvalid}
	}
	body := map[string]any{"zone_id": r.Zone, "image_id": r.Image, "flavor_id": r.Flavor, "count": 1, "attach_public_ip": true}
	if r.Name != "" {
		body["name"] = r.Name
	}
	if r.Description != "" {
		body["description"] = r.Description
	}
	if len(r.SSHKeys) > 0 {
		keys := append([]string(nil), r.SSHKeys...)
		sort.Strings(keys)
		body["ssh_key_id"] = strings.Join(keys, ",")
	}
	if r.Script != "" {
		body["user_script_id"] = r.Script
	}
	env, err := p.do(ctx, http.MethodPost, "/v1/instances", nil, body)
	if err != nil {
		return Instance{}, err
	}
	var rows []struct {
		ID     string `json:"instance_id"`
		Name   string `json:"name"`
		Zone   string `json:"zone_id"`
		Flavor string `json:"flavor_id"`
	}
	if json.Unmarshal(env.Result, &rows) != nil || len(rows) != 1 || !validInstanceID(rows[0].ID) {
		return Instance{}, &Error{Kind: KindProtocol}
	}
	return Instance{ID: rows[0].ID, Name: rows[0].Name, Zone: rows[0].Zone, Flavor: rows[0].Flavor, Status: StatusPending}, nil
}

func (p *iwinv) action(ctx context.Context, method, id, suffix string) error {
	if !validInstanceID(id) {
		return &Error{Kind: KindInvalid}
	}
	_, err := p.do(ctx, method, "/v1/instances/"+id+suffix, nil, nil)
	return err
}

func (p *iwinv) Shutdown(ctx context.Context, id string) error {
	return p.action(ctx, http.MethodPost, id, "/shutdown")
}
func (p *iwinv) Start(ctx context.Context, id string) error {
	return p.action(ctx, http.MethodPost, id, "/start")
}
func (p *iwinv) Delete(ctx context.Context, id string) error {
	return p.action(ctx, http.MethodDelete, id, "")
}

func (p *iwinv) MonthTraffic(ctx context.Context, id string, year, month int) (Traffic, error) {
	if !validInstanceID(id) || month < 1 || month > 12 || year < 2000 || year > 9999 {
		return Traffic{}, &Error{Kind: KindInvalid}
	}
	q := url.Values{"year": {strconv.Itoa(year)}, "month": {strconv.Itoa(month)}}
	env, err := p.do(ctx, http.MethodGet, "/v1/monitoring/traffic/"+id, q, nil)
	if KindOf(err) == KindEmpty {
		return Traffic{Year: year, Month: month, DailyMB: map[int]int64{}}, nil
	}
	if err != nil {
		return Traffic{}, err
	}
	r, err := one[struct {
		Year    int `json:"year"`
		Month   int `json:"month"`
		Traffic map[string]struct {
			Total json.Number `json:"total"`
		} `json:"traffic"`
		Usage struct {
			BillUsage float64 `json:"bill_usage"`
			Total     int64   `json:"total"`
		} `json:"usage"`
		Start string `json:"usage_start"`
		End   string `json:"usage_end"`
	}](env)
	if err != nil {
		return Traffic{}, err
	}
	if r.Year != year || r.Month != month {
		return Traffic{}, &Error{Kind: KindProtocol}
	}
	t := Traffic{Year: year, Month: month, DailyMB: map[int]int64{}, TotalMB: r.Usage.Total, BilledUnits: r.Usage.BillUsage, First: r.Start, Last: r.End}
	for k, v := range r.Traffic {
		d, err1 := strconv.Atoi(k)
		n, err2 := v.Total.Int64()
		if err1 != nil || err2 != nil || d < 1 || d > 31 || n < 0 {
			return Traffic{}, &Error{Kind: KindProtocol}
		}
		t.DailyMB[d] = n
	}
	return t, nil
}

func (p *iwinv) LiveBill(ctx context.Context) (Bill, error) {
	env, err := p.do(ctx, http.MethodGet, "/v1/bill/live", nil, nil)
	if KindOf(err) == KindEmpty {
		return Bill{}, nil
	}
	if err != nil {
		return Bill{}, err
	}
	r, err := one[struct {
		Currency string `json:"currency"`
		Price    int64  `json:"price"`
		Start    string `json:"start_date"`
		End      string `json:"end_date"`
	}](env)
	if err != nil {
		return Bill{}, err
	}
	if r.Currency != "" && r.Currency != "KRW" {
		return Bill{}, &Error{Kind: KindProtocol}
	}
	return Bill{From: r.Start, To: r.End, KRW: r.Price}, nil
}

func anyString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}
