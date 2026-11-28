// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Hostinger adapter, an Owned vendor (devel/design/vps-hostinger.md, Jay
// 2026-11-28 14:02–14:23 KST). The operator buys and keeps the VPS in
// hPanel; sfcd only attaches existing ones. Paths and fields follow the
// public Hostinger OpenAPI 5.1.0 (github.com/hostinger/api):
//
//	GET  /api/vps/v1/virtual-machines            account check, list
//	GET  /api/vps/v1/virtual-machines/{id}       read
//	POST /api/vps/v1/virtual-machines/{id}/stop | /start   power
//	POST /api/vps/v1/virtual-machines/{id}/ssh-keys        SSH install path
//	GET  /api/vps/v1/virtual-machines/{id}/metrics         traffic
//	GET  /api/billing/v1/subscriptions           remaining period (read only)
//
// Nothing else is ever sent: hostingerAllowed is checked before every
// request, so a purchase, rebuild (recreate), backup restore, renewal,
// auto-renewal change, payment-method or firewall change cannot leave this
// adapter. Auth is one bearer token. It has not been run against a real
// account yet.

// HostingerBaseURL is the production address.
const HostingerBaseURL = "https://developers.hostinger.com"

// HostingerVendor is the Hostinger adapter. It is not in Vendors() until
// the owned-VPS book and its own API exist, so its accounts never show up
// next to Managed ones.
func HostingerVendor() Vendor {
	// The help page counts traffic "between your server and the
	// internet" (both ways); confirm on a real account.
	return Vendor{ID: "hostinger", Name: "Hostinger", Ownership: Owned, TokenOnly: true, TrafficCounting: CountRXTX,
		NewOwned: func(c Credential, env Env) OwnedProvider {
			base := strings.TrimRight(env.BaseURL, "/")
			if base == "" {
				base = HostingerBaseURL
			}
			now := env.Now
			if now == nil {
				now = time.Now
			}
			return &hostinger{cred: c, base: base, now: now, http: &http.Client{Transport: env.Transport, Timeout: 30 * time.Second}}
		}}
}

// HostingerThrottleMbps is the speed Hostinger leaves a VPS at for the rest
// of the month once its monthly bandwidth is used up (help article, revised
// 2026-10-29). There is no overage charge.
const HostingerThrottleMbps = 10

type hostinger struct {
	cred Credential
	base string
	now  func() time.Time
	http *http.Client
}

func (*hostinger) Kind() string { return "hostinger" }

var hostingerAllowed = []struct {
	method string
	path   *regexp.Regexp
}{
	{http.MethodGet, regexp.MustCompile(`^/api/vps/v1/virtual-machines$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/vps/v1/virtual-machines/[0-9]+$`)},
	{http.MethodPost, regexp.MustCompile(`^/api/vps/v1/virtual-machines/[0-9]+/(stop|start|ssh-keys)$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/vps/v1/virtual-machines/[0-9]+/metrics$`)},
	{http.MethodGet, regexp.MustCompile(`^/api/billing/v1/subscriptions$`)},
}

func hostingerAllows(method, path string) bool {
	for _, a := range hostingerAllowed {
		if a.method == method && a.path.MatchString(path) {
			return true
		}
	}
	return false
}

var hostingerID = regexp.MustCompile(`^[0-9]{1,19}$`)

func (p *hostinger) vmPath(id, suffix string) (string, error) {
	if !hostingerID.MatchString(id) {
		return "", &Error{Kind: KindInvalid, Code: "INSTANCE_ID"}
	}
	return "/api/vps/v1/virtual-machines/" + id + suffix, nil
}

// do sends one request and decodes a 2xx body into out (nil = ignore). A
// 429 is retried once after Retry-After (at most 10 s).
func (p *hostinger) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	if !p.cred.Valid() || p.cred.SecretKey != "" {
		return &Error{Kind: KindAuth, Code: "CREDENTIAL"}
	}
	if !hostingerAllows(method, path) {
		return &Error{Kind: KindInvalid, Code: "NOT_ALLOWED"}
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return &Error{Kind: KindInvalid}
		}
	}
	u := p.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(payload))
		if err != nil {
			return &Error{Kind: KindTransport}
		}
		req.Header.Set("Authorization", "Bearer "+p.cred.AccessKey)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		res, err := p.http.Do(req)
		if err != nil {
			return &Error{Kind: KindTransport}
		}
		data, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
		res.Body.Close()
		if err != nil {
			return &Error{Kind: KindTransport}
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			wait := 2 * time.Second
			if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s >= 0 {
				wait = min(time.Duration(s)*time.Second, 10*time.Second)
			}
			select {
			case <-ctx.Done():
				return &Error{Kind: KindTransport}
			case <-time.After(wait):
			}
			continue
		}
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return hostingerError(res.StatusCode, data)
		}
		if out == nil {
			return nil
		}
		if json.Unmarshal(data, out) != nil {
			return &Error{Kind: KindProtocol}
		}
		return nil
	}
}

// hostingerError maps a refusal to a Kind. Only field names are kept from
// the body, never messages.
func hostingerError(status int, data []byte) error {
	e := &Error{Code: strconv.Itoa(status)}
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		e.Kind = KindAuth
	case status == http.StatusNotFound:
		e.Kind = KindNotFound
	case status == http.StatusConflict || status == http.StatusLocked:
		e.Kind = KindBusy
	case status == http.StatusUnprocessableEntity || status == http.StatusBadRequest:
		e.Kind = KindInvalid
		var body struct {
			Errors map[string]json.RawMessage `json:"errors"`
		}
		if json.Unmarshal(data, &body) == nil {
			for k := range body.Errors {
				if len(k) <= 64 {
					e.Fields = append(e.Fields, k)
				}
			}
			sort.Strings(e.Fields)
		}
	case status == http.StatusTooManyRequests:
		e.Kind = KindLimit
	case status >= 500:
		e.Kind = KindTransport
	default:
		e.Kind = KindProtocol
	}
	return e
}

func (p *hostinger) Check(ctx context.Context) (Account, error) {
	var vms []json.RawMessage
	if err := p.do(ctx, http.MethodGet, "/api/vps/v1/virtual-machines", nil, nil, &vms); err != nil {
		return Account{}, err
	}
	// The API has no account name; show the token's last four characters.
	k := p.cred.AccessKey
	return Account{Name: "token …" + k[max(0, len(k)-4):]}, nil
}

type hostingerIP struct {
	Address string `json:"address"`
}

type hostingerVM struct {
	ID             int64           `json:"id"`
	SubscriptionID string          `json:"subscription_id"`
	DataCenterID   int64           `json:"data_center_id"`
	Plan           string          `json:"plan"`
	Hostname       string          `json:"hostname"`
	State          string          `json:"state"`
	ActionsLock    string          `json:"actions_lock"`
	BandwidthMB    int64           `json:"bandwidth"`
	IPv4           json.RawMessage `json:"ipv4"`
	Template       *struct {
		Name string `json:"name"`
	} `json:"template"`
	CreatedAt string `json:"created_at"`
}

func hostingerStatus(state string) Status {
	switch state {
	case "creating", "initial":
		return StatusPending
	case "running":
		return StatusActive
	case "stopped":
		return StatusOff
	case "starting", "stopping", "recreating", "restoring", "recovery", "stopping_recovery", "suspending", "unsuspending":
		return StatusWorking
	}
	return StatusError // error, suspended, destroying, destroyed, unknown
}

// firstIPv4 reads ipv4 as the collection the schema names, or a single
// object, or a plain string.
func firstIPv4(raw json.RawMessage) string {
	var list []hostingerIP
	if json.Unmarshal(raw, &list) == nil {
		for _, a := range list {
			if a.Address != "" {
				return a.Address
			}
		}
		return ""
	}
	var one hostingerIP
	if json.Unmarshal(raw, &one) == nil && one.Address != "" {
		return one.Address
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func (v hostingerVM) instance() Instance {
	in := Instance{
		ID: strconv.FormatInt(v.ID, 10), Name: v.Hostname, Status: hostingerStatus(v.State),
		Zone: strconv.FormatInt(v.DataCenterID, 10), Flavor: v.Plan, PublicIPv4: firstIPv4(v.IPv4),
		SubscriptionID: v.SubscriptionID,
	}
	if v.ActionsLock == "locked" && in.Status == StatusActive {
		in.Status = StatusWorking
	}
	if v.BandwidthMB > 0 {
		in.IncludedGB, in.TrafficPeriod = v.BandwidthMB/1024, "MONTH"
	}
	if v.Template != nil {
		in.Image = v.Template.Name
	}
	if t, err := time.Parse(time.RFC3339Nano, v.CreatedAt); err == nil {
		in.Started = t
	}
	return in
}

func (p *hostinger) Instances(ctx context.Context) ([]Instance, error) {
	var vms []hostingerVM
	if err := p.do(ctx, http.MethodGet, "/api/vps/v1/virtual-machines", nil, nil, &vms); err != nil {
		return nil, err
	}
	out := make([]Instance, 0, len(vms))
	for _, v := range vms {
		out = append(out, v.instance())
	}
	return out, nil
}

func (p *hostinger) vm(ctx context.Context, id string) (hostingerVM, error) {
	path, err := p.vmPath(id, "")
	if err != nil {
		return hostingerVM{}, err
	}
	var v hostingerVM
	if err := p.do(ctx, http.MethodGet, path, nil, nil, &v); err != nil {
		return hostingerVM{}, err
	}
	if v.ID == 0 {
		return hostingerVM{}, &Error{Kind: KindProtocol}
	}
	return v, nil
}

func (p *hostinger) Instance(ctx context.Context, id string) (Instance, error) {
	v, err := p.vm(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	return v.instance(), nil
}

func (p *hostinger) power(ctx context.Context, id, action string) error {
	path, err := p.vmPath(id, "/"+action)
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, path, nil, nil, nil)
}

func (p *hostinger) Shutdown(ctx context.Context, id string) error { return p.power(ctx, id, "stop") }
func (p *hostinger) Start(ctx context.Context, id string) error    { return p.power(ctx, id, "start") }

func (p *hostinger) AttachSSHKey(ctx context.Context, id, publicKey string) error {
	publicKey = strings.TrimSpace(publicKey)
	if !strings.HasPrefix(publicKey, "ssh-ed25519 ") || len(publicKey) > 512 || strings.ContainsAny(publicKey, "\r\n") {
		return &Error{Kind: KindInvalid, Code: "SSH_KEY"}
	}
	path, err := p.vmPath(id, "/ssh-keys")
	if err != nil {
		return err
	}
	return p.do(ctx, http.MethodPost, path, nil, map[string][]string{"keys": {publicKey}}, nil)
}

type hostingerMetric struct {
	Usage map[string]float64 `json:"usage"`
}

// MonthTraffic adds outgoing and incoming bytes of the month (UTC) per day.
// MB is 10^6 bytes. The usage values are taken as the amount of each
// sample interval; confirm on a real account.
func (p *hostinger) MonthTraffic(ctx context.Context, id string, year, month int) (Traffic, error) {
	if month < 1 || month > 12 || year < 2000 || year > 9999 {
		return Traffic{}, &Error{Kind: KindInvalid}
	}
	path, err := p.vmPath(id, "/metrics")
	if err != nil {
		return Traffic{}, err
	}
	from := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 1, 0)
	if now := p.now().UTC(); now.Before(to) {
		to = now
	}
	q := url.Values{"date_from": {from.Format(time.RFC3339)}, "date_to": {to.Format(time.RFC3339)}}
	var m struct {
		Out *hostingerMetric `json:"outgoing_traffic"`
		In  *hostingerMetric `json:"incoming_traffic"`
	}
	if err := p.do(ctx, http.MethodGet, path, q, nil, &m); err != nil {
		return Traffic{}, err
	}
	bytesByDay := map[int]float64{}
	for _, metric := range []*hostingerMetric{m.Out, m.In} {
		if metric == nil {
			continue
		}
		for ts, v := range metric.Usage {
			sec, err := strconv.ParseInt(ts, 10, 64)
			if err != nil || v < 0 {
				continue
			}
			t := time.Unix(sec, 0).UTC()
			if t.Before(from) || !t.Before(from.AddDate(0, 1, 0)) {
				continue
			}
			bytesByDay[t.Day()] += v
		}
	}
	tr := Traffic{Year: year, Month: month, DailyMB: map[int]int64{}}
	if len(bytesByDay) == 0 {
		return tr, &Error{Kind: KindEmpty}
	}
	days := make([]int, 0, len(bytesByDay))
	var total float64
	for d, b := range bytesByDay {
		tr.DailyMB[d] = int64(b / 1e6)
		total += b
		days = append(days, d)
	}
	sort.Ints(days)
	tr.TotalMB = int64(total / 1e6)
	tr.First = from.AddDate(0, 0, days[0]-1).Format("2006-01-02")
	tr.Last = from.AddDate(0, 0, days[len(days)-1]-1).Format("2006-01-02")
	return tr, nil
}

type hostingerSubscription struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	CurrencyCode  string `json:"currency_code"`
	RenewalPrice  int64  `json:"renewal_price"`
	IsAutoRenewed bool   `json:"is_auto_renewed"`
	ExpiresAt     string `json:"expires_at"`
	NextBillingAt string `json:"next_billing_at"`
}

func parseHostingerTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// Subscription reads the billing period behind instance id. It only reads;
// renewal is done by the operator in the Hostinger panel (Jay 2026-11-28
// 14:22 KST).
func (p *hostinger) Subscription(ctx context.Context, id string) (Subscription, error) {
	v, err := p.vm(ctx, id)
	if err != nil {
		return Subscription{}, err
	}
	if v.SubscriptionID == "" {
		return Subscription{}, &Error{Kind: KindEmpty}
	}
	var subs []hostingerSubscription
	if err := p.do(ctx, http.MethodGet, "/api/billing/v1/subscriptions", nil, nil, &subs); err != nil {
		return Subscription{}, err
	}
	for _, s := range subs {
		if s.ID != v.SubscriptionID {
			continue
		}
		out := Subscription{ID: s.ID, Status: strings.ToLower(s.Status), AutoRenew: s.IsAutoRenewed,
			Currency: strings.ToUpper(s.CurrencyCode), RenewalCost: s.RenewalPrice, ExpiresAt: parseHostingerTime(s.ExpiresAt)}
		if s.IsAutoRenewed {
			out.NextBilling = parseHostingerTime(s.NextBillingAt)
		}
		return out, nil
	}
	return Subscription{}, &Error{Kind: KindNotFound, Code: "SUBSCRIPTION"}
}
