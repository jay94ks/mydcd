// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/jay94ks/mydcd/internal/web/provlog"
)

// Hostinger DNS adapter. Paths and fields follow the Hostinger API OpenAPI
// 3.9.2 (developers.hostinger.com/openapi/openapi.json):
//
//	GET    /api/domains/v1/portfolio                list domains
//	GET    /api/domains/v1/portfolio/{domain}       name servers of one domain
//	GET    /api/dns/v1/zones/{domain}               records
//	PUT    /api/dns/v1/zones/{domain}               upsert (overwrite=true replaces matching name+type)
//	DELETE /api/dns/v1/zones/{domain}               delete by name+type filters
//	POST   /api/dns/v1/zones/{domain}/validate      check an upsert
//	GET    /api/dns/v1/snapshots/{domain}           snapshots
//	POST   /api/dns/v1/snapshots/{domain}/{id}/restore
//
// It has not been run against a real account; the provider diagnostic log
// records every call so the first real run can be checked.

// HostingerBaseURL is the API address.
const HostingerBaseURL = "https://developers.hostinger.com"

var hostingerCaps = Capabilities{RecordTypes: []string{"A", "AAAA", "CNAME", "TXT", "MX", "CAA", "SRV", "NS"}, Wildcard: true, MinTTL: 60,
	Validate: true, Snapshots: true, Propagation: true, RateLimit: Rate{Requests: 90, Per: time.Minute}}

// HostingerVendor is the Hostinger adapter.
func HostingerVendor() Vendor {
	info := ProviderInfo{ID: "hostinger", Name: "Hostinger", TokenURL: "https://hpanel.hostinger.com/profile/api", Ready: true}
	return Vendor{Info: info, Capabilities: hostingerCaps, New: func(token string, env Env) Provider {
		base := strings.TrimRight(env.BaseURL, "/")
		if base == "" {
			base = HostingerBaseURL
		}
		tr := provlog.Transport(env.Transport, env.Log, provlog.Source{Provider: "dns:hostinger", Conn: env.Conn, Classify: func(status int, _ []byte) string {
			return string(hostingerKind(status))
		}})
		return &hostinger{info: info, token: token, base: base, http: &http.Client{Transport: tr, Timeout: 30 * time.Second}, lim: hostingerLimiter(token), log: env.Log, conn: env.Conn}
	}}
}

type hostinger struct {
	info  ProviderInfo
	token string
	base  string
	http  *http.Client
	lim   *rate.Limiter
	log   *provlog.Log
	conn  string
}

// The API allows 90 requests a minute per token. Providers are opened per
// request, so the limiter lives per token hash.
// An entry unused for an hour is dropped (a replaced token's limiter
// would otherwise stay forever).
var (
	hostingerLimMu sync.Mutex
	hostingerLims  = map[[32]byte]*hostingerLim{}
)

type hostingerLim struct {
	l    *rate.Limiter
	used time.Time
}

func hostingerLimiter(token string) *rate.Limiter {
	k := sha256.Sum256([]byte(token))
	now := time.Now()
	hostingerLimMu.Lock()
	defer hostingerLimMu.Unlock()
	for key, e := range hostingerLims {
		if now.Sub(e.used) > time.Hour {
			delete(hostingerLims, key)
		}
	}
	e := hostingerLims[k]
	if e == nil {
		e = &hostingerLim{l: rate.NewLimiter(rate.Every(time.Minute/80), 10)} // a little under 90/min
		hostingerLims[k] = e
	}
	e.used = now
	return e.l
}

func (h *hostinger) Info() ProviderInfo         { return h.info }
func (h *hostinger) Capabilities() Capabilities { return hostingerCaps }

func hostingerKind(status int) Kind {
	switch {
	case status == http.StatusUnauthorized:
		return AuthFailed
	case status == http.StatusForbidden:
		return Forbidden
	case status == http.StatusNotFound:
		return NotFound
	case status == http.StatusConflict:
		return Conflict
	case status == http.StatusTooManyRequests:
		return RateLimited
	case status == http.StatusUnprocessableEntity || status == http.StatusBadRequest:
		return Invalid
	}
	return Unavailable
}

type hostingerError struct {
	Message       string              `json:"message"`
	CorrelationID string              `json:"correlation_id"`
	Errors        map[string][]string `json:"errors"`
}

// call sends one request (retrying once after a 429 whose Retry-After is
// at most a minute) and decodes a 2xx JSON body into out.
func (h *hostinger) call(ctx context.Context, op, method, path string, in, out any) error {
	ctx = provlog.WithOp(ctx, op)
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		if err := h.lim.Wait(ctx); err != nil {
			return &Error{Kind: Unavailable, Detail: err.Error()}
		}
		req, err := http.NewRequestWithContext(ctx, method, h.base+path, bytes.NewReader(body))
		if err != nil {
			return err
		}
		if in == nil {
			req.Body, req.GetBody, req.ContentLength = nil, nil, 0
		} else {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+h.token)
		resp, err := h.http.Do(req)
		if err != nil {
			return &Error{Kind: Unavailable, Detail: "hostinger: " + err.Error()}
		}
		raw, rerr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp.Header.Get("Retry-After"))
			if attempt == 0 && wait <= time.Minute {
				select {
				case <-ctx.Done():
					return &Error{Kind: RateLimited, Detail: "hostinger: rate limited", RetryAfter: wait}
				case <-time.After(wait):
				}
				continue
			}
			return &Error{Kind: RateLimited, Detail: "hostinger: rate limited", RetryAfter: wait}
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return hostingerErr(resp.StatusCode, raw)
		}
		if rerr != nil {
			return &Error{Kind: Unavailable, Detail: "hostinger: " + rerr.Error()}
		}
		if out != nil {
			if err := json.Unmarshal(raw, out); err != nil {
				return &Error{Kind: Unavailable, Detail: fmt.Sprintf("hostinger: unexpected %s response: %v", op, err)}
			}
		}
		return nil
	}
}

func hostingerErr(status int, raw []byte) *Error {
	var he hostingerError
	_ = json.Unmarshal(raw, &he)
	d := he.Message
	if d == "" {
		d = http.StatusText(status)
	}
	if len(he.Errors) > 0 {
		var fields []string
		for f, msgs := range he.Errors {
			fields = append(fields, f+": "+strings.Join(msgs, " "))
		}
		sort.Strings(fields)
		d += " (" + strings.Join(fields, "; ") + ")"
	}
	if he.CorrelationID != "" {
		d += " [correlation " + he.CorrelationID + "]"
	}
	return &Error{Kind: hostingerKind(status), Detail: "hostinger " + strconv.Itoa(status) + ": " + d}
}

func retryAfter(v string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(0, time.Until(t))
	}
	return 10 * time.Second
}

type hostingerDomain struct {
	ID     int    `json:"id"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

func (h *hostinger) portfolio(ctx context.Context, op string) ([]hostingerDomain, error) {
	var ds []hostingerDomain
	if err := h.call(ctx, op, http.MethodGet, "/api/domains/v1/portfolio", nil, &ds); err != nil {
		return nil, err
	}
	return ds, nil
}

// Check lists the account's domains (Hostinger has no token info call).
func (h *hostinger) Check(ctx context.Context) (Account, error) {
	ds, err := h.portfolio(ctx, "Check")
	if err != nil {
		return Account{}, err
	}
	rem := -1
	if t := h.lim.Tokens(); t >= 0 {
		rem = int(t)
	}
	return Account{Name: "Hostinger", Scope: "the token owner's domains", Domains: len(ds), Remaining: rem}, nil
}

var hostingerNS = regexp.MustCompile(`(?i)(^|\.)(dns-parking\.com|hostinger\.[a-z.]+)\.?$`)

// ListDomains lists the account's domains. A domain has its zone here when
// it is active and its name servers are Hostinger's (dns-parking.com).
func (h *hostinger) ListDomains(ctx context.Context) ([]Domain, error) {
	ds, err := h.portfolio(ctx, "ListDomains")
	if err != nil {
		return nil, err
	}
	var out []Domain
	for _, d := range ds {
		if d.Domain == "" {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(d.Domain, "."))
		dom := Domain{Name: name}
		if d.Status == "active" {
			var det struct {
				NameServers map[string]string `json:"name_servers"`
			}
			if err := h.call(ctx, "DomainNameServers", http.MethodGet, "/api/domains/v1/portfolio/"+url.PathEscape(name), nil, &det); err != nil {
				return nil, err
			}
			dom.HasZone = len(det.NameServers) > 0
			var ns []string
			for _, v := range det.NameServers {
				if v == "" {
					continue
				}
				ns = append(ns, v)
				if !hostingerNS.MatchString(v) {
					dom.HasZone = false
				}
			}
			sort.Strings(ns)
			h.log.Add(provlog.Entry{Provider: "dns:hostinger", Conn: h.conn, Op: "ListDomains", Msg: "zone check",
				Attrs: map[string]string{"domain": name, "status": d.Status, "nameservers": strings.Join(ns, ","), "hasZone": strconv.FormatBool(dom.HasZone)}})
		}
		out = append(out, dom)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type hostingerRecord struct {
	Content    string `json:"content"`
	IsDisabled bool   `json:"is_disabled,omitempty"`
}

type hostingerSet struct {
	Name    string            `json:"name"`
	Records []hostingerRecord `json:"records"`
	TTL     int               `json:"ttl,omitempty"`
	Type    string            `json:"type"`
}

func zonePath(domain string) string { return "/api/dns/v1/zones/" + url.PathEscape(domain) }

// GetZone reads the records. Disabled records are left out (they are not
// served). MX and SRV priorities are the first field of the content.
func (h *hostinger) GetZone(ctx context.Context, domain string) (Zone, error) {
	var sets []hostingerSet
	if err := h.call(ctx, "GetZone", http.MethodGet, zonePath(domain), nil, &sets); err != nil {
		return Zone{}, err
	}
	z := Zone{Domain: domain}
	for _, hs := range sets {
		set := RRSet{Name: relName(hs.Name, domain), Type: strings.ToUpper(hs.Type), TTL: hs.TTL}
		for _, r := range hs.Records {
			if r.IsDisabled {
				continue
			}
			set.Records = append(set.Records, fromHostinger(set.Type, r.Content))
		}
		if len(set.Records) > 0 {
			z.Sets = append(z.Sets, set)
		}
	}
	sort.Slice(z.Sets, func(i, j int) bool {
		if z.Sets[i].Name != z.Sets[j].Name {
			return z.Sets[i].Name < z.Sets[j].Name
		}
		return z.Sets[i].Type < z.Sets[j].Type
	})
	return z, nil
}

// relName makes a returned name zone-relative ("@" for the apex) in case
// the API gives a full name.
func relName(n, domain string) string {
	n = strings.ToLower(strings.TrimSuffix(n, "."))
	switch {
	case n == "" || n == "@" || n == domain:
		return "@"
	case strings.HasSuffix(n, "."+domain):
		return strings.TrimSuffix(n, "."+domain)
	}
	return n
}

func fromHostinger(typ, content string) Record {
	switch typ {
	case "MX", "SRV":
		if f, rest, ok := strings.Cut(strings.TrimSpace(content), " "); ok {
			if p, err := strconv.Atoi(f); err == nil {
				return Record{Content: strings.TrimSpace(rest), Priority: p}
			}
		}
	case "TXT":
		// one pair of surrounding quotes, if the API returns them
		if len(content) >= 2 && content[0] == '"' && content[len(content)-1] == '"' && !strings.Contains(content[1:len(content)-1], `" "`) {
			return Record{Content: content[1 : len(content)-1]}
		}
	}
	return Record{Content: content}
}

func toHostinger(typ string, r Record) hostingerRecord {
	if typ == "MX" || typ == "SRV" {
		return hostingerRecord{Content: strconv.Itoa(r.Priority) + " " + r.Content}
	}
	return hostingerRecord{Content: r.Content}
}

type hostingerUpdate struct {
	Overwrite bool           `json:"overwrite"`
	Zone      []hostingerSet `json:"zone"`
}

func upsertBody(c ChangeSet) hostingerUpdate {
	u := hostingerUpdate{Overwrite: true, Zone: []hostingerSet{}}
	for _, s := range c.Upsert {
		hs := hostingerSet{Name: s.Name, Type: s.Type, TTL: s.TTL}
		for _, r := range s.Records {
			hs.Records = append(hs.Records, toHostinger(s.Type, r))
		}
		u.Zone = append(u.Zone, hs)
	}
	return u
}

// Validate asks Hostinger to check the upserts (a 422 lists the problems).
// Deletes are not checked.
func (h *hostinger) Validate(ctx context.Context, domain string, c ChangeSet) ([]Problem, error) {
	if len(c.Upsert) == 0 {
		return nil, nil
	}
	err := h.call(ctx, "Validate", http.MethodPost, zonePath(domain)+"/validate", upsertBody(c), nil)
	if err == nil {
		return nil, nil
	}
	e, ok := err.(*Error)
	if !ok || e.Kind != Invalid {
		return nil, err
	}
	return []Problem{{Name: "", Type: "", Message: strings.TrimPrefix(e.Detail, "hostinger 422: ")}}, nil
}

// Apply deletes, then upserts with overwrite (each listed name+type is
// replaced). Hostinger takes a snapshot of the zone on each change; the
// newest one made since the call started is returned.
func (h *hostinger) Apply(ctx context.Context, domain string, c ChangeSet) (ApplyResult, error) {
	start := time.Now().Add(-5 * time.Second)
	if len(c.Delete) > 0 {
		type filter struct {
			Name string `json:"name"`
			Type string `json:"type"`
		}
		var body struct {
			Filters []filter `json:"filters"`
		}
		for _, k := range c.Delete {
			body.Filters = append(body.Filters, filter{k.Name, k.Type})
		}
		if err := h.call(ctx, "Apply.Delete", http.MethodDelete, zonePath(domain), body, nil); err != nil {
			return ApplyResult{}, err
		}
	}
	if len(c.Upsert) > 0 {
		if err := h.call(ctx, "Apply.Upsert", http.MethodPut, zonePath(domain), upsertBody(c), nil); err != nil {
			return ApplyResult{}, err
		}
	}
	var res ApplyResult
	// the snapshot is a convenience: a failure to list it is only logged
	if ss, err := h.ListSnapshots(ctx, domain); err == nil {
		for _, s := range ss {
			if !s.CreatedAt.Before(start) {
				res.Snapshot = s.ID
				break
			}
		}
	}
	return res, nil
}

type hostingerSnapshot struct {
	ID        int64  `json:"id"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
}

// ListSnapshots lists the zone's snapshots, newest first.
func (h *hostinger) ListSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	var ss []hostingerSnapshot
	if err := h.call(ctx, "ListSnapshots", http.MethodGet, "/api/dns/v1/snapshots/"+url.PathEscape(domain), nil, &ss); err != nil {
		return nil, err
	}
	out := make([]Snapshot, 0, len(ss))
	for _, s := range ss {
		t, _ := time.Parse(time.RFC3339, s.CreatedAt)
		out = append(out, Snapshot{ID: strconv.FormatInt(s.ID, 10), CreatedAt: t, Reason: s.Reason})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// RestoreSnapshot restores a snapshot.
func (h *hostinger) RestoreSnapshot(ctx context.Context, domain, id string) error {
	if _, err := strconv.ParseInt(id, 10, 64); err != nil {
		return &Error{Kind: Invalid, Detail: "snapshot id must be a number"}
	}
	return h.call(ctx, "RestoreSnapshot", http.MethodPost, "/api/dns/v1/snapshots/"+url.PathEscape(domain)+"/"+id+"/restore", nil, nil)
}
