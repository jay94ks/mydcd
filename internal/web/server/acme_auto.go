// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/acme"
	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Automatic issuance (UI-57 "자동 발급", web-own). Every minute the
// incident watcher's automation session reads the REQ-22 mapping: each
// route host on an instance with a :443 listener that no certificate store
// entry covers (exact SAN, or a "*." SAN one label up) is a watched host.
// When its external domain has automatic issuance on, the web app makes an
// ACME definition for it and starts an order as the automation account
// (the order's put-certificate is signed by that account; mydcd decides if
// it may). REQ-21's "certificate: auto" then picks the new store version
// without a redeploy. Hosts that cannot be issued wait in a list kept in
// memory (the mapping is mydcd's and read each round).

const acmeAutoEvery = time.Minute

// acmeAutoPerRound caps new definitions (and orders) per round, for the
// CA's request limits; the rest are picked up in later rounds.
var acmeAutoPerRound = 3

type acmeAutoWaiting struct {
	Host     string    `json:"host"`
	Reason   string    `json:"reason"` // no-domain, not-assigned, auto-off, caa-blocked, rate-limit
	Tenant   string    `json:"tenant,omitempty"`
	App      string    `json:"app,omitempty"`
	Node     string    `json:"node"`
	Listen   string    `json:"listen"`
	Since    time.Time `json:"since"`
	notified bool
}

type acmeAutoState struct {
	mu      sync.Mutex
	polled  time.Time
	waiting map[string]*acmeAutoWaiting
	tenants map[string][]string // domain → tenants with watched hosts under it
}

type acmeAutoDomainView struct {
	Domain   string   `json:"domain"`
	Enabled  bool     `json:"enabled"`
	Mode     string   `json:"mode"`
	KeyTypes []string `json:"keyTypes,omitempty"`
	Tenants  []string `json:"tenants"`
}

// acmeAutoActive: some domain has automatic issuance on (the watcher then
// keeps reading even with incident response off).
func (s *Server) acmeAutoActive() bool {
	a, err := s.opt.Store.GetACMEAuto()
	if err != nil || a.Revision == 0 {
		return false
	}
	ds, _ := s.opt.Store.ListDNSDomains()
	for _, d := range ds {
		if acmeAutoDomainOf(a, d.Domain).Enabled {
			return true
		}
	}
	return false
}

func acmeAutoDomainOf(a *store.ACMEAuto, domain string) store.ACMEAutoDomain {
	if d := a.Domains[domain]; d != nil {
		return *d
	}
	return store.ACMEAutoDomain{Enabled: a.Enabled, Mode: "per-host"}
}

func (s *Server) acmeAutoView() (map[string]any, error) {
	a, err := s.opt.Store.GetACMEAuto()
	if err != nil {
		return nil, err
	}
	ds, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		return nil, err
	}
	st := &s.acmeAuto
	st.mu.Lock()
	defer st.mu.Unlock()
	domains := []acmeAutoDomainView{}
	for _, d := range ds {
		x := acmeAutoDomainOf(a, d.Domain)
		v := acmeAutoDomainView{Domain: d.Domain, Enabled: x.Enabled, Mode: x.Mode, KeyTypes: x.KeyTypes, Tenants: []string{}}
		// the domain's tenant assignments, then tenants seen using it
		for _, as := range d.Assignments {
			if !slices.Contains(v.Tenants, as.Tenant) {
				v.Tenants = append(v.Tenants, as.Tenant)
			}
		}
		for _, t := range st.tenants[d.Domain] {
			if !slices.Contains(v.Tenants, t) {
				v.Tenants = append(v.Tenants, t)
			}
		}
		domains = append(domains, v)
	}
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })
	waiting := []*acmeAutoWaiting{}
	for _, w := range st.waiting {
		if _, ign := a.Ignored[w.Host]; !ign {
			waiting = append(waiting, w)
		}
	}
	sort.Slice(waiting, func(i, j int) bool { return waiting[i].Host < waiting[j].Host })
	kts := a.KeyTypes
	if len(kts) == 0 {
		for _, k := range acme.DefaultKeyTypes {
			kts = append(kts, string(k))
		}
	}
	out := map[string]any{"enabled": a.Enabled, "keyTypes": kts, "dualRsa": a.DualRSA, "notifyAfterMinutes": a.NotifyAfterMinutes,
		"domains": domains, "waiting": waiting, "revision": a.Revision}
	if a.Account != "" {
		out["account"] = a.Account
	}
	return out, nil
}

// GET /acme/auto
func (s *Server) handleACMEAuto(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	out, err := s.acmeAutoView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// PUT /acme/auto {enabled, account?, keyTypes, dualRsa, notifyAfterMinutes, domains, revision}
func (s *Server) handlePutACMEAuto(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Enabled            bool     `json:"enabled"`
		Account            string   `json:"account,omitempty"`
		KeyTypes           []string `json:"keyTypes"`
		DualRSA            bool     `json:"dualRsa"`
		NotifyAfterMinutes int      `json:"notifyAfterMinutes"`
		Domains            []struct {
			Domain   string   `json:"domain"`
			Enabled  bool     `json:"enabled"`
			Mode     string   `json:"mode"`
			KeyTypes []string `json:"keyTypes,omitempty"`
			Tenants  []string `json:"tenants,omitempty"` // shown only; assignments are the domain's
		} `json:"domains"`
		Revision uint64 `json:"revision"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	bad := func(msg string) { writeError(w, http.StatusUnprocessableEntity, "invalid", msg) }
	if err := checkKeyTypes(req.KeyTypes); err != nil {
		bad("keyTypes: " + err.Error())
		return
	}
	if req.Account != "" {
		if _, err := s.opt.Store.GetACMEAccount(req.Account); err != nil {
			bad("account: no such account")
			return
		}
	} else if req.Enabled {
		bad("account: needed to turn automatic issuance on")
		return
	}
	if req.NotifyAfterMinutes < 1 || req.NotifyAfterMinutes > 24*60 {
		bad("notifyAfterMinutes: 1..1440")
		return
	}
	ds, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	known := map[string]bool{}
	for _, d := range ds {
		known[d.Domain] = true
	}
	domains := map[string]*store.ACMEAutoDomain{}
	for _, d := range req.Domains {
		if !known[d.Domain] || domains[d.Domain] != nil {
			bad("domains: unknown or repeated external domain " + d.Domain)
			return
		}
		if d.Mode != "per-host" && d.Mode != "wildcard" {
			bad("domains[].mode: per-host or wildcard")
			return
		}
		if len(d.KeyTypes) > 0 {
			if err := checkKeyTypes(d.KeyTypes); err != nil {
				bad("domains[].keyTypes: " + err.Error())
				return
			}
		}
		if d.Enabled && req.Account == "" {
			bad("account: needed to turn automatic issuance on")
			return
		}
		domains[d.Domain] = &store.ACMEAutoDomain{Enabled: d.Enabled, Mode: d.Mode, KeyTypes: d.KeyTypes}
	}
	_, err = s.opt.Store.UpdateACMEAuto(req.Revision, func(a *store.ACMEAuto) error {
		a.Enabled, a.Account, a.KeyTypes, a.DualRSA, a.NotifyAfterMinutes = req.Enabled, req.Account, req.KeyTypes, req.DualRSA, req.NotifyAfterMinutes
		a.Domains, a.UpdatedBy, a.UpdatedAt = domains, ws.user.ID, s.now()
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "stale", "the settings changed; reload them")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "acme", "set-auto", "settings", nil, map[string]any{"enabled": req.Enabled, "account": req.Account, "domains": domains})
	s.handleACMEAuto(w, r, ws)
}

// POST /acme/auto/ignore {host}: stop watching a waiting host.
func (s *Server) handleACMEAutoIgnore(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Host string `json:"host"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	host := strings.ToLower(req.Host)
	s.acmeAuto.mu.Lock()
	_, ok := s.acmeAuto.waiting[host]
	s.acmeAuto.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "not-found", "the host is not waiting")
		return
	}
	a, err := s.opt.Store.GetACMEAuto()
	if err == nil {
		_, err = s.opt.Store.UpdateACMEAuto(a.Revision, func(a *store.ACMEAuto) error {
			a.Ignored[host] = s.now()
			return nil
		})
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.acmeAuto.mu.Lock()
	delete(s.acmeAuto.waiting, host)
	s.acmeAuto.mu.Unlock()
	s.audit(ws, "", "acme", "ignore-auto-host", host, nil, nil)
	s.handleACMEAuto(w, r, ws)
}

// certCovers: a store SAN (or definition name) covers host.
func certCovers(san, host string) bool {
	if san == host {
		return true
	}
	if base, ok := strings.CutPrefix(san, "*."); ok {
		if i := strings.IndexByte(host, '.'); i > 0 && host[i+1:] == base {
			return true
		}
	}
	return false
}

type watchedHost struct {
	host, tenant, app, node, listen string
}

// acmeWatchedHosts: route hosts of mappings with a :443 listener.
func acmeWatchedHosts(v *ingressView) []watchedHost {
	seen := map[string]bool{}
	var out []watchedHost
	for _, m := range v.Mappings {
		listen := ""
		if m.Runtime != nil {
			for _, l := range m.Runtime.Listeners {
				if listenerPort(l.Address) == 443 {
					listen = l.Address
					break
				}
			}
		}
		if listen == "" {
			continue
		}
		for _, rt := range m.Spec.Routes {
			h := strings.ToLower(strings.TrimSuffix(rt.Host, "."))
			if h == "" || strings.Contains(h, "*") || seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, watchedHost{h, m.Tenant, m.App, m.Node, listen})
		}
	}
	return out
}

// acmeAutoName is a free definition name for names[0].
func acmeAutoName(first string, taken func(string) bool) string {
	base := strings.ReplaceAll(strings.TrimPrefix(first, "*."), ".", "-")
	if strings.HasPrefix(first, "*.") {
		base = "wild-" + base
	}
	base = strings.Trim(base, "-")
	if len(base) > 56 {
		base = strings.TrimRight(base[:56], "-")
	}
	name := base
	for i := 2; taken(name); i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

// acmeAutoPoll runs one scan as ws (the watcher's automation session).
func (s *Server) acmeAutoPoll(ctx context.Context, ws *webSession) {
	st := &s.acmeAuto
	now := s.now()
	st.mu.Lock()
	due := now.Sub(st.polled) >= acmeAutoEvery
	if due {
		st.polled = now
	}
	st.mu.Unlock()
	if !due {
		return
	}
	a, err := s.opt.Store.GetACMEAuto()
	if err != nil || a.Revision == 0 {
		return
	}
	var iv *ingressView
	var certs []certstore.PublicEntry
	err = ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if iv, err = ingressRead(ctx, c, control.IngressQuery{}); err != nil {
			return err
		}
		certs, err = certAll(ctx, c)
		return err
	})
	if err != nil {
		s.log.Warn("acme auto: read", "err", err)
		return
	}
	defs, err := s.opt.Store.ListACMECerts()
	if err != nil {
		return
	}
	s.acmeAutoScan(a, acmeWatchedHosts(iv), certs, defs, now)
}

func (s *Server) acmeAutoScan(a *store.ACMEAuto, hosts []watchedHost, certs []certstore.PublicEntry, defs []*store.ACMECert, now time.Time) {
	stored := func(h string) bool {
		for _, c := range certs {
			if c.Metadata.NotAfter <= now.Unix() {
				continue
			}
			for _, name := range c.Metadata.Hosts {
				if certCovers(name, h) {
					return true
				}
			}
		}
		return false
	}
	defFor := func(h string) *store.ACMECert {
		for _, d := range defs {
			for _, n := range d.Names {
				if certCovers(n, h) {
					return d
				}
			}
		}
		return nil
	}
	taken := func(name string) bool {
		return slices.ContainsFunc(defs, func(d *store.ACMECert) bool { return d.Name == name })
	}

	waiting := map[string]*acmeAutoWaiting{}
	tenants := map[string][]string{}
	st := &s.acmeAuto
	st.mu.Lock()
	old := st.waiting
	st.mu.Unlock()
	wait := func(h watchedHost, reason string) {
		w := &acmeAutoWaiting{Host: h.host, Reason: reason, Tenant: h.tenant, App: h.app, Node: h.node, Listen: h.listen, Since: now}
		if o := old[h.host]; o != nil && o.Reason == reason {
			w.Since, w.notified = o.Since, o.notified
		}
		waiting[h.host] = w
	}
	made := 0
	for _, h := range hosts {
		if _, ign := a.Ignored[h.host]; ign || stored(h.host) {
			continue
		}
		dom, _, rel, derr := s.dnsFor(h.host)
		if dom != nil && h.tenant != "" && !slices.Contains(tenants[dom.Domain], h.tenant) {
			tenants[dom.Domain] = append(tenants[dom.Domain], h.tenant)
		}
		if d := defFor(h.host); d != nil {
			// A definition covers it: its order is running or waits for
			// its retry; only reasons a retry cannot fix are listed.
			if orders, _ := s.opt.Store.ListACMEOrders(d.Name, 1); len(orders) > 0 && orders[0].State == "failed" {
				switch orders[0].ErrorCode {
				case "caa-blocked", "rate-limit":
					wait(h, orders[0].ErrorCode)
				}
			}
			continue
		}
		if derr != nil || dom == nil {
			wait(h, "no-domain")
			continue
		}
		// The workspace that serves the host must hold the name in the
		// domain's assignments (the same rule as its DNS records).
		if h.tenant != "" && !slices.ContainsFunc(dom.Assignments, func(as store.DNSAssignment) bool {
			return as.Tenant == h.tenant && dns.InRange(rel, as.Names)
		}) {
			wait(h, "not-assigned")
			continue
		}
		ds := acmeAutoDomainOf(a, dom.Domain)
		if !ds.Enabled || a.Account == "" {
			wait(h, "auto-off")
			continue
		}
		if made >= acmeAutoPerRound {
			continue
		}
		made++
		names := []string{h.host}
		if ds.Mode == "wildcard" {
			if i := strings.IndexByte(h.host, '.'); i > 0 && h.host[i+1:] == dom.Domain {
				names = []string{"*." + dom.Domain}
			}
		}
		kts := ds.KeyTypes
		if len(kts) == 0 {
			kts = a.KeyTypes
		}
		c := &store.ACMECert{Name: acmeAutoName(names[0], taken), Names: names, Account: a.Account, KeyTypes: kts, AutoRenew: true,
			OwnerID: a.UpdatedBy, CreatedBy: "자동 발급", CreatedAt: now, AutoIssued: &store.ACMEAutoIssued{Host: h.host, DetectedAt: now}}
		if err := s.opt.Store.CreateACMECert(c); err != nil {
			s.log.Error("acme auto: definition", "host", h.host, "err", err)
			continue
		}
		defs = append(defs, c)
		if _, err := s.startOrder(c, "auto-"+newOpID(), nil); err != nil && !errors.Is(err, errOrderRunning) {
			s.log.Error("acme auto: order", "cert", c.Name, "err", err)
		}
	}
	for _, w := range waiting {
		if !w.notified && a.UpdatedBy != "" && now.Sub(w.Since) >= time.Duration(a.NotifyAfterMinutes)*time.Minute {
			w.notified = true
			s.notify(&store.Notification{User: a.UpdatedBy, Kind: NotifyCertificate, Severity: "warning", Action: true, Tenant: w.Tenant,
				Title: "인증서 자동 발급 대기: " + w.Host, Body: acmeAutoReasonText[w.Reason], Link: "/certificates"})
		}
	}
	st.mu.Lock()
	st.waiting, st.tenants = waiting, tenants
	st.mu.Unlock()
}

var acmeAutoReasonText = map[string]string{
	"no-domain":    "외부 도메인에 없는 이름이라 DNS 확인을 할 수 없습니다.",
	"not-assigned": "이 호스트를 쓰는 작업 공간에 그 이름이 배정되지 않았습니다.",
	"auto-off":     "이 도메인은 자동 발급이 꺼져 있습니다.",
	"caa-blocked":  "CAA 레코드가 이 인증 기관을 막습니다.",
	"rate-limit":   "인증 기관 요청 수 한도에 닿았습니다.",
}
