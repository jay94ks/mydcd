// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/seal"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// External DNS (UI-54~56, devel/design/web-dns-plan.md). The web app calls
// the DNS provider itself; mydcd is asked only who the user is and which
// workspaces they manage. Provider tokens live in sealed files.

func dnsSecretName(id string) string { return "dns-" + id }

func newProviderID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "p" + hex.EncodeToString(b)
}

// writeDNSError maps a provider error.
func writeDNSError(w http.ResponseWriter, err error) {
	var e *dns.Error
	if !errors.As(err, &e) {
		writeError(w, http.StatusBadGateway, "dns-unavailable", err.Error())
		return
	}
	status := map[dns.Kind]int{
		dns.AuthFailed: http.StatusBadGateway, dns.Forbidden: http.StatusBadGateway, dns.NotFound: http.StatusNotFound,
		dns.RateLimited: http.StatusTooManyRequests, dns.Invalid: http.StatusUnprocessableEntity, dns.Conflict: http.StatusConflict,
		dns.Unavailable: http.StatusBadGateway,
	}[e.Kind]
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", itoa(int(e.RetryAfter/time.Second)))
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": "dns-" + string(e.Kind), "message": "DNS provider: " + string(e.Kind), "detail": e.Detail}})
}

func itoa(n int) string { return strconv.Itoa(n) }

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// dnsAccess is what the caller may do in DNS.
type dnsAccess struct {
	admin   bool
	manages map[string]bool // workspaces the user manages
	member  map[string]bool // workspaces the user belongs to
}

func (s *Server) dnsAccess(w http.ResponseWriter, r *http.Request, ws *webSession) (*dnsAccess, bool) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var who mydc.Whoami
	var tenants []mydc.TenantView
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		var err error
		if who, err = c.Whoami(ctx); err != nil {
			return err
		}
		tenants, err = c.Tenants(ctx)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return nil, false
	}
	a := &dnsAccess{admin: who.User.SystemAdmin, manages: map[string]bool{}, member: map[string]bool{}}
	for _, t := range tenants {
		a.member[t.ID] = true
		if t.Role == mydc.RoleManager {
			a.manages[t.ID] = true
		}
	}
	return a, true
}

// ranges returns the name patterns the caller may write in d (nil for an
// administrator, meaning everything) and the workspace they belong to.
func (a *dnsAccess) ranges(d *store.DNSDomain, manage bool) (patterns []string, tenants []string) {
	for _, as := range d.Assignments {
		if (manage && a.manages[as.Tenant]) || (!manage && a.member[as.Tenant]) {
			patterns = append(patterns, as.Names...)
			tenants = append(tenants, as.Tenant)
		}
	}
	return
}

// tenantFor returns the workspace whose assignment covers name for this
// caller ("" if none).
func (a *dnsAccess) tenantFor(d *store.DNSDomain, name string) string {
	for _, as := range d.Assignments {
		if a.manages[as.Tenant] && dns.InRange(name, as.Names) {
			return as.Tenant
		}
	}
	return ""
}

func (s *Server) dnsProvider(w http.ResponseWriter, p *store.DNSProvider) (dns.Provider, bool) {
	tok, err := s.opt.Seal.Get(dnsSecretName(p.ID))
	if err != nil {
		if errors.Is(err, seal.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "sealed storage is not available; DNS is off")
		} else {
			writeError(w, http.StatusConflict, "token-missing", "the provider token is missing; enter it again")
		}
		return nil, false
	}
	prov, err := s.opt.DNS.Open(p.Vendor, p.ID, string(tok))
	if err != nil {
		writeDNSError(w, err)
		return nil, false
	}
	return prov, true
}

func (s *Server) loadDomain(w http.ResponseWriter, r *http.Request) (*store.DNSDomain, *store.DNSProvider, bool) {
	d, err := s.opt.Store.GetDNSDomain(r.PathValue("domain"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such domain")
		return nil, nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, nil, false
	}
	p, err := s.opt.Store.GetDNSProvider(d.Provider)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "provider of "+d.Domain+": "+err.Error())
		return nil, nil, false
	}
	return d, p, true
}

func (s *Server) dnsCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 30*time.Second)
}

// ---- vendors and provider connections (system administrators) ----

func (s *Server) handleDNSVendors(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type vendorView struct {
		dns.ProviderInfo
		Capabilities dns.Capabilities `json:"capabilities"`
	}
	out := []vendorView{}
	for _, v := range s.opt.DNS.Vendors() {
		info := v.Info
		info.Ready = v.New != nil
		out = append(out, vendorView{info, v.Capabilities})
	}
	st, _ := s.opt.Seal.Status()
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "sealReady": st == seal.StateReady})
}

func (s *Server) handleDNSProviders(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	ps, err := s.opt.Store.ListDNSProviders()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if ps == nil {
		ps = []*store.DNSProvider{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ps})
}

// checkProvider runs Check and records the result on p.
func (s *Server) checkProvider(ctx context.Context, prov dns.Provider, p *store.DNSProvider) (dns.Account, error) {
	acct, err := prov.Check(ctx)
	p.LastCheck = s.now()
	p.LastCheckOK = err == nil
	p.LastError = ""
	if err != nil {
		p.LastError = string(dns.KindOf(err))
		return acct, err
	}
	p.Account, p.TokenExpires, p.Remaining = acct.Name, acct.ExpiresAt, acct.Remaining
	return acct, nil
}

// POST /dns/providers {vendor, name, token}: the token is tested, then
// sealed; it is never shown again (only its last 4 characters).
func (s *Server) handleDNSAddProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Vendor string `json:"vendor"`
		Name   string `json:"name"`
		Token  string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 || len(req.Token) < 8 || len(req.Token) > 4096 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "name (1..100) and token (8..4096) are required")
		return
	}
	if !s.opt.Seal.Ready() {
		writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "sealed storage is not available; tokens cannot be kept")
		return
	}
	prov, err := s.opt.DNS.Open(req.Vendor, "", req.Token)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	p := &store.DNSProvider{ID: newProviderID(), Vendor: req.Vendor, Name: req.Name, TokenHint: seal.Hint([]byte(req.Token)), CreatedBy: ws.user.Username, CreatedAt: s.now()}
	ctx, cancel := s.dnsCtx(r)
	acct, err := s.checkProvider(ctx, prov, p)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	if err := s.opt.Seal.Put(dnsSecretName(p.ID), []byte(req.Token)); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.opt.Store.PutDNSProvider(p); err != nil {
		_ = s.opt.Seal.Delete(dnsSecretName(p.ID))
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "add-provider", p.ID, nil, map[string]any{"vendor": p.Vendor, "name": p.Name, "token": "set"})
	writeJSON(w, http.StatusCreated, map[string]any{"provider": p, "account": acct})
}

func (s *Server) loadProvider(w http.ResponseWriter, r *http.Request) (*store.DNSProvider, bool) {
	p, err := s.opt.Store.GetDNSProvider(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such provider connection")
		return nil, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, false
	}
	return p, true
}

// POST /dns/providers/{id}/check
func (s *Server) handleDNSCheckProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	acct, err := s.checkProvider(ctx, prov, p)
	cancel()
	_ = s.opt.Store.PutDNSProvider(p)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": p, "account": acct})
}

// PUT /dns/providers/{id}/token {token}
func (s *Server) handleDNSProviderToken(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Token string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	if len(req.Token) < 8 || len(req.Token) > 4096 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "token (8..4096) is required")
		return
	}
	prov, err := s.opt.DNS.Open(p.Vendor, p.ID, req.Token)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	ctx, cancel := s.dnsCtx(r)
	_, err = s.checkProvider(ctx, prov, p)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	if err := s.opt.Seal.Put(dnsSecretName(p.ID), []byte(req.Token)); err != nil {
		if errors.Is(err, seal.ErrUnavailable) {
			writeError(w, http.StatusServiceUnavailable, "seal-unavailable", "sealed storage is not available")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	p.TokenHint = seal.Hint([]byte(req.Token))
	_ = s.opt.Store.PutDNSProvider(p)
	s.audit(ws, "", "dns", "replace-token", p.ID, map[string]any{"token": "set"}, map[string]any{"token": "changed"})
	writeJSON(w, http.StatusOK, map[string]any{"provider": p})
}

// PUT /dns/providers/{id} {name}: rename a connection (the token is kept).
func (s *Server) handleDNSRenameProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 100 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "name (1..100) is required")
		return
	}
	before := p.Name
	p.Name = name
	if err := s.opt.Store.PutDNSProvider(p); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if before != name {
		s.audit(ws, "", "dns", "rename-provider", p.ID, map[string]any{"name": before}, map[string]any{"name": name})
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider": p})
}

// DELETE /dns/providers/{id}: refused while a domain uses it.
func (s *Server) handleDNSDeleteProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	id := r.PathValue("id")
	switch err := s.opt.Store.DeleteDNSProvider(id); {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "missing", "no such provider connection")
		return
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "in-use", "remove its domains first")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_ = s.opt.Seal.Delete(dnsSecretName(id))
	s.audit(ws, "", "dns", "delete-provider", id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// GET /dns/providers/{id}/domains: domains of the account, for import.
func (s *Server) handleDNSProviderDomains(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	p, ok := s.loadProvider(w, r)
	if !ok {
		return
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	ds, err := prov.ListDomains(ctx)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	type row struct {
		dns.Domain
		Connected bool `json:"connected"`
	}
	out := []row{}
	for _, d := range ds {
		_, err := s.opt.Store.GetDNSDomain(d.Name)
		out = append(out, row{d, err == nil})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// ---- domains ----

type domainView struct {
	*store.DNSDomain
	ProviderName string   `json:"providerName"`
	Vendor       string   `json:"vendor"`
	MyNames      []string `json:"myNames,omitempty"` // non-admin: names the caller may write
}

// GET /dns/domains: administrators see all, others the domains with an
// assignment to one of their workspaces (and only those assignments).
func (s *Server) handleDNSDomains(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	ds, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := []domainView{}
	for _, d := range ds {
		v := domainView{DNSDomain: d}
		if p, err := s.opt.Store.GetDNSProvider(d.Provider); err == nil {
			v.ProviderName, v.Vendor = p.Name, p.Vendor
		}
		if !a.admin {
			if _, tenants := a.ranges(d, false); len(tenants) == 0 {
				continue
			}
			cp := *d
			cp.Assignments = nil
			for _, as := range d.Assignments {
				if a.member[as.Tenant] {
					cp.Assignments = append(cp.Assignments, as)
				}
			}
			v.DNSDomain = &cp
			v.MyNames, _ = a.ranges(d, true)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func checkAssignments(as []store.DNSAssignment) error {
	seen := map[string]bool{}
	for _, a := range as {
		if a.Tenant == "" || seen[a.Tenant] {
			return errors.New("each assignment needs a distinct workspace")
		}
		seen[a.Tenant] = true
		if len(a.Names) == 0 || len(a.Names) > 50 {
			return errors.New("an assignment has 1..50 names")
		}
		for _, n := range a.Names {
			if err := dns.CheckPattern(n); err != nil {
				return err
			}
		}
	}
	return nil
}

// POST /dns/domains {domain, provider, defaultTtl?, assignments?}
func (s *Server) handleDNSAddDomain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Domain      string                `json:"domain"`
		Provider    string                `json:"provider"`
		DefaultTTL  int                   `json:"defaultTtl"`
		Assignments []store.DNSAssignment `json:"assignments"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	req.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(req.Domain), "."))
	if req.Domain == "" || len(req.Domain) > 253 || strings.ContainsAny(req.Domain, " /\x00") {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "domain is required")
		return
	}
	if err := checkAssignments(req.Assignments); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	p, err := s.opt.Store.GetDNSProvider(req.Provider)
	if err != nil {
		writeError(w, http.StatusNotFound, "missing", "no such provider connection")
		return
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	caps := prov.Capabilities()
	if req.DefaultTTL == 0 {
		req.DefaultTTL = 3600
	}
	if req.DefaultTTL < caps.MinTTL || req.DefaultTTL > 86400*7 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "defaultTtl is outside what the provider accepts")
		return
	}
	ctx, cancel := s.dnsCtx(r)
	defer cancel()
	ds, err := prov.ListDomains(ctx)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	i := slices.IndexFunc(ds, func(d dns.Domain) bool { return d.Name == req.Domain })
	if i < 0 {
		writeError(w, http.StatusNotFound, "missing", "the provider account has no such domain")
		return
	}
	if !ds[i].HasZone {
		writeError(w, http.StatusConflict, "zone-elsewhere", "this domain's DNS is not served by this provider")
		return
	}
	if _, err := prov.GetZone(ctx, req.Domain); err != nil {
		writeDNSError(w, err)
		return
	}
	d := &store.DNSDomain{Domain: req.Domain, Provider: p.ID, DefaultTTL: req.DefaultTTL, Assignments: req.Assignments, AddedBy: ws.user.Username, AddedAt: s.now()}
	if d.Assignments == nil {
		d.Assignments = []store.DNSAssignment{}
	}
	if err := s.opt.Store.CreateDNSDomain(d); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "this domain is already connected")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "add-domain", d.Domain, nil, d)
	writeJSON(w, http.StatusCreated, map[string]any{"domain": d})
}

// PUT /dns/domains/{domain} {defaultTtl, assignments}
func (s *Server) handleDNSUpdateDomain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		DefaultTTL  int                   `json:"defaultTtl"`
		Assignments []store.DNSAssignment `json:"assignments"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	d, _, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	if err := checkAssignments(req.Assignments); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if req.DefaultTTL < 1 || req.DefaultTTL > 86400*7 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "defaultTtl must be 1..604800")
		return
	}
	before := *d
	d.DefaultTTL = req.DefaultTTL
	d.Assignments = req.Assignments
	if d.Assignments == nil {
		d.Assignments = []store.DNSAssignment{}
	}
	if err := s.opt.Store.PutDNSDomain(d); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "update-domain", d.Domain, before, d)
	writeJSON(w, http.StatusOK, map[string]any{"domain": d})
}

// DELETE /dns/domains/{domain}: disconnect. Records at the provider stay.
func (s *Server) handleDNSDeleteDomain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	dom := r.PathValue("domain")
	if err := s.opt.Store.DeleteDNSDomain(dom); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such domain")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "delete-domain", dom, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---- records ----

type recordView struct {
	dns.RRSet
	Fingerprint string            `json:"fingerprint"`
	Managed     *store.DNSManaged `json:"managed,omitempty"`
	Outside     bool              `json:"outside"`  // not a name MyDC manages (admin view)
	Writable    bool              `json:"writable"` // the caller may change it
}

// GET /dns/domains/{domain}/records — read from the provider every time.
// A workspace manager sees only names in their assigned range.
func (s *Server) handleDNSRecords(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	var mine []string
	if !a.admin {
		var tenants []string
		mine, tenants = a.ranges(d, false)
		if len(tenants) == 0 {
			writeError(w, http.StatusForbidden, "denied", "no access to this domain")
			return
		}
	}
	writable, _ := a.ranges(d, true)
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	z, err := prov.GetZone(ctx, d.Domain)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	managed, _ := s.opt.Store.ListDNSManaged(d.Domain)
	var all []string
	for _, as := range d.Assignments {
		all = append(all, as.Names...)
	}
	out := []recordView{}
	for _, set := range z.Sets {
		if !a.admin && !dns.InRange(set.Name, mine) {
			continue
		}
		v := recordView{RRSet: set, Fingerprint: dns.Fingerprint(&set), Managed: managed[set.Key().String()]}
		v.Outside = v.Managed == nil && !dns.InRange(set.Name, all)
		v.Writable = a.admin || dns.InRange(set.Name, writable)
		out = append(out, v)
	}
	// managed marks whose record is gone (orphans)
	var orphans []*store.DNSManaged
	for k, m := range managed {
		name, typ, _ := strings.Cut(k, "|")
		if z.Find(dns.Key{Name: name, Type: typ}) == nil && (a.admin || dns.InRange(name, mine)) {
			orphans = append(orphans, m)
		}
	}
	sort.Slice(orphans, func(i, j int) bool { return orphans[i].Name+orphans[i].Type < orphans[j].Name+orphans[j].Type })
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "orphans": orphans, "capabilities": prov.Capabilities(), "readAt": rfc3339(s.now())})
}

type dnsChangeReq struct {
	Upsert []dns.RRSet `json:"upsert"`
	Delete []dns.Key   `json:"delete"`
	// Outside must be true to change a record MyDC did not make and no
	// workspace is assigned (administrators only; the confirm dialog).
	Outside bool   `json:"outside"`
	Tenant  string `json:"tenant"` // optional: the workspace the change is for
	App     string `json:"app"`    // optional: the app whose ingress needs it
}

type plannedChange struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"`
	Before      *dns.RRSet `json:"before"`
	After       *dns.RRSet `json:"after"`
	Fingerprint string     `json:"fingerprint"` // of Before; apply must see the same
	Tenant      string     `json:"tenant,omitempty"`
	Outside     bool       `json:"outside,omitempty"` // a record MyDC does not manage (stays unmarked)
}

// planDNS checks a change request against the caller's range and the zone
// and returns the planned changes. It writes the error itself.
func (s *Server) planDNS(w http.ResponseWriter, a *dnsAccess, d *store.DNSDomain, prov dns.Provider, z dns.Zone, req *dnsChangeReq) ([]plannedChange, bool) {
	if len(req.Upsert)+len(req.Delete) == 0 || len(req.Upsert)+len(req.Delete) > 200 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "1..200 changes")
		return nil, false
	}
	caps := prov.Capabilities()
	managed, _ := s.opt.Store.ListDNSManaged(d.Domain)
	var assigned []string
	for _, as := range d.Assignments {
		assigned = append(assigned, as.Names...)
	}
	seen := map[dns.Key]bool{}
	var out []plannedChange
	add := func(k dns.Key, after *dns.RRSet) bool {
		if seen[k] {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "a record set appears twice: "+k.Name+" "+k.Type)
			return false
		}
		seen[k] = true
		tenant := ""
		outside := false
		if !a.admin {
			if tenant = a.tenantFor(d, k.Name); tenant == "" {
				writeError(w, http.StatusForbidden, "out-of-range", k.Name+" is outside the names assigned to your workspaces")
				return false
			}
		} else if managed[k.String()] == nil && !dns.InRange(k.Name, assigned) {
			if !req.Outside {
				writeError(w, http.StatusConflict, "outside", k.Name+" "+k.Type+" is not managed by MyDC; confirm to change it")
				return false
			}
			outside = true
		}
		before := z.Find(k)
		var bp *dns.RRSet
		if before != nil {
			cp := *before
			bp = &cp
		}
		out = append(out, plannedChange{Name: k.Name, Type: k.Type, Before: bp, After: after, Fingerprint: dns.Fingerprint(before), Tenant: tenant, Outside: outside})
		return true
	}
	for i := range req.Upsert {
		u := req.Upsert[i]
		if u.TTL == 0 {
			u.TTL = d.DefaultTTL
		}
		if err := dns.CheckSet(u, caps); err != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
			return nil, false
		}
		if !add(u.Key(), &u) {
			return nil, false
		}
	}
	for _, k := range req.Delete {
		if z.Find(k) == nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "no record set "+k.Name+" "+k.Type+" to delete")
			return nil, false
		}
		if !add(k, nil) {
			return nil, false
		}
	}
	return out, true
}

func changeSet(cs []plannedChange) dns.ChangeSet {
	var c dns.ChangeSet
	for _, p := range cs {
		if p.After != nil {
			c.Upsert = append(c.Upsert, *p.After)
		} else {
			c.Delete = append(c.Delete, dns.Key{Name: p.Name, Type: p.Type})
		}
	}
	return c
}

// POST /dns/domains/{domain}/plan {upsert, delete, outside?} → planned
// changes with the fingerprint of each set as read now, and the provider's
// validation problems. Nothing changes.
func (s *Server) handleDNSPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req dnsChangeReq
	if !readJSON(w, r, &req) {
		return
	}
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	if !a.admin && len(a.manages) == 0 {
		writeError(w, http.StatusForbidden, "denied", "no access to this domain")
		return
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	defer cancel()
	z, err := prov.GetZone(ctx, d.Domain)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	plan, ok := s.planDNS(w, a, d, prov, z, &req)
	if !ok {
		return
	}
	problems := []dns.Problem{}
	if v, ok := prov.(dns.Validator); ok && prov.Capabilities().Validate {
		ps, err := v.Validate(ctx, d.Domain, changeSet(plan))
		if err != nil {
			writeDNSError(w, err)
			return
		}
		if ps != nil {
			problems = ps
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": plan, "problems": problems})
}

// POST /dns/domains/{domain}/apply {opId, upsert, delete, outside?, basis}
// basis maps "name|type" to the fingerprint the plan showed. The zone is
// read again; if any set differs, nothing is applied (409 zone-changed).
// The same opId returns the stored result instead of applying again.
func (s *Server) handleDNSApply(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		dnsChangeReq
		OpID  string            `json:"opId"`
		Basis map[string]string `json:"basis"`
		// RevertOf names the history row this change puts back (from
		// /history/{id}/revert). It is a label on the new row only.
		RevertOf string `json:"revertOf,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a UUID")
		return
	}
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	raw, _ := json.Marshal(req.dnsChangeReq)
	dg := sha256hex(append(append(raw, mustJSON(req.Basis)...), req.RevertOf...))
	if h, err := s.opt.Store.GetDNSHistory(d.Domain, req.OpID); err == nil {
		if h.Digest != dg || h.User != ws.user.ID {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"history": h})
		return
	}
	if !a.admin && len(a.manages) == 0 {
		writeError(w, http.StatusForbidden, "denied", "no access to this domain")
		return
	}
	if req.RevertOf != "" {
		if _, err := s.opt.Store.GetDNSHistory(d.Domain, req.RevertOf); err != nil || req.RevertOf == req.OpID {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "revertOf: no such change in this domain")
			return
		}
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	defer cancel()
	z, err := prov.GetZone(ctx, d.Domain)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	plan, ok := s.planDNS(w, a, d, prov, z, &req.dnsChangeReq)
	if !ok {
		return
	}
	var changed []plannedChange
	for _, c := range plan {
		k := c.Name + "|" + c.Type
		if fp, ok := req.Basis[k]; !ok || fp != c.Fingerprint {
			changed = append(changed, c)
		}
	}
	if len(changed) > 0 {
		writeJSON(w, http.StatusConflict, map[string]any{"error": map[string]any{"code": "zone-changed", "message": "records changed since the plan; plan again"}, "changes": changed})
		return
	}
	if v, ok := prov.(dns.Validator); ok && prov.Capabilities().Validate {
		if ps, err := v.Validate(ctx, d.Domain, changeSet(plan)); err != nil {
			writeDNSError(w, err)
			return
		} else if len(ps) > 0 {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{"code": "dns-invalid", "message": "the provider rejected the change"}, "problems": ps})
			return
		}
	}

	// The workspace a change belongs to comes from the plan: for a
	// workspace manager it is the assignment that covers the name, never a
	// value the caller sends. An administrator may name one of the domain's
	// assigned workspaces.
	tenant := ""
	if a.admin {
		if req.Tenant != "" && !slices.ContainsFunc(d.Assignments, func(as store.DNSAssignment) bool { return as.Tenant == req.Tenant }) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "tenant "+req.Tenant+" has no assignment in this domain")
			return
		}
		tenant = req.Tenant
	} else {
		for _, c := range plan {
			if tenant == "" {
				tenant = c.Tenant
			} else if c.Tenant != tenant {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "one change list must stay within one workspace's names")
				return
			}
		}
		if req.Tenant != "" && req.Tenant != tenant {
			writeError(w, http.StatusForbidden, "out-of-range", "these names belong to workspace "+tenant)
			return
		}
	}
	h := &store.DNSHistory{ID: req.OpID, Domain: d.Domain, At: s.now(), User: ws.user.ID, Username: ws.user.Username, Tenant: tenant, Digest: dg, RevertOf: req.RevertOf}
	for _, c := range plan {
		h.Changes = append(h.Changes, store.DNSChange{Name: c.Name, Type: c.Type, Before: mustJSON(c.Before), After: mustJSON(c.After)})
	}
	// Record before the call, so a lost reply leaves an "unknown" row with
	// the values to compare or revert.
	h.Result = "unknown"
	if err := s.opt.Store.PutDNSHistory(h); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	res, err := prov.Apply(ctx, d.Domain, changeSet(plan))
	if err != nil {
		switch dns.KindOf(err) {
		case dns.Unavailable:
			// The provider may have applied it: read the zone to tell.
			h.Result, h.Error = "unknown", err.Error()
		default:
			h.Result, h.Error = "failed", string(dns.KindOf(err))
		}
		_ = s.opt.Store.PutDNSHistory(h)
		if h.Result == "failed" {
			s.notify(&store.Notification{User: ws.user.ID, Kind: NotifyOpFailed, Severity: "error", Tenant: h.Tenant, Title: "DNS 변경 실패: " + d.Domain, Body: h.Error, Link: "/dns/" + d.Domain})
		}
		writeJSON(w, http.StatusOK, map[string]any{"history": h})
		return
	}
	h.Result, h.Snapshot = "applied", res.Snapshot
	_ = s.opt.Store.PutDNSHistory(h)
	var set []*store.DNSManaged
	var remove [][2]string
	for _, c := range plan {
		if c.After == nil {
			remove = append(remove, [2]string{c.Name, c.Type})
			continue
		}
		if c.Outside {
			continue // an outside record stays outside
		}
		set = append(set, &store.DNSManaged{Domain: d.Domain, Name: c.Name, Type: c.Type, Tenant: firstNonEmpty(c.Tenant, tenant), App: req.App, By: ws.user.Username, Fingerprint: dns.Fingerprint(c.After), At: s.now()})
	}
	_ = s.opt.Store.ApplyDNSManaged(d.Domain, set, remove)
	s.audit(ws, h.Tenant, "dns", "apply", d.Domain, nil, map[string]any{"changes": len(plan), "history": h.ID})
	writeJSON(w, http.StatusOK, map[string]any{"history": h})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// GET /dns/domains/{domain}/history?limit=
func (s *Server) handleDNSHistory(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, _, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	_, tenants := a.ranges(d, false)
	if !a.admin && len(tenants) == 0 {
		writeError(w, http.StatusForbidden, "denied", "no access to this domain")
		return
	}
	hs, err := s.opt.Store.ListDNSHistory(d.Domain, 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := []*store.DNSHistory{}
	for _, h := range hs {
		if a.admin || slices.Contains(tenants, h.Tenant) {
			out = append(out, h)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

// POST /dns/domains/{domain}/history/{id}/revert → a change request that
// puts the sets back to their before values. It is planned and applied like
// any other change (nothing is applied here).
func (s *Server) handleDNSRevert(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, _, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	h, err := s.opt.Store.GetDNSHistory(d.Domain, r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "missing", "no such change")
		return
	}
	if !a.admin && (h.Tenant == "" || !a.manages[h.Tenant]) {
		writeError(w, http.StatusForbidden, "denied", "no access to this change")
		return
	}
	req := dnsChangeReq{Tenant: h.Tenant, Upsert: []dns.RRSet{}, Delete: []dns.Key{}}
	for _, c := range h.Changes {
		var before *dns.RRSet
		_ = json.Unmarshal(c.Before, &before)
		if before != nil {
			req.Upsert = append(req.Upsert, *before)
		} else {
			req.Delete = append(req.Delete, dns.Key{Name: c.Name, Type: c.Type})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"request": req, "revertOf": h.ID})
}

// DELETE /dns/domains/{domain}/history/{id} (administrators)
func (s *Server) handleDNSDeleteHistory(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	dom, id := r.PathValue("domain"), r.PathValue("id")
	if err := s.opt.Store.DeleteDNSHistory(dom, id); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no such change")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "delete-history", dom+"/"+id, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// GET /dns/domains/{domain}/snapshots and POST …/snapshots/{id}/restore
// (administrators, providers with Snapshots).
func (s *Server) snapshotter(w http.ResponseWriter, r *http.Request, ws *webSession) (*store.DNSDomain, dns.Snapshotter, bool) {
	if !s.requireAdmin(w, r, ws) {
		return nil, nil, false
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return nil, nil, false
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return nil, nil, false
	}
	sn, ok := prov.(dns.Snapshotter)
	if !ok || !prov.Capabilities().Snapshots {
		writeError(w, http.StatusNotImplemented, "unsupported", "this provider keeps no snapshots")
		return nil, nil, false
	}
	return d, sn, true
}

func (s *Server) handleDNSSnapshots(w http.ResponseWriter, r *http.Request, ws *webSession) {
	d, sn, ok := s.snapshotter(w, r, ws)
	if !ok {
		return
	}
	ctx, cancel := s.dnsCtx(r)
	ss, err := sn.ListSnapshots(ctx, d.Domain)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	if ss == nil {
		ss = []dns.Snapshot{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": ss})
}

func (s *Server) handleDNSRestoreSnapshot(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	d, sn, ok := s.snapshotter(w, r, ws)
	if !ok {
		return
	}
	if req.Confirm != d.Domain {
		writeError(w, http.StatusBadRequest, "confirm-mismatch", "type the domain name to confirm")
		return
	}
	id := r.PathValue("id")
	ctx, cancel := s.dnsCtx(r)
	err := sn.RestoreSnapshot(ctx, d.Domain, id)
	cancel()
	if err != nil {
		writeDNSError(w, err)
		return
	}
	h := &store.DNSHistory{ID: "restore-" + randomID(9), Domain: d.Domain, At: s.now(), User: ws.user.ID, Username: ws.user.Username, Result: "applied", Snapshot: id}
	_ = s.opt.Store.PutDNSHistory(h)
	s.audit(ws, "", "dns", "restore-snapshot", d.Domain, nil, map[string]any{"snapshot": id})
	writeJSON(w, http.StatusOK, map[string]any{"history": h})
}
