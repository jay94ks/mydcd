// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// The external domain list is the cluster domain list (sfcd `domain list`,
// docs/reference/certificate-store.md). The web app adds only its own part
// to a domain: the DNS provider connection, default TTL and workspace
// assignments (store.DNSDomain). A registered domain without a connection
// has provider null; its records cannot be read or changed here, and its
// certificates are issued by HTTP-01 only. Registering and removing a
// domain are add-domain / remove-domain, signed by the logged-in user.

// clusterDomainView is one row of GET /dns/domains (src/api/dns.ts DnsDomain).
type clusterDomainView struct {
	Domain       string                `json:"domain"`
	Unicode      string                `json:"unicode,omitempty"`
	Provider     *domainProviderView   `json:"provider"`
	Registered   bool                  `json:"registered"` // in the cluster list (false: a connection left after a remove elsewhere)
	Hosts        int                   `json:"hosts"`
	Certificates int                   `json:"certificates"`
	DefaultTTL   int                   `json:"defaultTtl"`
	Assignments  []store.DNSAssignment `json:"assignments"`
	AddedBy      string                `json:"addedBy,omitempty"`
	AddedAt      string                `json:"addedAt,omitempty"`
	MyNames      []string              `json:"myNames,omitempty"`
}

type domainProviderView struct {
	ID     string `json:"id"`
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}

// clusterDomains is what one read of the store gives the domain screens.
type clusterDomains struct {
	Revision uint64
	Domains  []certstore.Domain
	Certs    []certstore.PublicEntry
	Names    map[string]string // user ID → username
}

func (c *clusterDomains) has(name string) bool {
	return slices.ContainsFunc(c.Domains, func(d certstore.Domain) bool { return d.Name == name })
}

// linked returns the hosts and certificate IDs linked under domain.
func (c *clusterDomains) linked(domain string) (hosts map[string]bool, certs map[string]bool) {
	hosts, certs = map[string]bool{}, map[string]bool{}
	for _, e := range c.Certs {
		for _, l := range e.Links {
			if certstore.DomainCovers(domain, l.Host) {
				hosts[l.Host+"\x00"+l.Family] = true
				certs[e.Metadata.ID.String()] = true
			}
		}
	}
	return hosts, certs
}

func (c *clusterDomains) linkedIDs() map[string]bool {
	out := map[string]bool{}
	for _, e := range c.Certs {
		if len(e.Links) > 0 {
			out[e.Metadata.ID.String()] = true
		}
	}
	return out
}

// readClusterDomains reads the domain list (first store page) and every
// certificate, as the caller's session (system administrators only).
func readClusterDomains(ctx context.Context, c sfc.Conn, withNames bool) (*clusterDomains, error) {
	for try := 0; ; try++ {
		p, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		if err != nil {
			return nil, err
		}
		certs, err := certAll(ctx, c)
		if err != nil {
			return nil, err
		}
		again, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		if err != nil {
			return nil, err
		}
		if again.Revision != p.Revision && try+1 < certMaxTries {
			continue
		}
		out := &clusterDomains{Revision: again.Revision, Domains: again.Domains, Certs: certs}
		if withNames {
			out.Names = usernames(ctx, c)
		}
		return out, nil
	}
}

func (s *Server) providerView(id string) *domainProviderView {
	if id == "" {
		return nil
	}
	v := &domainProviderView{ID: id, Name: id}
	if p, err := s.opt.Store.GetDNSProvider(id); err == nil {
		v.Vendor, v.Name = p.Vendor, p.Name
	}
	return v
}

// domainRow builds the row of name from the cluster entry (if any) and the
// web connection (if any).
func (s *Server) domainRow(cd *clusterDomains, name string, conn *store.DNSDomain) clusterDomainView {
	v := clusterDomainView{Domain: name, DefaultTTL: 3600, Assignments: []store.DNSAssignment{}}
	if u := certstore.DisplayDomain(name); u != name {
		v.Unicode = u
	}
	if cd != nil {
		if i := slices.IndexFunc(cd.Domains, func(d certstore.Domain) bool { return d.Name == name }); i >= 0 {
			d := cd.Domains[i]
			v.Registered, v.AddedBy, v.AddedAt = true, d.AddedBy, rfc(d.AddedAt)
			if n := cd.Names[d.AddedBy]; n != "" {
				v.AddedBy = n
			}
		}
		hosts, certs := cd.linked(name)
		v.Hosts, v.Certificates = len(hosts), len(certs)
	}
	if conn != nil {
		v.Provider = s.providerView(conn.Provider)
		v.DefaultTTL = conn.DefaultTTL
		if conn.Assignments != nil {
			v.Assignments = conn.Assignments
		}
		if !v.Registered {
			v.AddedBy, v.AddedAt = conn.AddedBy, rfc3339(conn.AddedAt)
		}
	}
	return v
}

// GET /dns/domains → {items, cluster: true}. System administrators see the
// cluster list joined with the web connections. Other users see only the
// connected domains with an assignment to one of their workspaces (and only
// those assignments); they cannot read the store.
func (s *Server) handleDNSDomains(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	conns, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	byName := map[string]*store.DNSDomain{}
	for _, d := range conns {
		byName[d.Domain] = d
	}
	out := []clusterDomainView{}
	if !a.admin {
		for _, d := range conns {
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
			v := s.domainRow(nil, d.Domain, &cp)
			v.Registered = true // not known to this user; the row exists because it is connected
			v.MyNames, _ = a.ranges(d, true)
			out = append(out, v)
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": out, "cluster": true})
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var cd *clusterDomains
	if err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) (err error) {
		cd, err = readClusterDomains(ctx, c, true)
		return err
	}); err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	seen := map[string]bool{}
	for _, d := range cd.Domains {
		seen[d.Name] = true
		out = append(out, s.domainRow(cd, d.Name, byName[d.Name]))
	}
	for _, d := range conns {
		if !seen[d.Domain] {
			out = append(out, s.domainRow(cd, d.Domain, d))
		}
	}
	slices.SortFunc(out, func(x, y clusterDomainView) int { return strings.Compare(x.Domain, y.Domain) })
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "cluster": true})
}

// normalizeDomainInput maps a typed domain to the cluster A-label form, or
// the 422 the web API gives (public-suffix, invalid-domain).
func normalizeDomainInput(raw string) (string, error) {
	name, ok := certstore.NormalizeDomain(strings.TrimSpace(raw))
	if ok {
		return name, nil
	}
	t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if t != "" && !strings.ContainsAny(t, "* /") {
		if suffix, _ := publicsuffix.PublicSuffix(t); suffix == t {
			return "", &httpErr{http.StatusUnprocessableEntity, "public-suffix", t + " is a public suffix and cannot be registered"}
		}
	}
	return "", &httpErr{http.StatusUnprocessableEntity, "invalid-domain", "not a registrable domain name or IP address"}
}

// domainChange sends add-domain or remove-domain for name at revision as
// the caller and maps a change that did not apply.
func (s *Server) domainChange(ctx context.Context, c sfc.Conn, ws *webSession, action, name string, revision uint64) error {
	raw, _ := json.Marshal(control.DomainChange{Name: name})
	ch := sfc.Change{Schema: 1, Action: action, Principal: ws.user.ID, Expected: revision, Payload: raw}
	who, err := c.Whoami(ctx)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(append([]byte(action+"\x00"), raw...))
	o := &store.Op{ID: newOpID(), User: ws.user.ID, Username: ws.user.Username, Action: action, Target: name, Digest: hex.EncodeToString(sum[:])}
	if _, err := s.sendStored(ctx, c, o, ch, who.RootFor(action)); err != nil {
		return err
	}
	switch o.State {
	case store.OpApplied:
		return nil
	case store.OpFailed:
		return &httpErr{http.StatusConflict, "stale", "the cluster domain list changed; reload it"}
	case store.OpRejected:
		return &httpErr{http.StatusForbidden, "denied", "sfcd refused the change: " + o.ErrorCode}
	}
	return &httpErr{http.StatusServiceUnavailable, "unknown", "sfcd did not answer; operation " + o.ID + " keeps the signed original, read its result"}
}

// checkProviderZone checks that provider p serves domain's zone and returns
// the provider's minimum TTL. It writes the error itself.
func (s *Server) checkProviderZone(w http.ResponseWriter, r *http.Request, p *store.DNSProvider, domain string) (minTTL int, ok bool) {
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return 0, false
	}
	ctx, cancel := s.dnsCtx(r)
	defer cancel()
	ds, err := prov.ListDomains(ctx)
	if err != nil {
		writeDNSError(w, err)
		return 0, false
	}
	i := slices.IndexFunc(ds, func(d dns.Domain) bool { return d.Name == domain })
	if i < 0 {
		writeError(w, http.StatusNotFound, "missing", "the provider account has no such domain")
		return 0, false
	}
	if !ds[i].HasZone {
		writeError(w, http.StatusConflict, "zone-elsewhere", "this domain's DNS is not served by this provider")
		return 0, false
	}
	if _, err := prov.GetZone(ctx, domain); err != nil {
		writeDNSError(w, err)
		return 0, false
	}
	return prov.Capabilities().MinTTL, true
}

// POST /dns/domains {domain, provider?, defaultTtl?, assignments?} → 201
// {domain, linked}. The domain is registered in the cluster list (add-domain
// as the caller) when it is not there yet; with provider the connection is
// saved too. linked counts the certificates that gained a link.
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
	name, err := normalizeDomainInput(req.Domain)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if err := checkAssignments(req.Assignments); err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", err.Error())
		return
	}
	if _, err := s.opt.Store.GetDNSDomain(name); err == nil {
		writeError(w, http.StatusConflict, "exists", "this domain is already registered and connected")
		return
	}
	var p *store.DNSProvider
	if req.Provider != "" {
		if p, err = s.opt.Store.GetDNSProvider(req.Provider); err != nil {
			writeError(w, http.StatusNotFound, "missing", "no such provider connection")
			return
		}
		if req.DefaultTTL == 0 {
			req.DefaultTTL = 3600
		}
		minTTL, ok := s.checkProviderZone(w, r, p, name)
		if !ok {
			return
		}
		if req.DefaultTTL < minTTL || req.DefaultTTL > 86400*7 {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "defaultTtl is outside what the provider accepts")
			return
		}
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var before, after *clusterDomains
	err = ws.do(ctx, func(ctx context.Context, c sfc.Conn) (err error) {
		if before, err = readClusterDomains(ctx, c, false); err != nil {
			return err
		}
		if before.has(name) {
			if p == nil {
				return &httpErr{http.StatusConflict, "exists", "this domain is already registered"}
			}
			after = before
			return nil
		}
		if err := s.domainChange(ctx, c, ws, sfc.ActionAddDomain, name, before.Revision); err != nil {
			return err
		}
		after, err = readClusterDomains(ctx, c, true)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if before != after {
		s.audit(ws, "", "dns", "register-domain", name, nil, map[string]any{"domain": name})
	}
	var conn *store.DNSDomain
	if p != nil {
		conn = &store.DNSDomain{Domain: name, Provider: p.ID, DefaultTTL: req.DefaultTTL, Assignments: req.Assignments, AddedBy: ws.user.Username, AddedAt: s.now()}
		if conn.Assignments == nil {
			conn.Assignments = []store.DNSAssignment{}
		}
		if err := s.opt.Store.CreateDNSDomain(conn); errors.Is(err, store.ErrConflict) {
			writeError(w, http.StatusConflict, "exists", "this domain is already connected")
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		s.audit(ws, "", "dns", "add-domain", name, nil, conn)
	}
	linked := 0
	was := before.linkedIDs()
	for id := range after.linkedIDs() {
		if !was[id] {
			linked++
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{"domain": s.domainRow(after, name, conn), "linked": linked})
}

// DELETE /dns/domains/{domain} → {unlinkedHosts, unlinkedCertificates}.
// remove-domain as the caller (never refused for links: certificates under
// it only lose them) and the web connection is dropped. Records at the
// provider stay.
func (s *Server) handleDNSDeleteDomain(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := strings.ToLower(r.PathValue("domain"))
	_, connErr := s.opt.Store.GetDNSDomain(name)
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var before, after *clusterDomains
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) (err error) {
		if before, err = readClusterDomains(ctx, c, false); err != nil {
			return err
		}
		if !before.has(name) {
			if connErr != nil {
				return &httpErr{http.StatusNotFound, "missing", "no such domain"}
			}
			after = before
			return nil
		}
		if err := s.domainChange(ctx, c, ws, sfc.ActionRemoveDomain, name, before.Revision); err != nil {
			return err
		}
		after, err = readClusterDomains(ctx, c, false)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if connErr == nil {
		if err := s.opt.Store.DeleteDNSDomain(name); err != nil && !errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
	}
	s.audit(ws, "", "dns", "delete-domain", name, nil, nil)
	hosts, _ := before.linked(name)
	unlinked := 0
	now := after.linkedIDs()
	for id := range before.linkedIDs() {
		if !now[id] {
			unlinked++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"unlinkedHosts": len(hosts), "unlinkedCertificates": unlinked})
}

// PUT /dns/domains/{domain}/provider {provider} → {domain}: attach or
// replace the DNS provider of a registered domain. Default TTL and
// assignments stay.
func (s *Server) handleDNSPutDomainProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Provider string `json:"provider"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := strings.ToLower(r.PathValue("domain"))
	p, err := s.opt.Store.GetDNSProvider(req.Provider)
	if err != nil {
		writeError(w, http.StatusNotFound, "missing", "no such provider connection")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var cd *clusterDomains
	if err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) (err error) {
		cd, err = readClusterDomains(ctx, c, true)
		return err
	}); err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if !cd.has(name) {
		writeError(w, http.StatusNotFound, "missing", "the domain is not in the cluster domain list")
		return
	}
	minTTL, ok := s.checkProviderZone(w, r, p, name)
	if !ok {
		return
	}
	conn, err := s.opt.Store.GetDNSDomain(name)
	switch {
	case errors.Is(err, store.ErrNotFound):
		conn = &store.DNSDomain{Domain: name, Provider: p.ID, DefaultTTL: max(3600, minTTL), Assignments: []store.DNSAssignment{}, AddedBy: ws.user.Username, AddedAt: s.now()}
		err = s.opt.Store.CreateDNSDomain(conn)
		s.audit(ws, "", "dns", "add-domain", name, nil, conn)
	case err == nil:
		before := *conn
		conn.Provider = p.ID
		if conn.DefaultTTL < minTTL {
			conn.DefaultTTL = minTTL
		}
		err = s.opt.Store.PutDNSDomain(conn)
		s.audit(ws, "", "dns", "update-domain", name, before, conn)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": s.domainRow(cd, name, conn)})
}

// DELETE /dns/domains/{domain}/provider → {domain}: drop the web connection
// only; the domain stays in the cluster list. Records at the provider stay.
func (s *Server) handleDNSDeleteDomainProvider(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name := strings.ToLower(r.PathValue("domain"))
	if err := s.opt.Store.DeleteDNSDomain(name); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "missing", "no DNS provider is attached to this domain")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "delete-domain", name, nil, nil)
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var cd *clusterDomains
	_ = ws.do(ctx, func(ctx context.Context, c sfc.Conn) (err error) {
		cd, err = readClusterDomains(ctx, c, true)
		return err
	})
	writeJSON(w, http.StatusOK, map[string]any{"domain": s.domainRow(cd, name, nil)})
}

// registeredDomains reads the cluster domain names as the caller, for the
// provider import list; nil when the store cannot be read.
func registeredDomains(ctx context.Context, ws *webSession) map[string]bool {
	out := map[string]bool{}
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		p, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		for _, d := range p.Domains {
			out[d.Name] = true
		}
		return err
	})
	if err != nil {
		return nil
	}
	return out
}

// orderDomains reads the registered cluster domain names as ws for an ACME
// preflight.
func (s *Server) orderDomains(ctx context.Context, ws *webSession) ([]string, error) {
	var out []string
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		p, err := c.QueryCertificates(ctx, control.CertificateQuery{})
		for _, d := range p.Domains {
			out = append(out, d.Name)
		}
		return err
	})
	return out, err
}
