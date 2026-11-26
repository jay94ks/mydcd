// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/web/dns"
)

// GET /dns/domains/{domain}/propagation?name=&type=: what the domain's
// authoritative servers and some public resolvers answer for one record set,
// next to what the provider holds now (want). Only for a provider whose
// capabilities include propagation. Read access is the same as /records.
func (s *Server) handleDNSPropagation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return
	}
	name, rtype := r.URL.Query().Get("name"), strings.ToUpper(r.URL.Query().Get("type"))
	if name == "" || rtype == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "name and type are required")
		return
	}
	if !a.admin {
		mine, tenants := a.ranges(d, false)
		if len(tenants) == 0 || !dns.InRange(name, mine) {
			writeError(w, http.StatusForbidden, "denied", "no access to this name")
			return
		}
	}
	caps, _ := s.opt.DNS.Capabilities(p.Vendor)
	if !caps.Propagation {
		writeError(w, http.StatusConflict, "not-supported", "this DNS provider has no propagation check")
		return
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return
	}
	if !slices.Contains(caps.RecordTypes, rtype) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "record type "+rtype)
		return
	}
	ctx, cancel := s.dnsCtx(r)
	defer cancel()
	z, err := prov.GetZone(ctx, d.Domain)
	if err != nil {
		writeDNSError(w, err)
		return
	}
	want := dns.WantValues(z.Find(dns.Key{Name: name, Type: rtype}))
	fqdn := d.Domain
	if name != "@" {
		fqdn = name + "." + d.Domain
	}
	res := s.opt.Resolver
	if res == nil {
		res = dns.NetResolver{}
	}

	type resolverView struct {
		Kind    string   `json:"kind"`
		Server  string   `json:"server"`
		Values  []string `json:"values"`
		Fresh   bool     `json:"fresh"`
		TTLLeft *uint32  `json:"ttlLeft,omitempty"`
		Error   string   `json:"error,omitempty"`
	}
	// the authoritative servers are the domain's NS, as a public resolver sees them
	var servers []string
	qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
	if ns, err := res.Query(qctx, dns.PublicResolvers[0], d.Domain, "NS", true); err == nil {
		servers = ns.Values
	}
	qcancel()
	slices.Sort(servers)
	if len(servers) > 4 {
		servers = servers[:4]
	}
	type job struct {
		kind, server string
		recurse      bool
	}
	var jobs []job
	for _, ns := range servers {
		jobs = append(jobs, job{"authoritative", ns, false})
	}
	for _, pub := range dns.PublicResolvers {
		jobs = append(jobs, job{"public", strings.TrimSuffix(pub, ":53"), true})
	}
	out := make([]resolverView, len(jobs))
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			v := resolverView{Kind: j.kind, Server: j.server, Values: []string{}}
			ans, err := res.Query(qctx, j.server+":53", fqdn, rtype, j.recurse)
			if err != nil {
				v.Error = string(dns.KindOf(err))
			} else {
				if ans.Values != nil {
					v.Values = ans.Values
				}
				slices.Sort(v.Values)
				v.Fresh = dns.SameValues(v.Values, want)
				if j.recurse && len(ans.Values) > 0 {
					ttl := ans.TTL
					v.TTLLeft = &ttl
				}
			}
			out[i] = v
		}()
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "type": rtype, "want": want, "resolvers": out, "checkedAt": s.now().UTC().Format(time.RFC3339)})
}
