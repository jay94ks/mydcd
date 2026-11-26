// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/dns"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// A domain's linked servers (canvas ExtDomainDetail "연결된 서버", web-own
// data): the servers whose public addresses the domain's MyDC A/AAAA
// records point at. The servers, their external gateway and phase are read
// from mydcd each time; the links (address source, manual addresses,
// autoRemove, last reach check) are the web's. Saving a link does not touch
// the zone: it answers with the record changes it implies (changes, staged
// = their count), which go through the usual plan/apply.

const dnsReachTimeout = 5 * time.Second

// dnsNode is a server with an external gateway, as mydcd shows it.
type dnsNode struct {
	listen    []int
	addresses []string
	isolated  bool
}

// dnsNodes: the servers with an external gateway (system administrator's
// view of the gateways).
func (s *Server) dnsNodes(ctx context.Context, ws *webSession) (map[string]dnsNode, error) {
	out := map[string]dnsNode{}
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		iv, err := ingressRead(ctx, c, control.IngressQuery{})
		if err != nil {
			return err
		}
		for _, n := range iv.Nodes {
			if n.Enabled != nil && !*n.Enabled {
				continue
			}
			for _, g := range n.Gateways {
				if g.Gateway == "external" {
					out[n.Node] = externalNode(g)
				}
			}
		}
		return eachMember(ctx, c, func(m memberView, _ mydc.MembersPage) bool {
			if n, ok := out[m.ID]; ok && m.Phase == mydc.NodePhaseIsolated {
				n.isolated = true
				out[m.ID] = n
			}
			return true
		})
	})
	return out, err
}

// externalNode: the external gateway's listening ports and the specific
// (not wildcard) addresses it binds; a wildcard bind leaves the addresses
// to the link's manual list.
func externalNode(g control.IngressGatewaySummary) dnsNode {
	n := dnsNode{listen: []int{}, addresses: []string{}}
	for _, l := range g.Listeners {
		if p := listenerPort(l.Address); p != 0 && !slices.Contains(n.listen, p) {
			n.listen = append(n.listen, p)
		}
		if ap, err := netip.ParseAddrPort(l.Address); err == nil && !ap.Addr().IsUnspecified() {
			if a := ap.Addr().Unmap().String(); !slices.Contains(n.addresses, a) {
				n.addresses = append(n.addresses, a)
			}
		}
	}
	return n
}

func reachView(r *store.DNSReach) map[string]any {
	v := map[string]any{"ok": r.OK, "at": rfc3339(r.At)}
	if r.Error != "" {
		v["error"] = r.Error
	}
	return v
}

// linkAddresses: where a linked server's records point.
func linkAddresses(row *store.DNSServerLink, n dnsNode) []string {
	if row.AddressSource == "manual" {
		return row.Addresses
	}
	return n.addresses
}

// dnsServerItems: every server with an external gateway, then linked ones
// mydcd no longer shows (admin), or only the linked ones (others, nodes
// nil: node addresses and phases unknown).
func dnsServerItems(l *store.DNSServerLinks, nodes map[string]dnsNode, admin bool) []map[string]any {
	names := []string{}
	for n := range nodes {
		if admin || l.Rows[n] != nil {
			names = append(names, n)
		}
	}
	for n := range l.Rows {
		if _, ok := nodes[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	items := []map[string]any{}
	for _, name := range names {
		n, known := nodes[name]
		known = known || nodes == nil // nil: not read (partial view)
		row := l.Rows[name]
		listen := n.listen
		if listen == nil {
			listen = []int{}
		}
		v := map[string]any{"node": name, "listen": listen, "linked": row != nil}
		if n.isolated {
			v["isolated"] = true
		}
		if row == nil {
			v["addresses"], v["addressSource"], v["autoRemove"], v["state"] = n.addresses, "node", true, "not-linked"
		} else {
			addrs := linkAddresses(row, n)
			if addrs == nil {
				addrs = []string{}
			}
			v["addresses"], v["addressSource"], v["autoRemove"] = addrs, row.AddressSource, row.AutoRemove
			v["state"] = "in-dns"
			if row.AutoRemove && (n.isolated || !known) {
				v["state"] = "removed"
			}
			if !known {
				v["missing"] = true // mydcd no longer shows its external gateway
			}
			if row.Reach != nil {
				v["reach"] = reachView(row.Reach)
			}
		}
		if v["addresses"] == nil {
			v["addresses"] = []string{}
		}
		items = append(items, v)
	}
	return items
}

// dnsServerChanges: the record changes the links imply. Each name that
// has a MyDC A or AAAA record gets the addresses of the linked servers in
// the DNS (A for IPv4, AAAA for IPv6); a type left without addresses is
// deleted.
func dnsServerChanges(d *store.DNSDomain, z dns.Zone, managed map[string]*store.DNSManaged, items []map[string]any) dnsChangeReq {
	var v4, v6 []string
	for _, it := range items {
		if it["state"] != "in-dns" {
			continue
		}
		for _, a := range it["addresses"].([]string) {
			if ip, err := netip.ParseAddr(a); err == nil {
				if ip.Is4() {
					v4 = append(v4, ip.String())
				} else {
					v6 = append(v6, ip.String())
				}
			}
		}
	}
	slices.Sort(v4)
	v4 = slices.Compact(v4)
	slices.Sort(v6)
	v6 = slices.Compact(v6)
	names := map[string]bool{}
	for _, m := range managed {
		if m.Type == "A" || m.Type == "AAAA" {
			names[m.Name] = true
		}
	}
	keys := make([]string, 0, len(names))
	for n := range names {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	out := dnsChangeReq{Upsert: []dns.RRSet{}, Delete: []dns.Key{}}
	for _, name := range keys {
		for _, typ := range []string{"A", "AAAA"} {
			want := v4
			if typ == "AAAA" {
				want = v6
			}
			cur := z.Find(dns.Key{Name: name, Type: typ})
			// Only MyDC's own sets: a record someone else made stays.
			if cur != nil && managed[dns.Key{Name: name, Type: typ}.String()] == nil {
				continue
			}
			if len(want) == 0 {
				if cur != nil {
					out.Delete = append(out.Delete, dns.Key{Name: name, Type: typ})
				}
				continue
			}
			have := []string{}
			ttl := d.DefaultTTL
			if cur != nil {
				ttl = cur.TTL
				for _, r := range cur.Records {
					have = append(have, r.Content)
				}
				slices.Sort(have)
			}
			if slices.Equal(have, want) {
				continue
			}
			set := dns.RRSet{Name: name, Type: typ, TTL: ttl}
			for _, a := range want {
				set.Records = append(set.Records, dns.Record{Content: a})
			}
			out.Upsert = append(out.Upsert, set)
		}
	}
	return out
}

// dnsServersView reads everything and shapes {items, revision, changes,
// staged}.
func (s *Server) dnsServersView(w http.ResponseWriter, r *http.Request, ws *webSession, a *dnsAccess, d *store.DNSDomain, p *store.DNSProvider, l *store.DNSServerLinks) (map[string]any, bool) {
	if !a.admin {
		// The gateways and server phases are the system administrator's
		// in mydcd: others see the links as saved (partial).
		out := map[string]any{"items": dnsServerItems(l, nil, false), "revision": l.Revision, "partial": true}
		return out, true
	}
	ctx, cancel := s.callCtx(r)
	nodes, err := s.dnsNodes(ctx, ws)
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return nil, false
	}
	items := dnsServerItems(l, nodes, true)
	out := map[string]any{"items": items, "revision": l.Revision}
	if len(l.Rows) == 0 {
		// Links not in use: the records stay as they are.
		out["changes"], out["staged"] = map[string]any{"upsert": []dns.RRSet{}, "delete": []dns.Key{}}, 0
		return out, true
	}
	prov, ok := s.dnsProvider(w, p)
	if !ok {
		return nil, false
	}
	zctx, zcancel := s.dnsCtx(r)
	z, err := prov.GetZone(zctx, d.Domain)
	zcancel()
	if err != nil {
		writeDNSError(w, err)
		return nil, false
	}
	managed, _ := s.opt.Store.ListDNSManaged(d.Domain)
	ch := dnsServerChanges(d, z, managed, items)
	out["changes"], out["staged"] = map[string]any{"upsert": ch.Upsert, "delete": ch.Delete}, len(ch.Upsert)+len(ch.Delete)
	return out, true
}

// dnsDomainReader: the caller may read the domain (an administrator or a
// member of an assigned workspace).
func (s *Server) dnsDomainReader(w http.ResponseWriter, r *http.Request, ws *webSession) (*dnsAccess, *store.DNSDomain, *store.DNSProvider, bool) {
	a, ok := s.dnsAccess(w, r, ws)
	if !ok {
		return nil, nil, nil, false
	}
	d, p, ok := s.loadDomain(w, r)
	if !ok {
		return nil, nil, nil, false
	}
	if !a.admin {
		if _, tenants := a.ranges(d, false); len(tenants) == 0 {
			writeError(w, http.StatusForbidden, "denied", "no access to this domain")
			return nil, nil, nil, false
		}
	}
	return a, d, p, true
}

// GET /dns/domains/{domain}/servers → {items, revision, changes?, staged?}
func (s *Server) handleDNSServers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	a, d, p, ok := s.dnsDomainReader(w, r, ws)
	if !ok {
		return
	}
	l, err := s.opt.Store.GetDNSServerLinks(d.Domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if out, ok := s.dnsServersView(w, r, ws, a, d, p, l); ok {
		writeJSON(w, http.StatusOK, out)
	}
}

// recordAddress: an address a public A/AAAA record may hold.
func recordAddress(s string) (string, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || ip.Zone() != "" {
		return "", false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return "", false
	}
	return ip.String(), true
}

// PUT /dns/domains/{domain}/servers/{node} {linked, addressSource?,
// addresses?, autoRemove?, revision} → {items, revision, changes, staged}
func (s *Server) handlePutDNSServer(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Linked        bool     `json:"linked"`
		AddressSource string   `json:"addressSource"`
		Addresses     []string `json:"addresses"`
		AutoRemove    *bool    `json:"autoRemove"`
		Revision      uint64   `json:"revision"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	a, d, p, ok := s.dnsDomainReader(w, r, ws)
	if !ok {
		return
	}
	if !a.admin {
		writeError(w, http.StatusForbidden, "denied", "linking servers to a domain needs a system administrator")
		return
	}
	node := r.PathValue("node")
	ctx, cancel := s.callCtx(r)
	nodes, err := s.dnsNodes(ctx, ws)
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	n, known := nodes[node]
	cur, _ := s.opt.Store.GetDNSServerLinks(d.Domain)
	if !known && (req.Linked || cur.Rows[node] == nil) {
		writeError(w, http.StatusNotFound, "not-found", "the server has no external gateway")
		return
	}
	row := &store.DNSServerLink{AddressSource: "node", AutoRemove: req.AutoRemove == nil || *req.AutoRemove, By: ws.user.Username, At: s.now()}
	if req.Linked {
		switch req.AddressSource {
		case "", "node":
			if len(req.Addresses) > 0 {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "addresses: with addressSource manual only")
				return
			}
			if len(n.addresses) == 0 {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "the server's external gateway has no address; give addresses (manual)")
				return
			}
		case "manual":
			row.AddressSource = "manual"
			for _, x := range req.Addresses {
				ip, ok := recordAddress(x)
				if !ok {
					writeError(w, http.StatusUnprocessableEntity, "invalid", "addresses: public IPv4 or IPv6 addresses")
					return
				}
				if !slices.Contains(row.Addresses, ip) {
					row.Addresses = append(row.Addresses, ip)
				}
			}
			if len(row.Addresses) == 0 || len(row.Addresses) > 8 {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "addresses: 1 to 8")
				return
			}
		default:
			writeError(w, http.StatusUnprocessableEntity, "invalid", "addressSource: node or manual")
			return
		}
	}
	l, err := s.opt.Store.UpdateDNSServerLinks(d.Domain, req.Revision, func(l *store.DNSServerLinks) error {
		if !req.Linked {
			if l.Rows[node] != nil && len(l.Rows) == 1 {
				return errLastServer
			}
			delete(l.Rows, node)
			return nil
		}
		if prev := l.Rows[node]; prev != nil {
			row.Reach = prev.Reach
		}
		l.Rows[node] = row
		return nil
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "stale", "the links changed; read them again")
		return
	case errors.Is(err, errLastServer):
		writeError(w, http.StatusUnprocessableEntity, "last-server", "the last server cannot be unlinked; delete the records first")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, "", "dns", "link-server", d.Domain+"/"+node, nil, map[string]any{"linked": req.Linked, "addressSource": row.AddressSource})
	if out, ok := s.dnsServersView(w, r, ws, a, d, p, l); ok {
		writeJSON(w, http.StatusOK, out)
	}
}

var errLastServer = errors.New("last server")

// POST /dns/domains/{domain}/servers/check {node?, addresses?} →
// {items:[{node, ok, at, error?}]}: a TCP connection to :443 of each
// address from here. addresses (try before saving) need an administrator.
func (s *Server) handleCheckDNSServers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Node      string   `json:"node"`
		Addresses []string `json:"addresses"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	a, d, _, ok := s.dnsDomainReader(w, r, ws)
	if !ok {
		return
	}
	if len(req.Addresses) > 0 && (!a.admin || req.Node == "" || len(req.Addresses) > 8) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "addresses: an administrator's try for one node, at most 8")
		return
	}
	l, err := s.opt.Store.GetDNSServerLinks(d.Domain)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	var nodes map[string]dnsNode
	if a.admin {
		ctx, cancel := s.callCtx(r)
		nodes, err = s.dnsNodes(ctx, ws)
		cancel()
		if err != nil {
			s.writeBackendError(w, ws, err)
			return
		}
	}
	targets := map[string][]string{}
	switch {
	case len(req.Addresses) > 0:
		for _, x := range req.Addresses {
			ip, ok := recordAddress(x)
			if !ok {
				writeError(w, http.StatusUnprocessableEntity, "invalid", "addresses: public IPv4 or IPv6 addresses")
				return
			}
			targets[req.Node] = append(targets[req.Node], ip)
		}
	case req.Node != "":
		row := l.Rows[req.Node]
		if row == nil {
			writeError(w, http.StatusNotFound, "not-found", "the server is not linked")
			return
		}
		targets[req.Node] = linkAddresses(row, nodes[req.Node])
	default:
		for name, row := range l.Rows {
			targets[name] = linkAddresses(row, nodes[name])
		}
	}
	type result struct {
		node string
		r    *store.DNSReach
	}
	res := make(chan result, len(targets))
	var wg sync.WaitGroup
	for name, addrs := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res <- result{name, s.reach(r.Context(), addrs)}
		}()
	}
	wg.Wait()
	close(res)
	reach := map[string]*store.DNSReach{}
	items := []map[string]any{}
	for x := range res {
		v := reachView(x.r)
		v["node"] = x.node
		items = append(items, v)
		if len(req.Addresses) == 0 {
			reach[x.node] = x.r
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["node"].(string) < items[j]["node"].(string) })
	if len(reach) > 0 {
		if err := s.opt.Store.SetDNSReach(d.Domain, reach); err != nil {
			s.log.Warn("dns reach", "err", err)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// reach connects to :443 of every address (all must answer).
func (s *Server) reach(ctx context.Context, addrs []string) *store.DNSReach {
	out := &store.DNSReach{OK: true, At: s.now()}
	if len(addrs) == 0 {
		out.OK, out.Error = false, "주소 없음"
		return out
	}
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a)
		if err != nil || !s.webhookAddrOK(ip) {
			out.OK, out.Error = false, a+": 공개 주소가 아님"
			return out
		}
		port := s.hooks.reachPort
		if port == "" {
			port = "443"
		}
		cctx, cancel := context.WithTimeout(ctx, dnsReachTimeout)
		var d net.Dialer
		c, err := d.DialContext(cctx, "tcp", net.JoinHostPort(ip.String(), port))
		cancel()
		if err != nil {
			out.OK, out.Error = false, a+": 연결 안 됨 (:"+port+")"
			return out
		}
		_ = c.Close()
	}
	return out
}
