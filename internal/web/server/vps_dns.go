// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/dns"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Temporary DNS change for a stopped VPS server (devel/design/vps-nodes.md
// §5a, web-own). Each automation round reads the VPS page. A server that is
// stopping, stopped or stopped for its cap has its addresses taken out of
// the Seafield Cluster A/AAAA sets of every external domain it is a linked server of;
// the sets as they were after that are kept in web bbolt (VPSDNSHold). When
// the server runs again the addresses go back into each set that is still
// as it was left; a set someone changed is not overwritten and stays listed
// until an administrator dismisses it. A server's last address in a set is
// never taken out. When the server is gone from the page (deleted) its
// holds are dropped and it is unlinked from the domains (not put back).
// The domain's linked-server settings do not change otherwise.
//
// The automation account must be able to read the VPS page (system
// administrator); otherwise nothing is changed and GET /system/vps shows
// dnsAuto:false.

const vpsDNSEvery = time.Minute

type vpsDNSState struct {
	mu     sync.Mutex
	polled time.Time
	// ok: the last round could read the VPS page (shown as dnsAuto).
	ok bool
	// failed: when a withdrawal last failed per server/domain, so the
	// failure is told once an hour, not every round.
	failed map[string]time.Time
}

// vpsWithdrawn: phases in which the server's addresses are out of DNS.
func vpsWithdrawn(phase string) bool {
	return phase == control.VPSStopping || phase == control.VPSStopped || phase == control.VPSCapped
}

// vpsDNSAddresses: the addresses of server in a domain's link (its manual
// list, else what its external gateway binds), else its public IP.
func vpsDNSAddresses(row *store.DNSServerLink, n dnsNode, publicIP string) []string {
	addrs := slices.Clone(linkAddresses(row, n))
	if len(addrs) == 0 && publicIP != "" {
		addrs = []string{publicIP}
	}
	out := []string{}
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			out = append(out, ip.String())
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// vpsDNSRow is one record set in the stop dialog: what stopping does to it.
type vpsDNSRow struct {
	Domain  string `json:"domain"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	TTL     int    `json:"ttl"`
	Outcome string `json:"outcome"` // withdraw, keep-last
	Others  int    `json:"others"`  // addresses left in the set
}

// vpsDNSWithdraw is the change for one domain: the sets without the
// server's addresses (upsert), the hold to keep and the dialog rows.
type vpsDNSWithdraw struct {
	upsert []dns.RRSet
	hold   store.VPSDNSHold
	rows   []vpsDNSRow
}

func vpsDNSPlanDomain(d *store.DNSDomain, z dns.Zone, managed map[string]*store.DNSManaged, server string, addrs []string) vpsDNSWithdraw {
	out := vpsDNSWithdraw{hold: store.VPSDNSHold{Server: server, Domain: d.Domain}}
	keys := []string{}
	for k, m := range managed {
		if m.Type == "A" || m.Type == "AAAA" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		m := managed[k]
		cur := z.Find(dns.Key{Name: m.Name, Type: m.Type})
		if cur == nil || dns.Fingerprint(cur) != m.Fingerprint && m.Fingerprint != "" {
			continue // gone, or changed outside Seafield Cluster since it wrote it
		}
		var keep []dns.Record
		var removed []string
		for _, r := range cur.Records {
			if slices.Contains(addrs, canonicalIP(r.Content)) {
				removed = append(removed, r.Content)
			} else {
				keep = append(keep, r)
			}
		}
		if len(removed) == 0 {
			continue
		}
		row := vpsDNSRow{Domain: d.Domain, Name: m.Name, Type: m.Type, Value: strings.Join(removed, ", "), TTL: cur.TTL, Others: len(keep)}
		if len(keep) == 0 {
			row.Outcome = "keep-last"
			out.hold.Kept = append(out.hold.Kept, store.VPSDNSKept{Name: m.Name, Type: m.Type})
			out.rows = append(out.rows, row)
			continue
		}
		row.Outcome = "withdraw"
		set := dns.RRSet{Name: cur.Name, Type: cur.Type, TTL: cur.TTL, Records: keep}
		out.upsert = append(out.upsert, set)
		out.hold.Sets = append(out.hold.Sets, store.VPSDNSSet{Name: m.Name, Type: m.Type, Removed: removed, After: dns.Fingerprint(&set)})
		out.rows = append(out.rows, row)
	}
	return out
}

func canonicalIP(s string) string {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.String()
	}
	return s
}

// vpsDNSDomain is a domain the server is linked to, with what is needed to
// change it.
type vpsDNSDomain struct {
	d       *store.DNSDomain
	prov    dns.Provider
	links   *store.DNSServerLinks
	row     *store.DNSServerLink
	managed map[string]*store.DNSManaged
	z       dns.Zone
	err     string // why it cannot be changed (no-provider, provider error)
}

// vpsDNSDomains: the domains server is a linked server of. A domain whose
// provider cannot be opened or read is returned with err set.
func (s *Server) vpsDNSDomains(ctx context.Context, server string, want func(domain string) bool) ([]vpsDNSDomain, error) {
	ds, err := s.opt.Store.ListDNSDomains()
	if err != nil {
		return nil, err
	}
	var out []vpsDNSDomain
	for _, d := range ds {
		links, err := s.opt.Store.GetDNSServerLinks(d.Domain)
		if err != nil {
			return nil, err
		}
		row := links.Rows[server]
		if row == nil || want != nil && !want(d.Domain) {
			continue
		}
		v := vpsDNSDomain{d: d, links: links, row: row}
		p, err := s.opt.Store.GetDNSProvider(d.Provider)
		if err == nil {
			v.prov, err = s.openDNSProvider(p)
		}
		if err == nil {
			v.z, err = v.prov.GetZone(ctx, d.Domain)
		}
		if err != nil {
			v.err = "provider"
			if errors.Is(err, store.ErrNotFound) {
				v.err = "no-provider"
			}
			out = append(out, v)
			continue
		}
		v.managed, _ = s.opt.Store.ListDNSManaged(d.Domain)
		out = append(out, v)
	}
	return out, nil
}

// openDNSProvider is dnsProvider without an HTTP answer.
func (s *Server) openDNSProvider(p *store.DNSProvider) (dns.Provider, error) {
	tok, err := s.opt.Seal.Get(dnsSecretName(p.ID))
	if err != nil {
		return nil, err
	}
	return s.opt.DNS.Open(p.Vendor, p.ID, string(tok))
}

// vpsDNSApply applies one change as the VPS automation and records it in
// the domain's history and the managed marks. It returns the history ID.
func (s *Server) vpsDNSApply(ctx context.Context, ws *webSession, v vpsDNSDomain, upsert []dns.RRSet, label string) (string, error) {
	h := &store.DNSHistory{ID: newOpID(), Domain: v.d.Domain, At: s.now(), User: ws.user.ID, Username: ws.user.Username, Result: "unknown", Digest: label}
	for i := range upsert {
		before := v.z.Find(upsert[i].Key())
		h.Changes = append(h.Changes, store.DNSChange{Name: upsert[i].Name, Type: upsert[i].Type, Before: mustJSON(before), After: mustJSON(&upsert[i])})
	}
	if err := s.opt.Store.PutDNSHistory(h); err != nil {
		return "", err
	}
	res, err := v.prov.Apply(ctx, v.d.Domain, dns.ChangeSet{Upsert: upsert, Delete: []dns.Key{}})
	if err != nil {
		h.Result, h.Error = "failed", string(dns.KindOf(err))
		if dns.KindOf(err) == dns.Unavailable {
			h.Result = "unknown"
		}
		_ = s.opt.Store.PutDNSHistory(h)
		return h.ID, err
	}
	h.Result, h.Snapshot = "applied", res.Snapshot
	_ = s.opt.Store.PutDNSHistory(h)
	var set []*store.DNSManaged
	for i := range upsert {
		m := v.managed[upsert[i].Key().String()]
		nm := &store.DNSManaged{Domain: v.d.Domain, Name: upsert[i].Name, Type: upsert[i].Type, By: ws.user.Username, Fingerprint: dns.Fingerprint(&upsert[i]), At: s.now()}
		if m != nil {
			nm.Tenant, nm.App = m.Tenant, m.App
		}
		set = append(set, nm)
	}
	_ = s.opt.Store.ApplyDNSManaged(v.d.Domain, set, nil)
	return h.ID, nil
}

// vpsDNSPoll runs one round as ws (the watcher's automation session).
func (s *Server) vpsDNSPoll(ctx context.Context, ws *webSession) {
	st := &s.vpsDNS
	now := s.now()
	st.mu.Lock()
	due := now.Sub(st.polled) >= vpsDNSEvery
	if due {
		st.polled = now
	}
	st.mu.Unlock()
	if !due {
		return
	}
	var page control.VPSPage
	var nodes map[string]dnsNode
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		page, err = c.QueryVPS(ctx)
		return err
	})
	st.mu.Lock()
	st.ok = err == nil
	st.mu.Unlock()
	if err != nil {
		return
	}
	holds, err := s.opt.Store.ListVPSDNSHolds()
	if err != nil {
		s.log.Error("vps dns: holds", "err", err)
		return
	}
	held := map[string]map[string]*store.VPSDNSHold{}
	for _, h := range holds {
		if held[h.Server] == nil {
			held[h.Server] = map[string]*store.VPSDNSHold{}
		}
		held[h.Server][h.Domain] = h
	}
	servers := map[string]control.VPSServer{}
	for _, v := range page.Servers {
		servers[v.Name] = v
	}
	for _, v := range page.Servers {
		switch {
		case vpsWithdrawn(v.Phase):
			if nodes == nil {
				if nodes, err = s.dnsNodes(ctx, ws); err != nil {
					s.log.Warn("vps dns: gateways", "err", err)
					return
				}
			}
			s.vpsDNSWithdrawServer(ctx, ws, v, nodes[v.Name], held[v.Name])
		case v.Phase == control.VPSRunning && len(held[v.Name]) > 0:
			s.vpsDNSRestoreServer(ctx, ws, v, held[v.Name])
		}
	}
	for name, hs := range held {
		if _, ok := servers[name]; ok {
			continue
		}
		for domain := range hs {
			_ = s.opt.Store.DeleteVPSDNSHold(name, domain)
			l, err := s.opt.Store.GetDNSServerLinks(domain)
			if err == nil && l.Rows[name] != nil {
				_, _ = s.opt.Store.UpdateDNSServerLinks(domain, l.Revision, func(l *store.DNSServerLinks) error {
					delete(l.Rows, name)
					return nil
				})
			}
		}
	}
}

func (s *Server) vpsDNSWithdrawServer(ctx context.Context, ws *webSession, v control.VPSServer, n dnsNode, held map[string]*store.VPSDNSHold) {
	domains, err := s.vpsDNSDomains(ctx, v.Name, func(domain string) bool { return held[domain] == nil || held[domain].Request != v.PowerRequest })
	if err != nil {
		s.log.Error("vps dns: domains", "err", err)
		return
	}
	for _, dom := range domains {
		if dom.err != "" {
			continue
		}
		p := vpsDNSPlanDomain(dom.d, dom.z, dom.managed, v.Name, vpsDNSAddresses(dom.row, n, v.PublicIP))
		p.hold.At, p.hold.Request = s.now(), v.PowerRequest
		if old := held[dom.d.Domain]; old != nil {
			// left from an earlier stop: still to put back, or not put back
			p.hold.Blocked = old.Blocked
			for _, set := range old.Sets {
				if !slices.ContainsFunc(p.hold.Sets, func(x store.VPSDNSSet) bool { return x.Name == set.Name && x.Type == set.Type }) {
					p.hold.Sets = append(p.hold.Sets, set)
				}
			}
		}
		if len(p.upsert) > 0 {
			id, err := s.vpsDNSApply(ctx, ws, dom, p.upsert, "vps-stop:"+v.Name)
			if err != nil {
				if !s.vpsDNSFailed(v.Name + "\x00" + dom.d.Domain) {
					continue
				}
				s.notify(&store.Notification{User: dom.row.By, Kind: NotifyOpFailed, Severity: "error", Text: notice("vps-dns-failed", map[string]string{"domain": dom.d.Domain, "vps": v.Name, "kind": string(dns.KindOf(err))}, "vps-dns-failed.body"),
					Link: "/dns/" + dom.d.Domain})
				continue
			}
			p.hold.History = id
		}
		if err := s.opt.Store.PutVPSDNSHold(&p.hold); err != nil {
			s.log.Error("vps dns: hold", "err", err)
			continue
		}
		body := notice("vps-stopped", map[string]string{"domain": dom.d.Domain, "vps": v.Name, "sets": itoa(len(p.hold.Sets)), "kept": itoa(len(p.hold.Kept))},
			append([]string{"vps-stopped.body"}, bodyIf(len(p.hold.Kept) > 0, "vps-stopped.kept")...)...)
		if len(p.hold.Sets)+len(p.hold.Kept) > 0 {
			s.notify(&store.Notification{User: dom.row.By, Kind: NotifyVPSDNS, Severity: "info", Text: body, Link: "/nodes/vps"})
		}
	}
}

// vpsDNSReachWait: how long after a VPS server runs again its addresses
// wait for the outside reach check; after that they go back anyway (the
// web daemon may not reach the internet itself).
const vpsDNSReachWait = 10 * time.Minute

// vpsDNSReady: the addresses taken out for v may go back: the server runs
// and its addresses answer from outside (the linked-server reach check on
// :443), or vpsDNSReachWait passed since it began to run.
func (s *Server) vpsDNSReady(ctx context.Context, v control.VPSServer, held map[string]*store.VPSDNSHold) bool {
	if s.now().Sub(time.Unix(v.PhaseAt, 0)) >= vpsDNSReachWait {
		return true
	}
	var addrs []string
	for _, h := range held {
		for _, set := range h.Sets {
			for _, a := range set.Removed {
				addrs = append(addrs, canonicalIP(a))
			}
		}
	}
	slices.Sort(addrs)
	addrs = slices.Compact(addrs)
	if len(addrs) == 0 {
		return true
	}
	if s.hooks.vpsReach != nil {
		return s.hooks.vpsReach(ctx, addrs)
	}
	return s.reach(ctx, addrs).OK
}

func (s *Server) vpsDNSRestoreServer(ctx context.Context, ws *webSession, v control.VPSServer, held map[string]*store.VPSDNSHold) {
	if !s.vpsDNSReady(ctx, v, held) {
		return // the next round checks again
	}
	domains, err := s.vpsDNSDomains(ctx, v.Name, func(domain string) bool { return held[domain] != nil && len(held[domain].Sets) > 0 })
	if err != nil {
		s.log.Error("vps dns: domains", "err", err)
		return
	}
	byName := map[string]vpsDNSDomain{}
	for _, d := range domains {
		byName[d.d.Domain] = d
	}
	for domain, h := range held {
		if len(h.Sets) == 0 {
			if len(h.Blocked) == 0 {
				_ = s.opt.Store.DeleteVPSDNSHold(v.Name, domain)
			}
			continue
		}
		dom, ok := byName[domain]
		if !ok {
			// unlinked meanwhile: nothing to put back.
			_ = s.opt.Store.DeleteVPSDNSHold(v.Name, domain)
			continue
		}
		if dom.err != "" {
			continue // try again next round
		}
		var upsert []dns.RRSet
		blocked := slices.Clone(h.Blocked)
		for _, set := range h.Sets {
			cur := dom.z.Find(dns.Key{Name: set.Name, Type: set.Type})
			if cur == nil || dns.Fingerprint(cur) != set.After {
				blocked = append(blocked, set)
				continue
			}
			back := *cur
			back.Records = slices.Clone(cur.Records)
			for _, a := range set.Removed {
				back.Records = append(back.Records, dns.Record{Content: a})
			}
			upsert = append(upsert, back)
		}
		if len(upsert) > 0 {
			if _, err := s.vpsDNSApply(ctx, ws, dom, upsert, "vps-start:"+v.Name); err != nil {
				continue // the hold stays; try again next round
			}
		}
		if len(blocked) == 0 {
			_ = s.opt.Store.DeleteVPSDNSHold(v.Name, domain)
			continue
		}
		h.Sets, h.Blocked = nil, blocked
		_ = s.opt.Store.PutVPSDNSHold(h)
		names := []string{}
		for _, b := range blocked {
			names = append(names, b.Name+" "+b.Type)
		}
		s.notify(&store.Notification{User: dom.row.By, Kind: NotifyVPSDNS, Severity: "warning", Action: true, Text: notice("vps-restore-failed", map[string]string{"domain": domain, "vps": v.Name, "records": strings.Join(names, ", ")}, "vps-restore-failed.body"),
			Link: "/dns/" + domain})
	}
}

// vpsDNSHoldView is a server's holds as GET /system/vps shows them.
type vpsDNSHoldView struct {
	Domain  string             `json:"domain"`
	At      time.Time          `json:"at"`
	Sets    []store.VPSDNSSet  `json:"sets"`
	Kept    []store.VPSDNSKept `json:"kept"`
	Blocked []store.VPSDNSSet  `json:"blocked"`
}

func (s *Server) vpsDNSHoldViews() map[string][]vpsDNSHoldView {
	out := map[string][]vpsDNSHoldView{}
	holds, err := s.opt.Store.ListVPSDNSHolds()
	if err != nil {
		return out
	}
	for _, h := range holds {
		if len(h.Sets)+len(h.Kept)+len(h.Blocked) == 0 {
			continue // linked, but no record had its address
		}
		out[h.Server] = append(out[h.Server], vpsDNSHoldView{Domain: h.Domain, At: h.At, Sets: nonNil(h.Sets), Kept: nonNil(h.Kept), Blocked: nonNil(h.Blocked)})
	}
	return out
}

// vpsDNSFailed records a failed withdrawal and reports whether to tell
// about it (once an hour per server and domain).
func (s *Server) vpsDNSFailed(key string) bool {
	st := &s.vpsDNS
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.failed == nil {
		st.failed = map[string]time.Time{}
	}
	now := s.now()
	if at, ok := st.failed[key]; ok && now.Sub(at) < time.Hour {
		return false
	}
	st.failed[key] = now
	return true
}

func (s *Server) vpsDNSAuto() bool {
	s.vpsDNS.mu.Lock()
	defer s.vpsDNS.mu.Unlock()
	return s.vpsDNS.ok
}

// GET /system/vps/servers/{name}/dns-plan → {rows[], waitSeconds} for the
// stop dialog: each Seafield Cluster A/AAAA set of the server's linked domains with
// what stopping does to it, and the longest TTL among the sets taken out
// (send it as dnsWaitSeconds). A domain that cannot be read is a row with
// outcome "manual".
func (s *Server) handleVPSDNSPlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	name := r.PathValue("name")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var page control.VPSPage
	var nodes map[string]dnsNode
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		page, err = c.QueryVPS(ctx)
		return err
	})
	if err == nil {
		nodes, err = s.dnsNodes(ctx, ws)
	}
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	v, err := vpsServerOf(page, name)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	domains, err := s.vpsDNSDomains(ctx, name, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	rows := []vpsDNSRow{}
	wait := 0
	for _, d := range domains {
		if d.err != "" {
			rows = append(rows, vpsDNSRow{Domain: d.d.Domain, Outcome: "manual", Value: strings.Join(vpsDNSAddresses(d.row, nodes[name], v.PublicIP), ", ")})
			continue
		}
		p := vpsDNSPlanDomain(d.d, d.z, d.managed, name, vpsDNSAddresses(d.row, nodes[name], v.PublicIP))
		for _, row := range p.rows {
			if row.Outcome == "withdraw" && row.TTL > wait {
				wait = row.TTL
			}
		}
		rows = append(rows, p.rows...)
	}
	if wait == 0 {
		wait = control.VPSCapDNSWait
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "waitSeconds": min(wait, control.MaxVPSDNSWait), "dnsAuto": s.vpsDNSAuto()})
}

// DELETE /system/vps/servers/{name}/dns-holds/{domain} ("이대로 둠"):
// forget the records that were not put back. The zone is not changed.
func (s *Server) handleVPSDNSDismiss(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if !s.requireAdmin(w, r, ws) {
		return
	}
	name, domain := r.PathValue("name"), r.PathValue("domain")
	holds, err := s.opt.Store.ListVPSDNSHolds()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, h := range holds {
		if h.Server == name && h.Domain == domain {
			if len(h.Sets) > 0 {
				writeError(w, http.StatusConflict, "held", "the records are still taken out for the stopped server")
				return
			}
			_ = s.opt.Store.DeleteVPSDNSHold(name, domain)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
	}
	writeError(w, http.StatusNotFound, "not-found", "no such record")
}
