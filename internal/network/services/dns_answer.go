// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/sha256"
	"net"
	"net/netip"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/miekg/dns"
)

func projectionReferences(a Authority, p dnsProjection) bool {
	for _, r := range p.Records {
		alloc, ok := a.book.Allocation(r.Allocation.Endpoint)
		if !ok || alloc != r.Allocation {
			return false
		}
	}
	return true
}
func header(name string, kind uint16, ttl uint32) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: kind, Class: dns.ClassINET, Ttl: ttl}
}
func soa(p dnsProjection, zone string, negative bool) *dns.SOA {
	ttl := p.Config.TTL
	if negative {
		ttl = p.Config.NegativeTTL
	}
	serverZone := zone
	if zone == p.ReverseZone {
		serverZone = p.Config.Zone
	}
	return &dns.SOA{Hdr: header(zone, dns.TypeSOA, ttl), Ns: "ns." + serverZone, Mbox: "hostmaster." + serverZone, Serial: p.Serial, Refresh: 60, Retry: 30, Expire: 3600, Minttl: p.Config.NegativeTTL}
}
func addressRR(name string, a netip.Addr, ttl uint32) dns.RR {
	if a.Is4() {
		return &dns.A{Hdr: header(name, dns.TypeA, ttl), A: net.IP(a.AsSlice())}
	}
	return &dns.AAAA{Hdr: header(name, dns.TypeAAAA, ttl), AAAA: net.IP(a.AsSlice())}
}
func dnsResponse(p dnsProjection, response *dns.Msg) DNSResult {
	response.Compress = true
	response.Truncate(p.Config.MaxResponseBytes)
	return DNSResult{Response: response}
}
func (m DNSManager) privateName(name string) bool {
	for _, zone := range m.protected {
		if dns.IsSubDomain(zone, name) {
			return true
		}
	}
	return false
}

type DNSResult struct {
	Response *dns.Msg
	Forward  *DNSForward
}

// Answer requires the original query pin and a fresh authority/admission view.
// The native adapter derives the origin allocation from actual interface/TUN
// provenance; it never accepts this receipt from unauthenticated packet fields.
func (m DNSManager) Answer(c access.Catalog, n tenancy.Networks, a Authority, h DNSQuery, raw []byte, now Clock, unavailable ...[]DNSAddressReference) (DNSResult, error) {
	if len(unavailable) > 1 {
		return DNSResult{}, ErrProtocol
	}
	hidden := map[DNSAddressReference]bool{}
	if len(unavailable) == 1 {
		if len(unavailable[0]) > maxRecords {
			return DNSResult{}, ErrProtocol
		}
		for _, ref := range unavailable[0] {
			if ref.Endpoint == "" || ref.Generation == 0 || hidden[ref] {
				return DNSResult{}, ErrProtocol
			}
			hidden[ref] = true
		}
	}
	v, ok := m.query(h)
	if !ok || !m.referenceActive(a, v.Projection) || m.addressBlocked(a, h.origin.Allocation) || !queryLive(h, v.Projection, now) || sha256.Sum256(raw) != h.origin.Request || !freshDNSProjection(c, n, a, v.Projection) || !originAllowed(a, v.Projection, h.origin.Allocation, now) {
		return DNSResult{}, ErrProtocol
	}
	p := v.Projection
	request, e := DecodeDNSQuery(raw, min(p.Config.MaxResponseBytes, 4096))
	if e != nil {
		return DNSResult{}, e
	}
	q := request.Question[0]
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = len(p.Config.Upstreams) > 0
	zone := ""
	for _, z := range []string{p.Config.ClientZone, p.Config.Zone, p.ReverseZone} {
		if z != "" && dns.IsSubDomain(z, q.Name) && (zone == "" || len(z) > len(zone)) {
			zone = z
		}
	}
	if zone == "" {
		if m.privateName(q.Name) || len(p.Config.Upstreams) == 0 || !request.RecursionDesired {
			response.Rcode = dns.RcodeRefused
			return dnsResponse(p, response), nil
		}
		if cached, hit := m.cached(h.view, q, request.Id, now); hit {
			return DNSResult{Response: cached}, nil
		}
		wire, e := request.Pack()
		if e != nil {
			return DNSResult{}, ErrProtocol
		}
		return DNSResult{Forward: &DNSForward{handle: h, question: q, clientID: request.Id, wire: wire, upstreams: slices.Clone(p.Config.Upstreams), maxBytes: p.Config.MaxResponseBytes}}, nil
	}
	response.Authoritative = true
	exists := q.Name == zone
	serverZone := zone
	if zone == p.ReverseZone {
		serverZone = p.Config.Zone
	}
	if q.Name == zone {
		switch q.Qtype {
		case dns.TypeSOA:
			response.Answer = append(response.Answer, soa(p, zone, false))
		case dns.TypeNS:
			response.Answer = append(response.Answer, &dns.NS{Hdr: header(zone, dns.TypeNS, p.Config.TTL), Ns: "ns." + serverZone})
		}
	}
	if q.Name == "ns."+zone && zone != p.ReverseZone {
		exists = true
		for _, member := range p.Members {
			if q.Qtype == dns.TypeA && member.Gateway.Is4() || q.Qtype == dns.TypeAAAA && member.Gateway.Is6() {
				response.Answer = append(response.Answer, addressRR(q.Name, member.Gateway, p.Config.TTL))
			}
		}
	}
	for _, r := range p.Records {
		name := r.Name
		if zone == p.ReverseZone {
			if !p.Local.Prefix.Contains(r.Address) {
				continue
			}
			name, e = dns.ReverseAddr(r.Address.String())
			if e != nil {
				return DNSResult{}, ErrProtocol
			}
		}
		if !dns.IsSubDomain(zone, name) || !dns.IsSubDomain(q.Name, name) {
			continue
		}
		if hidden[DNSAddressReference{Endpoint: r.Allocation.Endpoint, Generation: r.Allocation.Generation}] {
			exists = true // reserved name with no currently available address
			continue
		}
		alloc, held := a.book.Allocation(r.Allocation.Endpoint)
		if !held || alloc != r.Allocation || m.addressBlocked(a, r.Allocation) {
			response.Answer = nil
			response.Rcode = dns.RcodeServerFailure
			return dnsResponse(p, response), nil
		}
		ttl := p.Config.TTL
		exists = true
		if name != q.Name {
			continue
		}
		switch {
		case zone == p.ReverseZone && q.Qtype == dns.TypePTR:
			response.Answer = append(response.Answer, &dns.PTR{Hdr: header(name, dns.TypePTR, ttl), Ptr: r.Name})
		case zone != p.ReverseZone && (q.Qtype == dns.TypeA && r.Address.Is4() || q.Qtype == dns.TypeAAAA && r.Address.Is6()):
			response.Answer = append(response.Answer, addressRR(name, r.Address, ttl))
		}
	}
	if !exists {
		response.Rcode = dns.RcodeNameError
	}
	if len(response.Answer) == 0 {
		response.Ns = []dns.RR{soa(p, zone, true)}
	}
	return dnsResponse(p, response), nil
}

// DNSForward/Exchange bind the response to the original view, query and selected
// configured peer. The native miekg client supplies a fresh dns.Id() exchange ID.
type DNSForward struct {
	handle    DNSQuery
	question  dns.Question
	clientID  uint16
	wire      []byte
	upstreams []netip.AddrPort
	maxBytes  int
}
type DNSExchange struct {
	plan DNSForward
	id   uint16
	peer netip.AddrPort
}

func (p DNSForward) Upstreams() []netip.AddrPort { return slices.Clone(p.upstreams) }
func (p DNSForward) Exchange(peer netip.AddrPort, exchangeID uint16) (DNSExchange, error) {
	if !slices.Contains(p.upstreams, peer) {
		return DNSExchange{}, ErrProtocol
	}
	p.wire = slices.Clone(p.wire)
	p.upstreams = slices.Clone(p.upstreams)
	return DNSExchange{p, exchangeID, peer}, nil
}
func (e DNSExchange) Request() (*dns.Msg, error) {
	q := new(dns.Msg)
	if q.Unpack(e.plan.wire) != nil {
		return nil, ErrProtocol
	}
	q.Id = e.id
	// Upstream and client are separate transactions. Advertise OUR original
	// view's bounded receive size and never forward a client's OPT/options.
	q.Extra = nil
	q.SetEdns0(uint16(e.plan.maxBytes), false)
	return q, nil
}
func (m DNSManager) FinishForward(c access.Catalog, n tenancy.Networks, a Authority, e DNSExchange, peer netip.AddrPort, raw []byte, now Clock) (*dns.Msg, error) {
	v, ok := m.query(e.plan.handle)
	if !ok || !m.referenceActive(a, v.Projection) || m.addressBlocked(a, e.plan.handle.origin.Allocation) || !queryLive(e.plan.handle, v.Projection, now) || peer != e.peer || !slices.Contains(v.Projection.Config.Upstreams, peer) || !freshDNSProjection(c, n, a, v.Projection) || !originAllowed(a, v.Projection, e.plan.handle.origin.Allocation, now) || m.privateName(e.plan.question.Name) || len(raw) > e.plan.maxBytes {
		return nil, ErrProtocol
	}
	r := new(dns.Msg)
	if r.Unpack(raw) != nil || !r.Response || r.Opcode != dns.OpcodeQuery || r.Id != e.id || r.Truncated || len(r.Question) != 1 || r.Question[0].Qtype != e.plan.question.Qtype || r.Question[0].Qclass != dns.ClassINET || r.Rcode != dns.RcodeSuccess && r.Rcode != dns.RcodeNameError {
		return nil, ErrProtocol
	}
	name, err := Domain(r.Question[0].Name)
	if err != nil || name != e.plan.question.Name {
		return nil, ErrProtocol
	}
	// Follow only a bounded CNAME chain for this question. Never expose an
	// upstream's unrelated or now-private answer/additional data to a tenant.
	allowed := map[string]bool{name: true}
	edges := map[string]string{}
	next := name
	for i := 0; i < 8; i++ {
		found := false
		for _, rr := range r.Answer {
			cname, ok := rr.(*dns.CNAME)
			if !ok {
				continue
			}
			owner, er := Domain(cname.Hdr.Name)
			if er != nil {
				return nil, ErrProtocol
			}
			if owner != next {
				continue
			}
			target, er := Domain(cname.Target)
			if er != nil || m.privateName(target) || allowed[target] {
				return nil, ErrProtocol
			}
			allowed[target] = true
			edges[owner] = target
			next = target
			found = true
			break
		}
		if !found {
			break
		}
	}
	seenCNAME := map[string]bool{}
	for _, rr := range r.Answer {
		owner, er := Domain(rr.Header().Name)
		if er != nil || !allowed[owner] || m.privateName(owner) || rr.Header().Class != dns.ClassINET || rr.Header().Rrtype != e.plan.question.Qtype && rr.Header().Rrtype != dns.TypeCNAME {
			return nil, ErrProtocol
		}
		if cname, ok := rr.(*dns.CNAME); ok {
			target, er := Domain(cname.Target)
			if er != nil || edges[owner] != target || seenCNAME[owner] {
				return nil, ErrProtocol
			}
			seenCNAME[owner] = true
		} else if edges[owner] != "" {
			return nil, ErrProtocol
		}
	}
	if len(r.Ns) > 1 {
		return nil, ErrProtocol
	}
	for _, rr := range r.Ns {
		soa, ok := rr.(*dns.SOA)
		if !ok {
			return nil, ErrProtocol
		}
		zone, er := Domain(soa.Hdr.Name)
		if er != nil || soa.Hdr.Class != dns.ClassINET || !dns.IsSubDomain(zone, next) || m.privateName(zone) {
			return nil, ErrProtocol
		}
	}
	r.Id = e.plan.clientID
	r.Question = []dns.Question{e.plan.question}
	r.Extra = nil
	r.AuthenticatedData = false
	r.CheckingDisabled = false
	r.Authoritative = false
	r.RecursionAvailable = true
	maximum := v.Projection.Config.TTL
	if r.Rcode == dns.RcodeNameError || len(r.Answer) == 0 {
		maximum = min(maximum, v.Projection.Config.NegativeTTL)
	}
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, rr := range section {
			rr.Header().Ttl = min(rr.Header().Ttl, maximum)
			if soa, ok := rr.(*dns.SOA); ok {
				soa.Minttl = min(soa.Minttl, v.Projection.Config.NegativeTTL)
			}
		}
	}
	return r, nil
}
