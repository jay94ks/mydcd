// SPDX-License-Identifier: Apache-2.0

package services

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/tenancy"
	"github.com/miekg/dns"
)

type dnsCacheKey struct {
	View [32]byte
	Name string
	Type uint16
}
type dnsCacheEntry struct {
	Wire string
	At   Clock
	TTL  uint32
}

func (m DNSManager) CacheEntries() int { return len(m.cache) }
func (m DNSManager) cached(view [32]byte, q dns.Question, id uint16, now Clock) (*dns.Msg, bool) {
	entry, ok := m.cache[dnsCacheKey{view, q.Name, q.Qtype}]
	if !ok {
		return nil, false
	}
	_, certain := elapsed(entry.At, now)
	if !certain {
		return nil, false
	}
	age := max(now.Wall-entry.At.Wall, now.Mono-entry.At.Mono)
	if age >= int64(entry.TTL) {
		return nil, false
	}
	r := new(dns.Msg)
	if r.Unpack([]byte(entry.Wire)) != nil {
		return nil, false
	}
	r.Id = id
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, rr := range section {
			if m.privateName(rr.Header().Name) {
				return nil, false
			}
			if cname, ok := rr.(*dns.CNAME); ok && m.privateName(cname.Target) {
				return nil, false
			}
		}
	}
	for _, section := range [][]dns.RR{r.Answer, r.Ns} {
		for _, rr := range section {
			if rr.Header().Ttl <= uint32(age) {
				return nil, false
			}
			rr.Header().Ttl -= uint32(age)
		}
	}
	return r, true
}
func cacheKeyCompare(a, b dnsCacheKey) int {
	if c := bytes.Compare(a.View[:], b.View[:]); c != 0 {
		return c
	}
	if a.Name != b.Name {
		return strings.Compare(a.Name, b.Name)
	}
	return int(a.Type) - int(b.Type)
}

// CompleteForward validates the actual configured peer/response first, then
// creates a bounded cache candidate. Cache is derived, node-local and volatile;
// the lifecycle snapshot intentionally does not restore it across a reboot.
func (m DNSManager) CompleteForward(c access.Catalog, n tenancy.Networks, a Authority, e DNSExchange, peer netip.AddrPort, raw []byte, now Clock) (DNSManager, *dns.Msg, error) {
	r, err := m.FinishForward(c, n, a, e, peer, raw, now)
	if err != nil {
		return m, nil, err
	}
	v, _ := m.query(e.plan.handle)
	cfg := v.Projection.Config
	if cfg.MaxCacheEntries == 0 || !validClock(now) {
		return m, r, nil
	}
	stored := r.Copy()
	ttl := cfg.TTL
	if stored.Rcode == dns.RcodeNameError || len(stored.Answer) == 0 {
		if len(stored.Ns) != 1 {
			return m, r, nil
		}
		soa, ok := stored.Ns[0].(*dns.SOA)
		if !ok {
			return m, r, nil
		}
		ttl = min(ttl, cfg.NegativeTTL, soa.Hdr.Ttl, soa.Minttl)
	}
	for _, rr := range stored.Answer {
		ttl = min(ttl, rr.Header().Ttl)
	}
	if ttl == 0 {
		return m, r, nil
	}
	for _, section := range [][]dns.RR{stored.Answer, stored.Ns} {
		for _, rr := range section {
			rr.Header().Ttl = min(rr.Header().Ttl, ttl)
		}
	}
	stored.Id = 0
	stored.Compress = true
	wire, err := stored.Pack()
	if err != nil || len(wire) > cfg.MaxResponseBytes {
		return m, r, nil
	}
	key := dnsCacheKey{e.plan.handle.view, e.plan.question.Name, e.plan.question.Qtype}
	q := m.clone()
	q.cache[key] = dnsCacheEntry{string(wire), now, ttl}
	// Per-view entry bounds and an owner-wide 4MiB/4096-entry ceiling. Retain
	// the just-admitted response even when multiple completions share a Clock
	// second; the deterministic name tie-break applies to prior entries only.
	// Eviction has no ownership effect or lease/view generation changes.
	for {
		count, total := 0, 0
		for k, v := range q.cache {
			if k.View == key.View {
				count++
			}
			total += len(v.Wire)
		}
		if count <= cfg.MaxCacheEntries && len(q.cache) <= 4096 && total <= 4<<20 {
			break
		}
		keys := []dnsCacheKey{}
		for k := range q.cache {
			if k == key {
				continue
			}
			if count > cfg.MaxCacheEntries && k.View != key.View {
				continue
			}
			keys = append(keys, k)
		}
		slices.SortFunc(keys, func(a, b dnsCacheKey) int {
			if q.cache[a].At.Wall < q.cache[b].At.Wall {
				return -1
			}
			if q.cache[a].At.Wall > q.cache[b].At.Wall {
				return 1
			}
			return cacheKeyCompare(a, b)
		})
		if len(keys) == 0 {
			break
		}
		delete(q.cache, keys[0])
	}
	return q, r, nil
}
