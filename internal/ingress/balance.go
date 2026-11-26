// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// Balance is declarative. Entropy, request identity and observation time enter
// through Selection; the selection core never reads a clock or randomness.
type Balance struct {
	Method           string                  `json:",omitempty" yaml:"method,omitempty"`
	Key              string                  `json:",omitempty" yaml:"key,omitempty"`
	Locality         string                  `json:",omitempty" yaml:"locality,omitempty"`
	SlowStartMS      int                     `json:",omitempty" yaml:"slow_start_ms,omitempty"`
	SlowStartSeconds int                     `json:",omitempty" yaml:"slow_start,omitempty"`
	Retry            int                     `json:",omitempty" yaml:"retry,omitempty"`
	Weights          map[string]int          `json:",omitempty" yaml:"weights,omitempty"`
	Groups           map[string]BackendGroup `json:",omitempty" yaml:"groups,omitempty"`
	Match            []BalanceCondition      `json:",omitempty" yaml:"match,omitempty"`
	Fallback         string                  `json:",omitempty" yaml:"fallback,omitempty"`
}
type BackendGroup struct {
	Labels   map[string]string `json:",omitempty" yaml:"labels,omitempty"`
	Version  string            `json:",omitempty" yaml:"version,omitempty"`
	Backends []string          `json:",omitempty" yaml:"backends,omitempty"`
}
type ValueMatch struct {
	Equal   *string `json:",omitempty" yaml:"equal,omitempty"`
	Prefix  *string `json:",omitempty" yaml:"prefix,omitempty"`
	Present bool    `json:",omitempty" yaml:"present,omitempty"`
}
type BalanceCondition struct {
	ID      string                `yaml:"id"`
	Group   string                `yaml:"group"`
	Headers map[string]ValueMatch `json:",omitempty" yaml:"headers,omitempty"`
	Cookies map[string]ValueMatch `json:",omitempty" yaml:"cookies,omitempty"`
	Query   map[string]ValueMatch `json:",omitempty" yaml:"query,omitempty"`
	Methods []string              `json:",omitempty" yaml:"methods,omitempty"`
	Sources []netip.Prefix        `json:",omitempty" yaml:"sources,omitempty"`
	Percent *int                  `json:",omitempty" yaml:"percent,omitempty"`
	Key     string                `json:",omitempty" yaml:"key,omitempty"`
}
type Selection struct {
	Node                    string
	Source                  netip.Addr
	Method                  string
	Headers, Cookies, Query map[string]string
	Backends                map[string]BackendSpec
	Exclude                 map[string]bool
	Entropy                 uint64
	Group, Condition        string
}

func tokenName(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for _, c := range v {
		if c > 127 || !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
			return false
		}
	}
	return true
}
func balanceKey(v string) bool {
	if v == "" || v == "source-ip" {
		return true
	}
	kind, name, ok := strings.Cut(v, ":")
	return ok && (kind == "cookie" || kind == "header") && tokenName(name)
}
func (p Balance) Validate() error {
	if p.SlowStartSeconds < 0 || p.SlowStartSeconds > 3600 || p.SlowStartSeconds != 0 && p.SlowStartMS != 0 {
		return ErrRoute
	}
	if p.Method != "" && p.Method != "round-robin" && p.Method != "least-request" && p.Method != "hash" && p.Method != "random" || !balanceKey(p.Key) || p.Method == "hash" && p.Key == "" || p.Locality != "" && p.Locality != "same-node" || p.SlowStartMS < 0 || p.SlowStartMS > 3600000 || p.Retry < 0 || p.Retry > 8 || p.Fallback != "" && p.Fallback != "default" && p.Fallback != "503" || len(p.Groups) > 128 || len(p.Match) > 128 || len(p.Weights) > 1024 {
		return ErrRoute
	}
	for k, w := range p.Weights {
		if k == "" || w < 1 || w > 1024 {
			return ErrRoute
		}
	}
	for id, g := range p.Groups {
		if !tokenName(id) || len(g.Labels) > 64 || len(g.Backends) > 128 || len(g.Labels) == 0 && g.Version == "" && len(g.Backends) == 0 {
			return ErrRoute
		}
	}
	ids := map[string]bool{}
	percent := 0
	for _, c := range p.Match {
		if !tokenName(c.ID) || ids[c.ID] || !balanceKey(c.Key) {
			return ErrRoute
		}
		ids[c.ID] = true
		if _, ok := p.Groups[c.Group]; !ok {
			return ErrRoute
		}
		for _, values := range []map[string]ValueMatch{c.Headers, c.Cookies, c.Query} {
			if len(values) > 32 {
				return ErrRoute
			}
			for key, v := range values {
				if !tokenName(key) || boolInt(v.Equal != nil)+boolInt(v.Prefix != nil)+boolInt(v.Present) != 1 {
					return ErrRoute
				}
			}
		}
		for _, method := range c.Methods {
			if !tokenName(method) || strings.ToUpper(method) != method {
				return ErrRoute
			}
		}
		for _, prefix := range c.Sources {
			if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
				return ErrRoute
			}
		}
		if c.Percent != nil {
			if *c.Percent < 0 || *c.Percent > 100 {
				return ErrRoute
			}
			percent += *c.Percent
		}
	}
	if percent > 100 {
		return ErrRoute
	}
	return nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func selectionKey(q Selection, key string) string {
	if key == "" || key == "source-ip" {
		if q.Source.IsValid() {
			return q.Source.String()
		}
		return ""
	}
	kind, name, _ := strings.Cut(key, ":")
	if kind == "cookie" {
		return q.Cookies[name]
	}
	return q.Headers[http.CanonicalHeaderKey(name)]
}
func hashSlot(key string) uint64 {
	sum := sha256.Sum256([]byte(key))
	return binary.BigEndian.Uint64(sum[:8])
}
func matchValues(values map[string]string, rules map[string]ValueMatch, header bool) bool {
	for key, r := range rules {
		if header {
			key = http.CanonicalHeaderKey(key)
		}
		v, exists := values[key]
		if !exists || r.Equal != nil && v != *r.Equal || r.Prefix != nil && !strings.HasPrefix(v, *r.Prefix) {
			return false
		}
	}
	return true
}
func (p Balance) Select(q Selection) (group, condition string) {
	for _, c := range p.Match {
		if !matchValues(q.Headers, c.Headers, true) || !matchValues(q.Cookies, c.Cookies, false) || !matchValues(q.Query, c.Query, false) {
			continue
		}
		if len(c.Methods) > 0 {
			ok := false
			for _, m := range c.Methods {
				ok = ok || m == q.Method
			}
			if !ok {
				continue
			}
		}
		if len(c.Sources) > 0 {
			ok := false
			for _, s := range c.Sources {
				ok = ok || s.Contains(q.Source)
			}
			if !ok {
				continue
			}
		}
		if c.Percent != nil {
			key := selectionKey(q, c.Key)
			if key == "" {
				key = stringEntropy(q.Entropy)
			}
			if hashSlot(c.ID+"\x00"+key)%10000 >= uint64(*c.Percent)*100 {
				continue
			}
		}
		return c.Group, c.ID
	}
	return "", ""
}
func stringEntropy(v uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return string(b[:])
}
func (g BackendGroup) contains(b BackendSpec) bool {
	if g.Version != "" && g.Version != b.Version {
		return false
	}
	for key, value := range g.Labels {
		if b.Labels[key] != value {
			return false
		}
	}
	if len(g.Backends) > 0 {
		for _, id := range g.Backends {
			if id == b.ID {
				return true
			}
		}
		return false
	}
	return true
}

func (b *Balancer) AcquireWith(now uint64, p Balance, q Selection) (BackendLease, error) {
	if p.Validate() != nil {
		return BackendLease{}, ErrRoute
	}
	group := q.Group
	if group == "" {
		group, _ = p.Select(q)
	}
	ids := []string{}
	weights := map[string]int64{}
	slowStart := p.SlowStartMS
	if p.SlowStartSeconds > 0 {
		slowStart = p.SlowStartSeconds * 1000
	}
	selectIDs := func(filter bool) {
		for id, s := range b.backends {
			v := s.spec
			if !v.Healthy || v.Draining || v.ObservedAt > now || now-v.ObservedAt > b.maxAge || s.leases.Count() >= v.Capacity || q.Exclude[id] {
				continue
			}
			if filter && !p.Groups[group].contains(q.Backends[id]) {
				continue
			}
			weight := int64(v.Weight)
			if configured := p.Weights[id]; configured > 0 {
				weight = int64(configured)
			}
			factor := int64(1)
			for group, selector := range p.Groups {
				if configured := p.Weights[group]; configured > 0 && selector.contains(q.Backends[id]) {
					factor = max(factor, int64(configured))
				}
			}
			weight *= factor
			if slowStart > 0 && now >= s.healthySince && now-s.healthySince < uint64(slowStart) {
				weight = max(1, weight*int64(now-s.healthySince)/int64(slowStart))
			}
			ids = append(ids, id)
			weights[id] = weight
		}
	}
	selectIDs(group != "")
	if len(ids) == 0 && group != "" && p.Fallback != "503" {
		selectIDs(false)
	}
	if len(ids) == 0 {
		return BackendLease{}, ErrRoute
	}
	sort.Strings(ids)
	if p.Locality == "same-node" && q.Node != "" {
		local := []string{}
		for _, id := range ids {
			if q.Backends[id].Node == q.Node {
				local = append(local, id)
			}
		}
		if len(local) > 0 {
			ids = local
		}
	}
	selected := ""
	var total int64
	for _, id := range ids {
		total += weights[id]
	}
	switch p.Method {
	case "least-request":
		// Rotate equal normalized loads; the ratio is compared without floats.
		for offset := range ids {
			id := ids[(offset+int(b.ticket%uint64(len(ids))))%len(ids)]
			if selected == "" || int64(b.backends[id].leases.Count())*weights[selected] < int64(b.backends[selected].leases.Count())*weights[id] {
				selected = id
			}
		}
	case "hash":
		key := selectionKey(q, p.Key)
		if key != "" {
			best := math.Inf(1)
			for _, id := range ids {
				u := (float64(hashSlot(key+"\x00"+id)>>11) + 1) / 9007199254740993
				score := -math.Log(u) / float64(weights[id])
				if score < best {
					best, selected = score, id
				}
			}
		}
	case "random":
		slot := q.Entropy % uint64(total)
		for _, id := range ids {
			if slot < uint64(weights[id]) {
				selected = id
				break
			}
			slot -= uint64(weights[id])
		}
	}
	if selected == "" {
		// Smooth weighted round-robin avoids blocks of high-weight requests.
		for _, id := range ids {
			state := b.backends[id]
			state.current += weights[id]
			if selected == "" || state.current > b.backends[selected].current {
				selected = id
			}
		}
		b.backends[selected].current -= total
	}
	b.ticket++
	lease, err := b.backends[selected].leases.Acquire()
	return BackendLease{Backend: selected, Lease: lease}, err
}
