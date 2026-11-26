// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// FakeWorld is an in-process DNS provider for development and tests. It is
// never a real provider: nothing leaves the process. Tokens that start with
// "fake-" are accepted; "fake-expired" fails the check.
type FakeWorld struct {
	mu        sync.Mutex
	zones     map[string]*Zone // domains whose DNS is here
	elsewhere []string         // domains of the account whose DNS is elsewhere
	snaps     map[string][]fakeSnap
	seq       int
	failNext  error
	applies   int
}

type fakeSnap struct {
	Snapshot
	zone Zone
}

// NewFakeWorld returns a world with example.com (apex A, www CNAME, MX,
// TXT), example.net (empty) and other.org (DNS elsewhere).
func NewFakeWorld() *FakeWorld {
	w := &FakeWorld{zones: map[string]*Zone{}, snaps: map[string][]fakeSnap{}, elsewhere: []string{"other.org"}}
	w.zones["example.com"] = &Zone{Domain: "example.com", Sets: []RRSet{
		{Name: "@", Type: "A", TTL: 3600, Records: []Record{{Content: "198.51.100.7"}}},
		{Name: "www", Type: "CNAME", TTL: 3600, Records: []Record{{Content: "example.com."}}},
		{Name: "@", Type: "MX", TTL: 3600, Records: []Record{{Content: "mail.example.com.", Priority: 10}}},
		{Name: "@", Type: "TXT", TTL: 3600, Records: []Record{{Content: "v=spf1 -all"}}},
	}}
	w.zones["example.net"] = &Zone{Domain: "example.net"}
	return w
}

// FailNext makes the next provider call return err.
func (w *FakeWorld) FailNext(err error) { w.mu.Lock(); w.failNext = err; w.mu.Unlock() }

// Applies counts successful Apply calls.
func (w *FakeWorld) Applies() int { w.mu.Lock(); defer w.mu.Unlock(); return w.applies }

// SetRecord changes a set behind the web app's back (tests: "changed
// elsewhere").
func (w *FakeWorld) SetRecord(domain string, r RRSet) {
	w.mu.Lock()
	defer w.mu.Unlock()
	applyTo(w.zones[domain], ChangeSet{Upsert: []RRSet{r}})
}

var fakeCaps = Capabilities{RecordTypes: []string{"A", "AAAA", "CNAME", "TXT", "MX", "CAA"}, Wildcard: true, MinTTL: 60,
	Validate: true, Snapshots: true, RateLimit: Rate{Requests: 600, Per: time.Minute}}

// FakeVendor is the "fake" vendor over w.
func FakeVendor(w *FakeWorld) Vendor {
	info := ProviderInfo{ID: "fake", Name: "Fake DNS (development)", Ready: true, Note: "in-process fake; nothing reaches a real provider"}
	return Vendor{Info: info, Capabilities: fakeCaps, New: func(token string, _ Env) Provider { return &fakeProvider{w: w, token: token, info: info} }}
}

type fakeProvider struct {
	w     *FakeWorld
	token string
	info  ProviderInfo
}

func (p *fakeProvider) Info() ProviderInfo         { return p.info }
func (p *fakeProvider) Capabilities() Capabilities { return fakeCaps }

// enter locks the world and returns a pending failure or bad token.
func (p *fakeProvider) enter() error {
	p.w.mu.Lock()
	if err := p.w.failNext; err != nil {
		p.w.failNext = nil
		return err
	}
	if !strings.HasPrefix(p.token, "fake-") || p.token == "fake-expired" {
		return &Error{Kind: AuthFailed, Detail: "fake: token rejected"}
	}
	return nil
}

func (p *fakeProvider) Check(ctx context.Context) (Account, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return Account{}, err
	}
	return Account{Name: "fake-account", Scope: "all domains", Domains: len(p.w.zones) + len(p.w.elsewhere), Remaining: 600,
		ExpiresAt: time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)}, nil
}

func (p *fakeProvider) ListDomains(ctx context.Context) ([]Domain, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return nil, err
	}
	var out []Domain
	for d := range p.w.zones {
		out = append(out, Domain{Name: d, HasZone: true})
	}
	for _, d := range p.w.elsewhere {
		out = append(out, Domain{Name: d})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (p *fakeProvider) GetZone(ctx context.Context, domain string) (Zone, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return Zone{}, err
	}
	z := p.w.zones[domain]
	if z == nil {
		return Zone{}, &Error{Kind: NotFound, Detail: "fake: no zone " + domain}
	}
	return cloneZone(*z), nil
}

func (p *fakeProvider) Validate(ctx context.Context, domain string, c ChangeSet) ([]Problem, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return nil, err
	}
	z := p.w.zones[domain]
	if z == nil {
		return nil, &Error{Kind: NotFound}
	}
	after := cloneZone(*z)
	applyTo(&after, c)
	var probs []Problem
	for _, s := range after.Sets {
		if s.Type == "CNAME" {
			for _, o := range after.Sets {
				if o.Name == s.Name && o.Type != "CNAME" {
					probs = append(probs, Problem{Name: s.Name, Type: s.Type, Message: "a CNAME cannot share its name with other records"})
					break
				}
			}
		}
	}
	return probs, nil
}

func (p *fakeProvider) Apply(ctx context.Context, domain string, c ChangeSet) (ApplyResult, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return ApplyResult{}, err
	}
	z := p.w.zones[domain]
	if z == nil {
		return ApplyResult{}, &Error{Kind: NotFound}
	}
	p.w.seq++
	id := fmt.Sprintf("snap-%d", p.w.seq)
	p.w.snaps[domain] = append(p.w.snaps[domain], fakeSnap{Snapshot{ID: id, CreatedAt: time.Now(), Reason: "before change"}, cloneZone(*z)})
	applyTo(z, c)
	p.w.applies++
	return ApplyResult{Snapshot: id}, nil
}

func (p *fakeProvider) ListSnapshots(ctx context.Context, domain string) ([]Snapshot, error) {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return nil, err
	}
	var out []Snapshot
	ss := p.w.snaps[domain]
	for i := len(ss) - 1; i >= 0; i-- {
		out = append(out, ss[i].Snapshot)
	}
	return out, nil
}

func (p *fakeProvider) RestoreSnapshot(ctx context.Context, domain, id string) error {
	defer p.w.mu.Unlock()
	if err := p.enter(); err != nil {
		return err
	}
	for _, s := range p.w.snaps[domain] {
		if s.ID == id {
			z := cloneZone(s.zone)
			p.w.zones[domain] = &z
			return nil
		}
	}
	return &Error{Kind: NotFound, Detail: "no snapshot " + id}
}

func cloneZone(z Zone) Zone {
	out := Zone{Domain: z.Domain, Sets: make([]RRSet, len(z.Sets))}
	for i, s := range z.Sets {
		s.Records = slices.Clone(s.Records)
		out.Sets[i] = s
	}
	return out
}

// applyTo replaces and deletes whole RRSets.
func applyTo(z *Zone, c ChangeSet) {
	if z == nil {
		return
	}
	drop := map[Key]bool{}
	for _, k := range c.Delete {
		drop[k] = true
	}
	for _, u := range c.Upsert {
		drop[u.Key()] = true
	}
	kept := z.Sets[:0]
	for _, s := range z.Sets {
		if !drop[s.Key()] {
			kept = append(kept, s)
		}
	}
	z.Sets = kept
	for _, u := range c.Upsert {
		u.Records = slices.Clone(u.Records)
		z.Sets = append(z.Sets, u)
	}
	sort.Slice(z.Sets, func(i, j int) bool {
		if z.Sets[i].Name != z.Sets[j].Name {
			return z.Sets[i].Name < z.Sets[j].Name
		}
		return z.Sets[i].Type < z.Sets[j].Type
	})
}

// CheckSet validates an RRSet the web app is asked to write: a known type,
// a valid relative name, a TTL at least minTTL, and contents that parse.
func CheckSet(r RRSet, caps Capabilities) error {
	if !slices.Contains(caps.RecordTypes, r.Type) {
		return fmt.Errorf("record type %q is not supported by this provider", r.Type)
	}
	if err := checkName(r.Name, caps.Wildcard); err != nil {
		return err
	}
	if r.TTL < caps.MinTTL || r.TTL > 86400*7 {
		return fmt.Errorf("ttl must be between %d and %d", caps.MinTTL, 86400*7)
	}
	if len(r.Records) == 0 || len(r.Records) > 100 {
		return fmt.Errorf("%s %s: 1..100 records", r.Name, r.Type)
	}
	if r.Type == "CNAME" && len(r.Records) != 1 {
		return fmt.Errorf("a CNAME has exactly one value")
	}
	for _, v := range r.Records {
		switch r.Type {
		case "A":
			if a, err := netip.ParseAddr(v.Content); err != nil || !a.Is4() {
				return fmt.Errorf("%q is not an IPv4 address", v.Content)
			}
		case "AAAA":
			if a, err := netip.ParseAddr(v.Content); err != nil || !a.Is6() || a.Is4In6() {
				return fmt.Errorf("%q is not an IPv6 address", v.Content)
			}
		default:
			if v.Content == "" || len(v.Content) > 2048 || strings.ContainsAny(v.Content, "\n\r") {
				return fmt.Errorf("invalid %s value", r.Type)
			}
		}
	}
	return nil
}

func checkName(n string, wildcard bool) error {
	if n == "@" {
		return nil
	}
	if n == "" || len(n) > 253 || strings.HasSuffix(n, ".") {
		return fmt.Errorf("invalid record name %q (relative to the domain, \"@\" for the domain itself)", n)
	}
	for i, l := range strings.Split(n, ".") {
		if l == "*" && i == 0 && wildcard {
			continue
		}
		if l == "" || len(l) > 63 {
			return fmt.Errorf("invalid record name %q", n)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("invalid record name %q (lowercase letters, digits, '-', '_')", n)
			}
		}
	}
	return nil
}

// InRange reports whether name is inside a workspace's assigned names.
// A pattern is a relative name ("shop") or a wildcard ("*.shop", which
// covers every name under shop, and "*.shop" itself).
func InRange(name string, patterns []string) bool {
	for _, p := range patterns {
		if name == p {
			return true
		}
		if strings.HasPrefix(p, "*.") && strings.HasSuffix(name, p[1:]) {
			return true
		}
	}
	return false
}

// CheckPattern validates an assignment pattern.
func CheckPattern(p string) error { return checkName(p, true) }
