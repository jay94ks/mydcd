// SPDX-License-Identifier: Apache-2.0

// Package firewall is a server's own inbound firewall chain
// (devel/proposals/node-firewall.md). sfcd keeps one iptables/ip6tables
// chain, SFC-INPUT, jumped to from the top of INPUT, and never reads back
// or changes the operator's own INPUT rules.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Chain is the one chain sfcd owns in the filter table of iptables and
// ip6tables.
const Chain = "SFC-INPUT"

// MaxRules is the most operator rules one server keeps.
const MaxRules = 256

// MaxSources is the most source prefixes one rule matches.
const MaxSources = 32

// Rule is one operator rule. Deny rules are checked before allow rules, so
// the order of rules carries no meaning.
type Rule struct {
	ID      string
	Action  string   // allow or deny
	Proto   string   // tcp, udp, icmp or any
	Ports   string   `json:",omitempty"` // "443" or "30000-30100"; tcp and udp only
	From    []string `json:",omitempty"` // source prefixes; empty: anywhere
	Comment string   `json:",omitempty"`
	// Required marks a cluster rule a server cannot override: it is checked
	// before the server's own rules. Cluster rules only.
	Required bool `json:",omitempty"`
}

// Policies: return falls through to the operator's own INPUT rules; drop
// drops what no rule took.
// inherit (a server only) follows the cluster's policy.
const (
	PolicyReturn  = "return"
	PolicyDrop    = "drop"
	PolicyInherit = "inherit"
)

// ScopeCluster marks the cluster's own firewall (rule IDs c1, c2, …); a
// server's firewall has no scope (r1, r2, …).
const ScopeCluster = "cluster"

// State is a server's firewall: what sfcd puts in SFC-INPUT besides the
// locked rules.
type State struct {
	Schema   uint8
	Scope    string `json:",omitempty"`
	Revision uint64
	Policy   string
	NextID   uint64
	Rules    []Rule
}

// New is a server's firewall before its first change: it follows the
// cluster's policy.
func New() State { return State{Schema: 1, Policy: PolicyInherit, NextID: 1, Rules: []Rule{}} }

// NewCluster is the cluster's firewall before its first change: unmatched
// traffic goes on to each server's own INPUT rules.
func NewCluster() State {
	return State{Schema: 1, Scope: ScopeCluster, Policy: PolicyReturn, NextID: 1, Rules: []Rule{}}
}

func (s State) prefix() byte {
	if s.Scope == ScopeCluster {
		return 'c'
	}
	return 'r'
}

func (s State) policyOK(p string) bool {
	return p == PolicyReturn || p == PolicyDrop || p == PolicyInherit && s.Scope != ScopeCluster
}

// Effective is the policy a server applies: its own unless it inherits the
// cluster's.
func Effective(node, cluster State) string {
	if node.Policy != PolicyInherit {
		return node.Policy
	}
	if cluster.Policy == PolicyDrop {
		return PolicyDrop
	}
	return PolicyReturn
}

// Delta is one change: what to add, update and delete, and the policy when
// it changes. Update names a rule by ID and replaces its fields.
type Delta struct {
	Add    []Rule   `json:",omitempty"`
	Update []Rule   `json:",omitempty"`
	Delete []string `json:",omitempty"`
	Policy string   `json:",omitempty"`
}

// Empty says the delta changes nothing.
func (d Delta) Empty() bool {
	return len(d.Add) == 0 && len(d.Update) == 0 && len(d.Delete) == 0 && d.Policy == ""
}

var (
	ErrRule      = errors.New("invalid firewall rule")
	ErrMissing   = errors.New("no such firewall rule")
	ErrTooMany   = errors.New("too many firewall rules")
	ErrRevision  = errors.New("firewall changed since it was read")
	ErrDuplicate = errors.New("the same firewall rule already exists")
)

// Valid checks r without its ID.
func (r Rule) check() error {
	if r.Action != "allow" && r.Action != "deny" {
		return fmt.Errorf("%w: action must be allow or deny", ErrRule)
	}
	switch r.Proto {
	case "tcp", "udp":
		if r.Ports == "" {
			return fmt.Errorf("%w: %s needs a port or a port range", ErrRule, r.Proto)
		}
		if _, _, err := PortRange(r.Ports); err != nil {
			return err
		}
	case "icmp", "any":
		if r.Ports != "" {
			return fmt.Errorf("%w: %s takes no port", ErrRule, r.Proto)
		}
	default:
		return fmt.Errorf("%w: protocol must be tcp, udp, icmp or any", ErrRule)
	}
	if len(r.From) > MaxSources {
		return fmt.Errorf("%w: at most %d sources", ErrRule, MaxSources)
	}
	seen := map[string]bool{}
	for _, s := range r.From {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Masked() != p || p.Addr().Zone() != "" || p.Addr().Is4In6() || seen[s] {
			return fmt.Errorf("%w: source %q must be a distinct network prefix such as 203.0.113.0/24", ErrRule, s)
		}
		seen[s] = true
	}
	if !utf8.ValidString(r.Comment) || utf8.RuneCountInString(r.Comment) > 120 || strings.ContainsFunc(r.Comment, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return fmt.Errorf("%w: comment must be one line of at most 120 characters", ErrRule)
	}
	return nil
}

func validID(id string, prefix byte) bool {
	if len(id) < 2 || len(id) > 12 || id[0] != prefix {
		return false
	}
	n, err := strconv.ParseUint(id[1:], 10, 64)
	return err == nil && n > 0 && string(prefix)+strconv.FormatUint(n, 10) == id
}

func (s State) ruleOK(r Rule) error {
	if r.Required && s.Scope != ScopeCluster {
		return fmt.Errorf("%w: only a cluster rule can be required", ErrRule)
	}
	return r.check()
}

// PortRange reads "443" or "30000-30100".
func PortRange(s string) (uint16, uint16, error) {
	lo, hi, ranged := strings.Cut(s, "-")
	a, err1 := strconv.ParseUint(lo, 10, 16)
	b := a
	var err2 error
	if ranged {
		b, err2 = strconv.ParseUint(hi, 10, 16)
	}
	if err1 != nil || err2 != nil || a == 0 || b < a || strconv.FormatUint(a, 10) != lo || ranged && strconv.FormatUint(b, 10) != hi {
		return 0, 0, fmt.Errorf("%w: port %q must be 1-65535 or a range such as 30000-30100", ErrRule, s)
	}
	return uint16(a), uint16(b), nil
}

// Valid checks a stored state.
func (s State) Valid() bool {
	if s.Schema != 1 || s.Scope != "" && s.Scope != ScopeCluster || !s.policyOK(s.Policy) || len(s.Rules) > MaxRules || s.NextID == 0 {
		return false
	}
	ids := map[string]bool{}
	for _, r := range s.Rules {
		if !validID(r.ID, s.prefix()) || s.ruleOK(r) != nil || ids[r.ID] {
			return false
		}
		n, _ := strconv.ParseUint(r.ID[1:], 10, 64)
		if n >= s.NextID {
			return false
		}
		ids[r.ID] = true
	}
	return true
}

// Change applies d to s at revision: it fails with ErrRevision when s moved
// on. The returned state has the next revision; added rules get new IDs.
func (s State) Change(revision uint64, d Delta) (State, []string, error) {
	if revision != s.Revision {
		return s, nil, ErrRevision
	}
	if d.Empty() {
		return s, nil, fmt.Errorf("%w: nothing to change", ErrRule)
	}
	if d.Policy != "" && !s.policyOK(d.Policy) {
		return s, nil, fmt.Errorf("%w: policy must be return or drop (a server also inherit)", ErrRule)
	}
	next := State{Schema: 1, Scope: s.Scope, Revision: s.Revision + 1, Policy: s.Policy, NextID: s.NextID, Rules: append([]Rule{}, s.Rules...)}
	if d.Policy != "" {
		next.Policy = d.Policy
	}
	touched := map[string]bool{}
	index := func(id string) int {
		for i, r := range next.Rules {
			if r.ID == id {
				return i
			}
		}
		return -1
	}
	for _, id := range d.Delete {
		i := index(id)
		if i < 0 || touched[id] {
			return s, nil, fmt.Errorf("%w: %s", ErrMissing, id)
		}
		touched[id] = true
		next.Rules = append(next.Rules[:i], next.Rules[i+1:]...)
	}
	for _, u := range d.Update {
		i := index(u.ID)
		if i < 0 || touched[u.ID] {
			return s, nil, fmt.Errorf("%w: %s", ErrMissing, u.ID)
		}
		if err := s.ruleOK(u); err != nil {
			return s, nil, err
		}
		touched[u.ID] = true
		next.Rules[i] = clean(u)
	}
	added := []string{}
	for _, a := range d.Add {
		if a.ID != "" {
			return s, nil, fmt.Errorf("%w: a new rule gets its ID from the server", ErrRule)
		}
		if err := s.ruleOK(a); err != nil {
			return s, nil, err
		}
		a.ID = string(s.prefix()) + strconv.FormatUint(next.NextID, 10)
		next.NextID++
		next.Rules = append(next.Rules, clean(a))
		added = append(added, a.ID)
	}
	if len(next.Rules) > MaxRules {
		return s, nil, ErrTooMany
	}
	seen := map[string]string{}
	for _, r := range next.Rules {
		k := r.key()
		if other, dup := seen[k]; dup {
			return s, nil, fmt.Errorf("%w: %s and %s", ErrDuplicate, other, r.ID)
		}
		seen[k] = r.ID
	}
	return next, added, nil
}

// key is what makes two rules the same, apart from ID and comment.
func (r Rule) key() string {
	from := append([]string{}, r.From...)
	slices.Sort(from)
	return r.Action + " " + r.Proto + " " + r.Ports + " " + strings.Join(from, ",") + " " + strconv.FormatBool(r.Required)
}

func clean(r Rule) Rule {
	if len(r.From) == 0 {
		r.From = nil
	} else {
		r.From = append([]string{}, r.From...)
	}
	return r
}

// Allows says whether any rule lets traffic in: a drop policy without one
// leaves only the locked rules open.
func (s State) Allows() bool {
	for _, r := range s.Rules {
		if r.Action == "allow" {
			return true
		}
	}
	return false
}

// Layers is what one server applies: the cluster's firewall under its own.
type Layers struct {
	Node, Cluster State
}

// Code is the fixed reason (control.NodeFirewallCodes) for an error of
// State.Change.
func Code(err error) string {
	switch {
	case errors.Is(err, ErrRevision):
		return "revision"
	case errors.Is(err, ErrDuplicate):
		return "duplicate"
	case errors.Is(err, ErrTooMany):
		return "too-many"
	case errors.Is(err, ErrMissing):
		return "missing"
	}
	return "invalid"
}

// Summary is a short line such as "add r4 allow tcp 443; delete r2; policy
// drop" for the event log; added are the IDs the new rules got.
func Summary(d Delta, added []string) string {
	parts := []string{}
	describe := func(r Rule) string {
		s := r.ID + " " + r.Action + " " + r.Proto
		if r.Ports != "" {
			s += " " + r.Ports
		}
		if len(r.From) > 0 {
			s += " from " + strings.Join(r.From, ",")
		}
		if r.Required {
			s += " required"
		}
		return s
	}
	for i, a := range d.Add {
		if i < len(added) {
			a.ID = added[i]
		}
		parts = append(parts, "add "+describe(a))
	}
	for _, u := range d.Update {
		parts = append(parts, "update "+describe(u))
	}
	for _, id := range d.Delete {
		parts = append(parts, "delete "+id)
	}
	if d.Policy != "" {
		parts = append(parts, "policy "+d.Policy)
	}
	s := strings.Join(parts, "; ")
	if len(s) > 2000 {
		s = s[:2000] + "…"
	}
	return s
}

// Shadowed are the IDs of server rules that a required cluster rule of the
// other action partly overrides: some traffic the server rule names is
// decided by the cluster rule first ("일부 가려짐").
func Shadowed(ls Layers) []string {
	out := []string{}
	for _, r := range ls.Node.Rules {
		for _, c := range ls.Cluster.Rules {
			if c.Required && c.Action != r.Action && overlaps(r, c) {
				out = append(out, r.ID)
				break
			}
		}
	}
	return out
}

// overlaps says whether some packet matches both a and b.
func overlaps(a, b Rule) bool {
	if a.Proto != "any" && b.Proto != "any" && a.Proto != b.Proto {
		return false
	}
	if a.Ports != "" && b.Ports != "" {
		alo, ahi, _ := PortRange(a.Ports)
		blo, bhi, _ := PortRange(b.Ports)
		if ahi < blo || bhi < alo {
			return false
		}
	}
	if len(a.From) == 0 || len(b.From) == 0 {
		return true
	}
	for _, x := range a.From {
		p, _ := netip.ParsePrefix(x)
		for _, y := range b.From {
			if q, _ := netip.ParsePrefix(y); p.Overlaps(q) {
				return true
			}
		}
	}
	return false
}
