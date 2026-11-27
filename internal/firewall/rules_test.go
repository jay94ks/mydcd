// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"errors"
	"strings"
	"testing"
)

func TestChangeAddsUpdatesDeletes(t *testing.T) {
	s := New()
	if s.Policy != PolicyInherit {
		t.Fatal("a new firewall must fall through to the operator rules")
	}
	s1, added, err := s.Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "443"}, {Action: "deny", Proto: "tcp", Ports: "8000-8100", From: []string{"198.51.100.7/32"}}}})
	if err != nil || s1.Revision != 1 || len(added) != 2 || added[0] != "r1" || added[1] != "r2" || !s1.Valid() {
		t.Fatal(s1, added, err)
	}
	if _, _, err := s1.Change(0, Delta{Delete: []string{"r1"}}); !errors.Is(err, ErrRevision) {
		t.Fatal("stale revision accepted", err)
	}
	s2, _, err := s1.Change(1, Delta{Update: []Rule{{ID: "r1", Action: "allow", Proto: "tcp", Ports: "443", From: []string{"203.0.113.0/24"}}}, Delete: []string{"r2"}, Policy: PolicyDrop})
	if err != nil || s2.Revision != 2 || len(s2.Rules) != 1 || s2.Rules[0].From[0] != "203.0.113.0/24" || s2.Policy != PolicyDrop {
		t.Fatal(s2, err)
	}
	s3, added, err := s2.Change(2, Delta{Add: []Rule{{Action: "allow", Proto: "udp", Ports: "51820"}}})
	if err != nil || added[0] != "r3" {
		t.Fatal("IDs are never reused", added, err)
	}
	if _, _, err := s3.Change(3, Delta{Add: []Rule{{Action: "allow", Proto: "udp", Ports: "51820", Comment: "again"}}}); !errors.Is(err, ErrDuplicate) {
		t.Fatal("duplicate accepted", err)
	}
	if _, _, err := s3.Change(3, Delta{Delete: []string{"r9"}}); !errors.Is(err, ErrMissing) {
		t.Fatal(err)
	}
}

func TestRuleChecks(t *testing.T) {
	for name, r := range map[string]Rule{
		"no port":       {Action: "allow", Proto: "tcp"},
		"icmp port":     {Action: "allow", Proto: "icmp", Ports: "1"},
		"bad range":     {Action: "allow", Proto: "tcp", Ports: "200-100"},
		"zero port":     {Action: "allow", Proto: "tcp", Ports: "0"},
		"padded port":   {Action: "allow", Proto: "tcp", Ports: "080"},
		"bad action":    {Action: "reject", Proto: "any"},
		"host bits":     {Action: "allow", Proto: "any", From: []string{"10.0.0.1/8"}},
		"comment lines": {Action: "allow", Proto: "any", Comment: "a\nb"},
		"given ID":      {ID: "r1", Action: "allow", Proto: "any"},
	} {
		if _, _, err := New().Change(0, Delta{Add: []Rule{r}}); err == nil {
			t.Error(name, "accepted")
		}
	}
	s := New()
	s.Revision = 7
	many := Delta{}
	for i := 1; i <= MaxRules+1; i++ {
		many.Add = append(many.Add, Rule{Action: "allow", Proto: "tcp", Ports: itoa(i)})
	}
	if _, _, err := s.Change(7, many); !errors.Is(err, ErrTooMany) {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	b := []byte{}
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestLinesOrderAndFamilies(t *testing.T) {
	s, _, _ := New().Change(0, Delta{Add: []Rule{
		{Action: "allow", Proto: "tcp", Ports: "443"},
		{Action: "deny", Proto: "tcp", Ports: "443", From: []string{"198.51.100.0/24", "2001:db8::/32"}},
		{Action: "allow", Proto: "icmp"},
	}, Policy: PolicyDrop})
	l := Locks{Ports: []Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}, {Proto: "tcp", Port: 22, Reason: "keep-open"}, {Proto: "tcp", Port: 22, Reason: "ingress"}}}
	v4 := Lines(4, only(s), l)
	if !strings.HasPrefix(v4[0], "-m comment --comment \"sfc revision 1/0 ") || v4[len(v4)-1] != "-m comment --comment \"sfc policy drop\" -j DROP" {
		t.Fatal(v4)
	}
	joined := strings.Join(v4, "\n")
	deny, allow, lock := strings.Index(joined, "198.51.100.0/24"), strings.Index(joined, "\"sfc r1\" -j ACCEPT"), strings.Index(joined, "--dport 7443")
	if !(lock < deny && deny < allow) || strings.Contains(joined, "2001:db8") || strings.Count(joined, "--dport 22 ") != 1 {
		t.Fatal("locks, then deny, then allow, per family, each port once:\n" + joined)
	}
	v6 := strings.Join(Lines(6, only(s), l), "\n")
	if !strings.Contains(v6, "-s 2001:db8::/32") || strings.Contains(v6, "198.51.100") || !strings.Contains(v6, "-p ipv6-icmp -m comment --comment \"sfc r3\" -j ACCEPT") || !strings.Contains(v6, "neighbour-solicitation") {
		t.Fatal(v6)
	}
	r, _, _ := New().Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "1"}}})
	if Lines(4, only(r), l)[0] == Lines(4, only(s), l)[0] {
		t.Fatal("marker must follow the content")
	}
}

func TestLayersOrderAndRequired(t *testing.T) {
	c, _, err := NewCluster().Change(0, Delta{Add: []Rule{
		{Action: "allow", Proto: "tcp", Ports: "22", From: []string{"192.168.1.0/24"}, Required: true},
		{Action: "deny", Proto: "tcp", Ports: "2375"},
		{Action: "allow", Proto: "tcp", Ports: "80"},
	}, Policy: PolicyDrop})
	if err != nil || c.Rules[0].ID != "c1" {
		t.Fatal(err, c)
	}
	if _, _, err := New().Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "1", Required: true}}}); err == nil {
		t.Fatal("a server rule cannot be required")
	}
	if _, _, err := New().Change(0, Delta{Policy: PolicyInherit}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewCluster().Change(0, Delta{Policy: PolicyInherit}); err == nil {
		t.Fatal("the cluster cannot inherit")
	}
	n, _, _ := New().Change(0, Delta{Add: []Rule{
		{Action: "deny", Proto: "any", From: []string{"192.168.1.7/32"}},
		{Action: "allow", Proto: "tcp", Ports: "2375", From: []string{"10.0.0.0/8"}},
		{Action: "deny", Proto: "udp", Ports: "53"},
	}})
	ls := Layers{Node: n, Cluster: c}
	if Effective(n, c) != PolicyDrop {
		t.Fatal("inherit follows the cluster")
	}
	l := Locks{Ports: []Port{{Proto: "tcp", Port: 22, From: []string{"10.0.0.0/8", "fd00::/8"}, Reason: "keep-open"}}}
	v4 := strings.Join(Lines(4, ls, l), "\n")
	at := func(s string) int {
		i := strings.Index(v4, s)
		if i < 0 {
			t.Fatal(s, "\n", v4)
		}
		return i
	}
	lock, req, nDeny, nAllow, cDeny, cAllow, policy := at("-s 10.0.0.0/8 -p tcp -m tcp --dport 22 -m comment --comment \"sfc lock keep-open\""), at("\"sfc c1\""), at("\"sfc r1\""), at("\"sfc r2\""), at("\"sfc c2\""), at("\"sfc c3\""), at("sfc policy drop")
	if !(lock < req && req < nDeny && nDeny < nAllow && nAllow < cDeny && cDeny < cAllow && cAllow < policy) || strings.Contains(v4, "fd00::/8") {
		t.Fatal(v4)
	}
	if v6 := strings.Join(Lines(6, ls, l), "\n"); !strings.Contains(v6, "-s fd00::/8 -p tcp") || strings.Contains(v6, "10.0.0.0/8 -p tcp -m tcp --dport 22") {
		t.Fatal(v6)
	}
	if got := Shadowed(ls); len(got) != 1 || got[0] != "r1" {
		t.Fatal(got)
	}
	own, _, _ := n.Change(1, Delta{Policy: PolicyReturn})
	if Effective(own, c) != PolicyReturn || strings.Contains(strings.Join(Lines(4, Layers{Node: own, Cluster: c}, l), "\n"), "policy drop") {
		t.Fatal("a server policy wins")
	}
}
