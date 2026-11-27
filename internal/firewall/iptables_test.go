// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// fakeHost keeps INPUT and SFC-INPUT per family and fails restores of a
// family on request.
type fakeHost struct {
	input, chain map[int][]string
	has          map[int]bool
	fail         map[int]bool
	restores     []string
}

func newFakeHost() *fakeHost {
	return &fakeHost{input: map[int][]string{4: {"-P INPUT ACCEPT", "-A INPUT -p tcp -m tcp --dport 8080 -j DROP"}, 6: {"-P INPUT ACCEPT"}}, chain: map[int][]string{}, has: map[int]bool{}, fail: map[int]bool{}}
}

func (h *fakeHost) List(_ context.Context, family int, chain string) ([]string, bool, error) {
	if chain == "INPUT" {
		return append([]string{}, h.input[family]...), false, nil
	}
	if !h.has[family] {
		return nil, true, nil
	}
	return append([]string{"-N " + Chain}, h.chain[family]...), false, nil
}

func (h *fakeHost) Restore(_ context.Context, family int, input []byte) error {
	h.restores = append(h.restores, string(input))
	if h.fail[family] {
		return errors.New("restore failed")
	}
	lines := strings.Split(strings.TrimSpace(string(input)), "\n")
	for _, l := range lines {
		switch {
		case l == ":"+Chain+" - [0:0]":
			h.has[family], h.chain[family] = true, nil
		case strings.HasPrefix(l, "-A "+Chain+" "):
			h.chain[family] = append(h.chain[family], l)
		case l == "-D INPUT -j "+Chain:
			for i, x := range h.input[family] {
				if x == jumpLine {
					h.input[family] = append(h.input[family][:i:i], h.input[family][i+1:]...)
					break
				}
			}
		case l == "-I INPUT 1 -j "+Chain:
			h.input[family] = append([]string{h.input[family][0], jumpLine}, h.input[family][1:]...)
		case l == "-X "+Chain:
			h.has[family], h.chain[family] = false, nil
		}
	}
	return nil
}

func TestApplyKeepsOperatorRulesAndOneJump(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	s, _, _ := New().Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "8080"}}})
	l := Locks{Ports: []Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}}}
	for range 2 {
		if err := Apply(ctx, h, only(s), l, nil); err != nil {
			t.Fatal(err)
		}
	}
	if jumps, first := inputJumps(h.input[4]); jumps != 1 || !first || h.input[4][2] != "-A INPUT -p tcp -m tcp --dport 8080 -j DROP" {
		t.Fatal(h.input[4])
	}
	for _, family := range Families {
		if ok, err := Installed(ctx, h, family, Lines(family, only(s), l)); !ok || err != nil {
			t.Fatal(family, ok, err)
		}
	}
	op, _, _ := Operator(ctx, h, 4)
	if len(op) != 2 || strings.Contains(strings.Join(op, "\n"), Chain) {
		t.Fatal(op)
	}
	if err := Remove(ctx, h); err != nil || h.has[4] || h.has[6] || len(h.input[4]) != 2 {
		t.Fatal(err, h.input[4])
	}
}

func TestApplyPutsEarlierFamilyBack(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	l := Locks{}
	old, _, _ := New().Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "1"}}})
	if err := Apply(ctx, h, only(old), l, nil); err != nil {
		t.Fatal(err)
	}
	next, _, _ := old.Change(1, Delta{Policy: PolicyDrop})
	h.fail[6] = true
	if err := Apply(ctx, h, only(next), l, ref(only(old))); err == nil {
		t.Fatal("v6 failure not reported")
	}
	if ok, _ := Installed(ctx, h, 4, Lines(4, only(old), l)); !ok {
		t.Fatal("v4 not put back to the previous rules")
	}
}

// TestRealIptablesInOwnNamespace runs the real iptables in a new network
// namespace (SFC_FIREWALL_NETNS_TEST=1, root): sfcd's allow wins over an
// operator drop, the operator rules stay, and Remove leaves them as found.
func TestRealIptablesInOwnNamespace(t *testing.T) {
	if os.Getenv("SFC_FIREWALL_NETNS_TEST") != "1" {
		t.Skip("set SFC_FIREWALL_NETNS_TEST=1 and run as root; the test runs itself in a new network namespace")
	}
	if os.Getenv("SFC_FIREWALL_IN_NETNS") != "1" {
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestRealIptablesInOwnNamespace$", "-test.v")
		cmd.Env = append(os.Environ(), "SFC_FIREWALL_IN_NETNS=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS") {
			t.Fatal(err, string(out))
		}
		return
	}
	ctx := context.Background()
	run := func(name string, args ...string) string {
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatal(name, args, err, string(out))
		}
		return string(out)
	}
	run("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	run("ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	before4, before6 := run("iptables", "-S", "INPUT"), run("ip6tables", "-S", "INPUT")
	s, _, err := New().Change(0, Delta{Add: []Rule{
		{Action: "allow", Proto: "tcp", Ports: "8080", From: []string{"10.0.0.0/8", "fd00::/8"}},
		{Action: "deny", Proto: "udp", Ports: "30000-30100"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	l := Locks{Ports: []Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}, {Proto: "tcp", Port: 22, Reason: "keep-open"}}}
	for range 2 {
		if err := Apply(ctx, Real, only(s), l, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range Families {
		if ok, err := Installed(ctx, Real, family, Lines(family, only(s), l)); !ok || err != nil {
			t.Fatal("not installed", family, err, run("iptables-save"))
		}
	}
	got := run("iptables", "-S", "INPUT")
	if !strings.HasPrefix(got, "-P INPUT ACCEPT\n-A INPUT -j SFC-INPUT\n-A INPUT -p tcp -m tcp --dport 8080 -j DROP") || strings.Count(got, "SFC-INPUT") != 1 {
		t.Fatal(got)
	}
	chain := run("iptables", "-S", Chain)
	if !strings.Contains(chain, "-s 10.0.0.0/8 -p tcp -m tcp --dport 8080") || !strings.Contains(chain, "--dport 30000:30100") || strings.Contains(chain, "fd00") {
		t.Fatal(chain)
	}
	// Someone flushes the chain: Installed notices.
	run("iptables", "-F", Chain)
	if ok, _ := Installed(ctx, Real, 4, Lines(4, only(s), l)); ok {
		t.Fatal("flushed chain reported installed")
	}
	if err := Remove(ctx, Real); err != nil {
		t.Fatal(err)
	}
	if run("iptables", "-S", "INPUT") != before4 || run("ip6tables", "-S", "INPUT") != before6 {
		t.Fatal("operator rules changed")
	}
	if err := Remove(ctx, Real); err != nil {
		t.Fatal("second remove", err)
	}
	t.Log("ok")
}
