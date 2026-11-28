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

// fakeHost keeps SFC-INPUT and the jump per family and fails writes on
// request; a failed write changes nothing.
type fakeHost struct {
	chain  map[int][]Line
	jumps  map[int]int
	fail   bool
	writes int
}

func newFakeHost() *fakeHost { return &fakeHost{chain: map[int][]Line{}, jumps: map[int]int{}} }

func (h *fakeHost) State(_ context.Context, family int) (ChainState, error) {
	lines, ok := h.chain[family]
	st := ChainState{Exists: ok, Count: len(lines), Jumps: h.jumps[family], First: h.jumps[family] > 0}
	if len(lines) > 0 {
		st.Marker = lines[0].Comment
	}
	return st, nil
}

func (h *fakeHost) Write(_ context.Context, plan map[int][]Line) error {
	h.writes++
	if h.fail {
		return errors.New("write failed")
	}
	for family, lines := range plan {
		if lines == nil {
			delete(h.chain, family)
			h.jumps[family] = 0
			continue
		}
		h.chain[family], h.jumps[family] = append([]Line{}, lines...), 1
	}
	return nil
}

func (h *fakeHost) Operator(context.Context) ([]string, bool, error) {
	return []string{"ip filter INPUT (hook input, priority 0, policy accept)", "  ip protocol tcp tcp dport 8080 counter drop"}, false, nil
}

func TestApplyKeepsOneJumpAndIsAllOrNothing(t *testing.T) {
	ctx := context.Background()
	h := newFakeHost()
	s, _, _ := New().Change(0, Delta{Add: []Rule{{Action: "allow", Proto: "tcp", Ports: "8080"}}})
	l := Locks{Ports: []Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}}}
	for range 2 {
		if err := Apply(ctx, h, only(s), l); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range Families {
		if ok, err := Installed(ctx, h, family, Lines(family, only(s), l)); !ok || err != nil {
			t.Fatal(family, ok, err)
		}
	}
	next, _, _ := s.Change(1, Delta{Policy: PolicyDrop})
	h.fail = true
	if err := Apply(ctx, h, only(next), l); err == nil {
		t.Fatal("failure not reported")
	}
	h.fail = false
	if ok, _ := Installed(ctx, h, 4, Lines(4, only(s), l)); !ok {
		t.Fatal("a failed write changed the chain")
	}
	if err := Remove(ctx, h); err != nil || len(h.chain) != 0 || h.jumps[4] != 0 {
		t.Fatal(err, h.chain)
	}
	writes := h.writes
	if err := Remove(ctx, h); err != nil || h.writes != writes {
		t.Fatal("removing nothing must not write", err)
	}
}

// TestRealNetfilterInOwnNamespace writes SFC-INPUT over netlink in a new
// network namespace (SFC_FIREWALL_NETNS_TEST=1, root) and reads it back with
// the real iptables and ip6tables (test only; sfcd itself never runs them):
// the lines are exactly what iptables-nft would print, the jump is first,
// operator rules stay, and Remove leaves them as found.
func TestRealNetfilterInOwnNamespace(t *testing.T) {
	if os.Getenv("SFC_FIREWALL_NETNS_TEST") != "1" {
		t.Skip("set SFC_FIREWALL_NETNS_TEST=1 and run as root with iptables installed; the test runs itself in a new network namespace")
	}
	if os.Getenv("SFC_FIREWALL_IN_NETNS") != "1" {
		cmd := exec.Command("unshare", "-n", os.Args[0], "-test.run", "^TestRealNetfilterInOwnNamespace$", "-test.v")
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
	// A fresh namespace has no filter table: sfcd creates the one
	// iptables-nft would.
	s, _, err := New().Change(0, Delta{Add: []Rule{
		{Action: "allow", Proto: "tcp", Ports: "8080", From: []string{"10.0.0.0/8", "fd00::/8", "10.254.240.0/20", "2001:db8:1230::/44", "203.0.113.7/32"}},
		{Action: "deny", Proto: "udp", Ports: "30000-30100"},
		{Action: "allow", Proto: "icmp"},
		{Action: "deny", Proto: "any", From: []string{"198.51.100.0/24"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	l := Locks{Ports: []Port{{Proto: "udp", Port: 7443, Reason: "sfcp"}, {Proto: "tcp", Port: 22, From: []string{"192.168.1.0/24"}, Reason: "keep-open"}}}
	if err := Apply(ctx, Real, only(s), l); err != nil {
		t.Fatal(err)
	}
	run("iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	run("ip6tables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "DROP")
	before4, before6 := run("iptables", "-S", "INPUT"), run("ip6tables", "-S", "INPUT")
	for range 2 {
		if err := Apply(ctx, Real, only(s), l); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range Families {
		if ok, err := Installed(ctx, Real, family, Lines(family, only(s), l)); !ok || err != nil {
			t.Fatal("not installed", family, err)
		}
		tool := map[int]string{4: "iptables", 6: "ip6tables"}[family]
		want := "-N " + Chain + "\n"
		for _, line := range Lines(family, only(s), l) {
			want += "-A " + Chain + " " + line + "\n"
		}
		if got := run(tool, "-S", Chain); got != want {
			t.Fatalf("%s -S differs\ngot:\n%s\nwant:\n%s", tool, got, want)
		}
		got := run(tool, "-S", "INPUT")
		if !strings.HasPrefix(got, "-P INPUT ACCEPT\n-A INPUT -j SFC-INPUT\n-A INPUT -p tcp -m tcp --dport 8080 -j DROP") || strings.Count(got, "SFC-INPUT") != 1 {
			t.Fatal(got)
		}
	}
	if out := run("iptables-save"); strings.Contains(out, "unsupported") || strings.Contains(out, "incompatible") {
		t.Fatal(out)
	}
	// An operator's own nft table with an input hook is shown too.
	if _, err := exec.LookPath("nft"); err == nil {
		run("nft", "add table inet ops")
		run("nft", "add chain inet ops in { type filter hook input priority -10; policy accept; }")
		run("nft", "add rule inet ops in iifname \"eth9\" tcp dport 25 ct state new counter drop")
	}
	op, _, err := Operator(ctx, Real)
	joined := strings.Join(op, "\n")
	if err != nil || !strings.Contains(joined, "ip filter INPUT (hook input, priority 0, policy accept)") || !strings.Contains(joined, "tcp dport 8080 counter drop") || strings.Contains(joined, "sfc lock") {
		t.Fatal(err, joined)
	}
	if _, err := exec.LookPath("nft"); err == nil && !strings.Contains(joined, "inet ops in (hook input, priority -10, policy accept)\n  iifname \"eth9\" meta l4proto tcp tcp dport 25 ct state new counter drop") {
		t.Fatal(joined)
	}
	t.Log("\n" + joined)
	// Someone flushes the chain: Installed notices.
	run("iptables", "-F", Chain)
	if ok, _ := Installed(ctx, Real, 4, Lines(4, only(s), l)); ok {
		t.Fatal("flushed chain reported installed")
	}
	if err := Remove(ctx, Real); err != nil {
		t.Fatal(err)
	}
	if run("iptables", "-S", "INPUT") != strings.Replace(before4, "-A INPUT -j SFC-INPUT\n", "", 1) || run("ip6tables", "-S", "INPUT") != strings.Replace(before6, "-A INPUT -j SFC-INPUT\n", "", 1) {
		t.Fatal("operator rules changed")
	}
	if err := Remove(ctx, Real); err != nil {
		t.Fatal("second remove", err)
	}
}
