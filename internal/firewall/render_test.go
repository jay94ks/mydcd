// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

// The operator's chains are shown from every input hook, following jumps,
// without SFC-INPUT or the jump to it; unknown expressions keep their name.
func TestOperatorLines(t *testing.T) {
	filter := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	accept := nftables.ChainPolicyDrop
	input := &nftables.Chain{Name: "INPUT", Table: filter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter, Policy: &accept}
	ufw := &nftables.Chain{Name: "ufw-before-input", Table: filter}
	own := &nftables.Chain{Name: Chain, Table: filter}
	rules := map[string][]*nftables.Rule{
		"INPUT": {
			{Table: filter, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: Chain}}},
			{Table: filter, Exprs: []expr.Any{&expr.Counter{}, &expr.Verdict{Kind: expr.VerdictJump, Chain: "ufw-before-input"}}},
		},
		"ufw-before-input": {
			{Table: filter, Exprs: []expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: []byte{255, 255, 240, 0}, Xor: []byte{0, 0, 0, 0}}, &expr.Cmp{Register: 1, Data: []byte{10, 254, 240, 0}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1}, &expr.Cmp{Register: 1, Data: []byte{17}},
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Range{Register: 1, FromData: []byte{0x75, 0x30}, ToData: []byte{0x75, 0x94}},
				&expr.Quota{Bytes: 1}, &expr.Verdict{Kind: expr.VerdictAccept}}},
		},
		Chain: {{Table: filter, Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}}},
	}
	lines, truncated, err := operatorLines([]*nftables.Chain{input, ufw, own}, func(c *nftables.Chain) ([]*nftables.Rule, error) { return rules[c.Name], nil })
	got := strings.Join(lines, "\n")
	want := "ip filter INPUT (hook input, priority 0, policy drop)\n  counter jump ufw-before-input\nip filter ufw-before-input\n  ip saddr 10.254.240.0/20 ip protocol udp udp dport 30000-30100 Quota accept"
	if err != nil || truncated || got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
