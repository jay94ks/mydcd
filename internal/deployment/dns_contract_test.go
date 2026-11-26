// SPDX-License-Identifier: Apache-2.0

package deployment

import "testing"

func TestComposeDNSReversePrefixBudgetsAndDisabledNoOwner(t *testing.T) {
	f := makeFixture(t)
	c := smallCompose(t)
	n := c.Networks["app"]
	d := &DNSDeclaration{Enabled: true, Reverse: true, Zone: "app.mydc.test", TTL: 30, NegativeTTL: 5, Transports: []string{"udp", "tcp"}}
	d.Limits.Cache, d.Limits.Inflight, d.Limits.TCP, d.Limits.Timeout = 4, 4, 2, 2000
	n.MyDC.DNS = d
	c.Networks["app"] = n
	if err := c.validate(); err != nil {
		t.Fatal("declared /24 reverse", err)
	}
	for _, invalid := range []func(){func() { d.TTL = 3601 }, func() { d.NegativeTTL = 31 }, func() { d.Limits.Cache = 4097 }, func() { p := n.MyDC.Pools["node-a"]; p.CIDR = "10.240.10.0/28"; n.MyDC.Pools["node-a"] = p }} {
		invalid()
		c.Networks["app"] = n
		if err := c.validate(); err == nil {
			t.Fatal("policy accepted a value native core rejects")
		}
		d.TTL, d.NegativeTTL, d.Limits.Cache = 30, 5, 4
	}
	d.Enabled = false
	c.Networks["app"] = n
	ctx := contextFor(t, f)
	ctx.Features["network-dns"] = true
	b, err := Compile(c, f.c, ctx)
	if err != nil {
		t.Fatal("explicit disabled DNS", err)
	}
	for _, step := range b.Steps() {
		if step.Kind == "dns" {
			t.Fatal("disabled DNS created a native owner step")
		}
	}
}
