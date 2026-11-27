// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestNeedsPinnedNode(t *testing.T) {
	key := strings.Repeat("ab", 32)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ok := map[string]string{"SFC_WEB_CLUSTER": key, "SFC_WEB_NODE": "node-a", "SFC_WEB_NODE_KEY": key}
	c, err := Parse(nil, env(ok))
	if err != nil || c.Node != "node-a" {
		t.Fatalf("%+v %v", c, err)
	}
	if k, err := c.ClusterKey(); err != nil || k[0] != 0xab {
		t.Fatal(k, err)
	}
	for _, drop := range []string{"SFC_WEB_CLUSTER", "SFC_WEB_NODE", "SFC_WEB_NODE_KEY"} {
		m := map[string]string{}
		for k, v := range ok {
			if k != drop {
				m[k] = v
			}
		}
		if _, err := Parse(nil, env(m)); err == nil {
			t.Fatalf("accepted without %s", drop)
		}
	}
	if _, err := Parse([]string{"-node-key", strings.Repeat("00", 32)}, env(ok)); err == nil {
		t.Fatal("accepted a zero node key")
	}
	if _, err := Parse([]string{"-backend", "fake"}, env(ok)); err == nil {
		t.Fatal("accepted -backend")
	}
}

func TestACMEAdvertiseAddress(t *testing.T) {
	for _, tc := range []struct{ listen, advertise, want string }{
		{"", "10.0.0.5:80", ""},
		{"10.0.0.5:8402", "", "10.0.0.5:8402"},
		{"0.0.0.0:8402", "", ""},
		{":8402", "", ""},
		{"0.0.0.0:8402", "10.0.0.5:8402", "10.0.0.5:8402"},
	} {
		if got := (Config{ACMEListen: tc.listen, ACMEAdvertise: tc.advertise}).ACMEAdvertiseAddress(); got != tc.want {
			t.Fatalf("%+v: %q", tc, got)
		}
	}
}

func TestTrustedProxies(t *testing.T) {
	key := strings.Repeat("ab", 32)
	env := map[string]string{"SFC_WEB_CLUSTER": key, "SFC_WEB_NODE": "node-a", "SFC_WEB_NODE_KEY": key, "SFC_WEB_TRUSTED_PROXIES": "10.88.0.1, 10.89.0.0/24"}
	c, err := Parse(nil, func(k string) string { return env[k] })
	if err != nil || c.Socket != "/run/sfc/sfcdp.sock" {
		t.Fatalf("%+v %v", c, err)
	}
	nets, err := c.TrustedProxyNets()
	if err != nil || len(nets) != 2 || nets[0].String() != "10.88.0.1/32" || nets[1].String() != "10.89.0.0/24" {
		t.Fatalf("%v %v", nets, err)
	}
	if _, err := Parse([]string{"-trusted-proxies", "ingress"}, func(k string) string { return env[k] }); err == nil {
		t.Fatal("accepted a name")
	}
}
