// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestNeedsPinnedNode(t *testing.T) {
	key := strings.Repeat("ab", 32)
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	ok := map[string]string{"MYDC_WEB_CLUSTER": key, "MYDC_WEB_NODE": "node-a", "MYDC_WEB_NODE_KEY": key}
	c, err := Parse(nil, env(ok))
	if err != nil || c.Node != "node-a" {
		t.Fatalf("%+v %v", c, err)
	}
	if k, err := c.ClusterKey(); err != nil || k[0] != 0xab {
		t.Fatal(k, err)
	}
	for _, drop := range []string{"MYDC_WEB_CLUSTER", "MYDC_WEB_NODE", "MYDC_WEB_NODE_KEY"} {
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
