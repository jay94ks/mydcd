// SPDX-License-Identifier: Apache-2.0

package cliprofile

import "testing"

func TestEndpointContract(t *testing.T) {
	good := []struct {
		input, uri, network, address string
		path                         bool
	}{
		{"", DefaultEndpoint, "unix", "/var/run/mydc.sock", false},
		{"/tmp/mydc.sock", "unix:///tmp/mydc.sock", "unix", "/tmp/mydc.sock", true},
		{"mydcp://CONTROL.example:7443", "mydcp://control.example:7443", "mydcp", "control.example:7443", true},
		{"mydcp://[2001:db8::1]:7443", "mydcp://[2001:db8::1]:7443", "mydcp", "[2001:db8::1]:7443", false},
		{"mydcp://127.0.0.1:7443", "mydcp://127.0.0.1:7443", "mydcp", "127.0.0.1:7443", false},
	}
	for _, tt := range good {
		t.Run(tt.input, func(t *testing.T) {
			e, err := ParseEndpoint(tt.input, tt.path)
			if err != nil || e.URI != tt.uri || e.Network != tt.network || e.Address != tt.address {
				t.Fatalf("endpoint: %+v %v", e, err)
			}
		})
	}
	for _, s := range []string{"http://host:80", "mydcp://host", "mydcp://host:0", "mydcp://host:65536", "mydcp://host:07443", "mydcp://u:p@host:7443", "mydcp://host:7443/", "mydcp://host:7443?", "mydcp://host:7443#", "mydcp://host:7443?q=x", "mydcp://host:7443/#x", "mydcp://2001:db8::1:7443", "mydcp://[fe80::1%25eth0]:7443", "mydcp://0.0.0.0:7443", "mydcp://[ff02::1]:7443", "mydcp://bad_host:7443", "mydcp://-host:7443", "mydcp://host.:7443", "unix://host/tmp/sock", "unix:relative", "unix://relative", "unix:///", "unix:///tmp/../sock", "unix:///tmp//sock", "unix:///tmp/sock?", "unix:///tmp/sock#", "unix:///tmp/%73ock", "unix:///@abstract\x00", " /tmp/sock", "/tmp/sock", "unix:///tmp\\sock"} {
		t.Run(s, func(t *testing.T) {
			if _, err := ParseEndpoint(s, false); err == nil {
				t.Fatal("accepted invalid endpoint")
			}
		})
	}
}
func TestLocalNamesDoNotBecomePaths(t *testing.T) {
	for _, s := range []string{"", "default", ".profile.yaml", ".", "..", "../production", "/tmp/p", "a/b", "a\\b", "a\x00b", "a b", "~user", "$HOME", "%2e%2e"} {
		if ValidName(s) {
			t.Fatalf("unsafe local name %q", s)
		}
	}
	for _, s := range []string{"production", "prod.us-east_1", "P1"} {
		if !ValidName(s) {
			t.Fatalf("valid local name %q", s)
		}
	}
	if !ValidKeyName("default") {
		t.Fatal("wallet key inherited local reserved name")
	}
}
