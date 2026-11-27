// SPDX-License-Identifier: Apache-2.0

package cliprofile

import "testing"

func TestEndpointContract(t *testing.T) {
	good := []struct {
		input, uri, network, address string
		path                         bool
	}{
		{"", DefaultEndpoint, "unix", "/run/sfcdp.sock", false},
		{"/tmp/sfcdp.sock", "unix:///tmp/sfcdp.sock", "unix", "/tmp/sfcdp.sock", true},
		{"sfcp://CONTROL.example:7443", "sfcp://control.example:7443", "sfcp", "control.example:7443", true},
		{"sfcp://[2001:db8::1]:7443", "sfcp://[2001:db8::1]:7443", "sfcp", "[2001:db8::1]:7443", false},
		{"sfcp://127.0.0.1:7443", "sfcp://127.0.0.1:7443", "sfcp", "127.0.0.1:7443", false},
	}
	for _, tt := range good {
		t.Run(tt.input, func(t *testing.T) {
			e, err := ParseEndpoint(tt.input, tt.path)
			if err != nil || e.URI != tt.uri || e.Network != tt.network || e.Address != tt.address {
				t.Fatalf("endpoint: %+v %v", e, err)
			}
		})
	}
	for _, s := range []string{"http://host:80", "sfcp://host", "sfcp://host:0", "sfcp://host:65536", "sfcp://host:07443", "sfcp://u:p@host:7443", "sfcp://host:7443/", "sfcp://host:7443?", "sfcp://host:7443#", "sfcp://host:7443?q=x", "sfcp://host:7443/#x", "sfcp://2001:db8::1:7443", "sfcp://[fe80::1%25eth0]:7443", "sfcp://0.0.0.0:7443", "sfcp://[ff02::1]:7443", "sfcp://bad_host:7443", "sfcp://-host:7443", "sfcp://host.:7443", "unix://host/tmp/sock", "unix:relative", "unix://relative", "unix:///", "unix:///tmp/../sock", "unix:///tmp//sock", "unix:///tmp/sock?", "unix:///tmp/sock#", "unix:///tmp/%73ock", "unix:///@abstract\x00", " /tmp/sock", "/tmp/sock", "unix:///tmp\\sock"} {
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
