// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"testing"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

func TestProbeNormalizationKeepsOriginalEffectIDAndOwnsActualSDKInputs(t *testing.T) {
	r := probeRequest()
	p := sourcePolicy()
	p.Execution.Capabilities = []string{"dependency", "exec", "file", "healthz"}
	c := ProbeCall{Schema: 1, Binding: requestDigest(r), Sequence: 1, DeadlineUnixMilli: r.DeadlineUnixMilli, Kind: "healthz", HTTP: &contract.HTTPProbe{Service: "web", Path: "/ready", Port: 8080}}
	n, err := NormalizeProbeCall(r, p, c)
	if err != nil || n.ID() != c.ID() || n.Digest() == c.Digest() || n.HTTP.Method != "GET" || n.HTTP.MaxBytes != 4096 || len(n.HTTP.ExpectedStatus) != 1 || n.HTTP.ExpectedStatus[0] != 200 {
		t.Fatal("normalization changed original effect or lost defaults", err)
	}
	c.HTTP.Path = "/different"
	if n.HTTP.Path != "/ready" {
		t.Fatal("native input aliases raw helper frame")
	}
	for _, bad := range []string{"http://other/", "//other/", "/ready#fragment", "/ready\r\nheader"} {
		c.HTTP.Path = bad
		if _, err := NormalizeProbeCall(r, p, c); err == nil {
			t.Fatal("unsafe HTTP input accepted", bad)
		}
	}
	c = ProbeCall{Schema: 1, Binding: requestDigest(r), Sequence: 1, DeadlineUnixMilli: r.DeadlineUnixMilli, Kind: "file", File: &contract.FileProbe{Service: "web", Path: "/ready"}}
	n, err = NormalizeProbeCall(r, p, c)
	if err != nil || n.File.Kind != "any" || n.ID() != c.ID() {
		t.Fatal("file shared normalization", err)
	}
	p.Execution.Capabilities = []string{"exec"}
	if _, err := NormalizeProbeCall(r, p, c); err == nil {
		t.Fatal("undeclared native capability admitted")
	}
	p = sourcePolicy()
	c.File.Service = "other"
	if _, err := NormalizeProbeCall(r, p, c); err == nil {
		t.Fatal("unbound native target admitted")
	}
	c.File.Service = "web"
	c.DeadlineUnixMilli++
	if _, err := NormalizeProbeCall(r, p, c); err == nil {
		t.Fatal("probe extended original deadline")
	}
}
