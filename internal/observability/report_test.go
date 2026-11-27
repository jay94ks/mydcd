// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestNodeObservationSignatureAndOneSourceRemainMeasurementsOnly(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	r := Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 1000, Host: &Host{Version: "1", CPUCapacity: 2e9, ModuleReady: true}}
	r.Signature = ed25519.Sign(key, SigningBytes(r))
	raw, _ := json.Marshal(r)
	decoded, err := Decode(raw)
	if err != nil || decoded.Source() != "host" {
		t.Fatal("signed observation", err)
	}
	for _, change := range []func(*Report){
		func(r *Report) { r.Node = "other-node" },
		func(r *Report) { r.At++ },
		func(r *Report) {
			r.Host.CPUCapacity = 1
			value := uint64(2)
			r.Host.CPUUsed = &value
			r.Signature = ed25519.Sign(key, SigningBytes(*r))
		},
		func(r *Report) {
			r.Usage = &Usage{Tenant: "tenant", Complete: true}
			r.Signature = ed25519.Sign(key, SigningBytes(*r))
		},
	} {
		copy, err := Decode(raw)
		if err != nil {
			t.Fatal(err)
		}
		change(&copy)
		if copy.Valid() {
			t.Fatal("mutated/mixed source observation accepted")
		}
	}
	if Fresh(1001, 1000) || Fresh(0, 1000) || Fresh(1000, 1000+MaxAge+1) || !Fresh(1000, 1000+MaxAge) {
		t.Fatal("future/missing/stale observation promoted")
	}
}

func TestHostClusterAppsAreBoundedFixedValues(t *testing.T) {
	ok := ClusterApp{Name: "web", Control: "node-config", Image: "sfc/web", Version: "0.9.0", Ports: []ClusterAppPort{{Name: "web", Port: 8080, Protocol: "tcp"}}, Digest: "sha256:" + strings.Repeat("a", 64), State: "running", Address: "10.254.1.2"}
	if !ok.valid() {
		t.Fatal("valid row refused")
	}
	// another control policy or the unknown state keeps the report valid
	other := ok
	other.Control, other.State, other.Reason = "api", "unknown", "status-unavailable"
	if !other.valid() {
		t.Fatal("another control policy refused")
	}
	for name, bad := range map[string]ClusterApp{
		"state":   {Name: "web", Control: "node-config", State: "weird"},
		"control": {Name: "web", Control: "Bad Policy", State: "running"},
		"address": {Name: "web", Control: "node-config", State: "running", Address: "10.254.1.2/24"},
		"reason":  {Name: "web", Control: "node-config", State: "failed", Reason: "line\nbreak"},
		"name":    {Name: "Web", Control: "node-config", State: "running"},
		"port":    {Name: "web", Control: "node-config", State: "running", Ports: []ClusterAppPort{{Name: "web", Port: 0, Protocol: "tcp"}}},
		"version": {Name: "web", Control: "node-config", State: "running", Version: "0.9 beta"},
	} {
		if bad.valid() {
			t.Fatal(name)
		}
	}
}

// Via names a third member carrying a live link; a direct link leaves it empty.
func TestLinkViaNamesAThirdMemberOnALiveLink(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	sign := func(via, dialer string) Report {
		r := Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 2000, Link: &Link{ID: "node-a/node-b", Peer: "node-b", State: "up", Measurement: "quic-connection-cumulative", LastHandshakeAt: 1000, LastChangeAt: 1900, Dialer: dialer, Via: via}}
		r.Signature = ed25519.Sign(key, SigningBytes(r))
		return r
	}
	for _, c := range []struct {
		via, dialer string
		ok          bool
	}{{"", "node-a", true}, {"", "", true}, {"node-v", "node-a", true}, {"node-v", "", false}, {"node-a", "node-a", false}, {"node-b", "node-a", false}, {"Bad ID", "node-a", false}} {
		r := sign(c.via, c.dialer)
		raw, _ := json.Marshal(r)
		if _, err := Decode(raw); (err == nil) != c.ok {
			t.Fatalf("via=%q dialer=%q: err=%v, want ok=%t", c.via, c.dialer, err, c.ok)
		}
		if c.via == "" && bytes.Contains(raw, []byte(`"Via"`)) {
			t.Fatal("direct link serialized an empty Via")
		}
	}
}
