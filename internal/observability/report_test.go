// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
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
