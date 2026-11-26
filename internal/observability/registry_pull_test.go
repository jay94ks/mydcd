// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
)

func TestRegistryPullReportRetainsOriginalTimeAndFiniteCodes(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	report := Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 2000,
		RegistryPull: &RegistryPull{Tenant: "tenant", Authority: "registry.example:443", Source: "private", Stage: "load", Code: "OK", CompletedAt: 1000, Sequence: 1}}
	sign := func(r *Report) { r.Signature = ed25519.Sign(key, SigningBytes(*r)) }
	sign(&report)
	raw, _ := json.Marshal(report)
	if !report.Valid() {
		t.Fatal("valid actual pull observation")
	}
	source := report.Source()
	for _, change := range []func(*Report){
		func(r *Report) { r.RegistryPull.Code = "password-echo" },
		func(r *Report) { r.RegistryPull.Stage = "login" },
		func(r *Report) { r.RegistryPull.Stage = "resolve" }, // OK metadata is not a full pull
		func(r *Report) { r.RegistryPull.CompletedAt = 2001 },
		func(r *Report) { r.RegistryPull.Authority = "user:password@registry.example" },
		func(r *Report) { r.RegistryPull.Sequence = 0 },
		func(r *Report) { r.Host = &Host{Version: "1"} },
	} {
		var copy Report
		if err := json.Unmarshal(raw, &copy); err != nil {
			t.Fatal(err)
		}
		change(&copy)
		sign(&copy)
		if copy.Valid() {
			t.Fatal("invalid public pull shape accepted", copy.RegistryPull)
		}
	}
	copy, _ := Decode(raw)
	copy.At = 9000
	sign(&copy)
	if !copy.Valid() || copy.RegistryPull.CompletedAt != 1000 || copy.Source() != source {
		t.Fatal("replication changed completion or source identity", copy)
	}
	copy.RegistryPull.Source = "rotated-definition"
	sign(&copy)
	if copy.Source() != source {
		t.Fatal("authority latest slot split by source definition")
	}
}
