// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestVolumeUsageReport(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	sign := func(u VolumeUsage) Report {
		r := Report{Kind: "node-observation", Schema: 1, Cluster: [32]byte{1}, Node: "node-a", Key: [32]byte(key.Public().(ed25519.PublicKey)), Index: 2, At: 5000, Volume: &u}
		r.Signature = ed25519.Sign(key, SigningBytes(r))
		return r
	}
	good := VolumeUsage{Key: "shop/php-shop/mysql-data", Binding: [32]byte{9}, Entries: 3, Files: 1, Directories: 2, LogicalBytes: 10, AllocatedBytes: 4096, ScannedAt: 4000}
	if r := sign(good); !r.Valid() || r.Source() != "volume/shop/php-shop/mysql-data" {
		t.Fatalf("valid sample rejected: %v %q", r.Valid(), r.Source())
	}
	for name, change := range map[string]func(*VolumeUsage){
		"no key":          func(u *VolumeUsage) { u.Key = "" },
		"newline key":     func(u *VolumeUsage) { u.Key = "a\nb" },
		"no binding":      func(u *VolumeUsage) { u.Binding = [32]byte{} },
		"no entries":      func(u *VolumeUsage) { u.Entries = 0 },
		"no root dir":     func(u *VolumeUsage) { u.Directories = 0 },
		"files > entries": func(u *VolumeUsage) { u.Files = 4 },
		"odd blocks":      func(u *VolumeUsage) { u.AllocatedBytes = 100 },
		"no scan time":    func(u *VolumeUsage) { u.ScannedAt = 0 },
		"future scan":     func(u *VolumeUsage) { u.ScannedAt = 5001 },
	} {
		u := good
		change(&u)
		if sign(u).Valid() {
			t.Fatalf("%s accepted", name)
		}
	}
	r := sign(good)
	r.Host = &Host{Version: "1", CPUCapacity: 1}
	r.Signature = ed25519.Sign(key, SigningBytes(r))
	if r.Valid() {
		t.Fatal("two sources in one report")
	}
}
