// SPDX-License-Identifier: Apache-2.0

package services

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/storage"
)

// Only the test-owned, clean-paused DNS journal is changed. This is explicit
// prior-boot input, not evidence that Linux rebooted. The surrounding fixture
// owns the REAL Bridge/Task and subsequently performs actual socket rebind,
// endpoint queries and original retirement/rollback using the product owner.
func injectDNSPreviousBootJournal(t *testing.T, path string, options DNSOwnerOptions) {
	t.Helper()
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	raw, err := db.Get("dns-owner")
	if err != nil {
		t.Fatal(err)
	}
	var disk dnsOwnerDisk
	if err = json.Unmarshal(raw, &disk); err != nil || !disk.Stopped || len(disk.Bridges) == 0 {
		t.Fatal("test requires original clean-paused journal", err)
	}
	m, err := DecodeSettings(disk.Settings)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeDNSManager(disk.DNS)
	if err != nil || len(d.Queries()) != 0 {
		t.Fatal("test requires joined original queries", err)
	}
	previous := disk.Boot
	previous[0] ^= 0x80
	m, err = m.ResumeBoot(previous)
	if err != nil {
		t.Fatal(err)
	}
	// Preserve original operation IDs, target bytes and pins. Prior-boot native
	// facts are injected under the fixture key; no product collector is faked.
	for _, group := range m.groups {
		if group.Proof == nil {
			t.Fatal("missing original preparation proof")
		}
		proof := *group.Proof
		proof.Boot = previous
		proof.Signature = ed25519.Sign(options.Key, SettingsProofBytes(proof))
		m, err = m.Revalidate(proof)
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, scope := range m.scopes {
		if scope.Proof == nil {
			t.Fatal("missing original serving proof")
		}
		proof := *scope.Proof
		proof.Boot = previous
		proof.Signature = ed25519.Sign(options.Key, SettingsProofBytes(proof))
		m, err = m.Revalidate(proof)
		if err != nil {
			t.Fatal(err)
		}
	}
	for id, view := range d.views {
		if view.Hold.Boot != ([32]byte{}) {
			view.Hold.Boot = previous
		}
		if view.Last.Boot != ([32]byte{}) {
			view.Last.Boot = previous
		}
		d.views[id] = view
	}
	for i, b := range disk.Bridges {
		original := m.groups[b.Group].Binding.Native
		b.Original, b.Boot = &original, previous
		b.Namespace[0] ^= 0x40
		b.Index++
		disk.Bridges[i] = b
	}
	disk.Boot = previous
	disk.Settings, err = m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	disk.DNS, err = d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(disk)
	if err == nil {
		err = db.Write(map[string][]byte{"dns-owner": raw})
	}
	if err != nil {
		t.Fatal(err)
	}
}
