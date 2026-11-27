// SPDX-License-Identifier: Apache-2.0

package sfcp

import "testing"

// Every purpose constant has one complete table entry: adding a purpose
// without its frame rules, sender rules and limits fails here, not at run
// time.
func TestPurposeTableComplete(t *testing.T) {
	defined := []Purpose{VolumeFS}
	for p := Handshake; p <= ChangeWatch; p++ {
		defined = append(defined, p)
	}
	for _, p := range defined {
		s, ok := specOf(p)
		if !ok || s.name == "" || s.shape == 0 || len(s.kinds) == 0 {
			t.Fatalf("purpose %d has no complete spec", p)
		}
		for kind, k := range s.kinds {
			if kind == 0 || len(k.fields) == 0 || k.budget <= 0 || k.budget > 65535+128 && k.budget > MaxBody {
				t.Fatalf("purpose %s kind %d rule", s.name, kind)
			}
			if (k.allow == nil) != (p == Handshake) {
				t.Fatalf("purpose %s kind %d sender rule", s.name, kind)
			}
		}
		streams := p != Handshake && p != Packet
		if streams != (s.limit > 0) || s.perPeer > s.limit {
			t.Fatalf("purpose %s limits %d/%d", s.name, s.limit, s.perPeer)
		}
		if s.local && (p == Handshake || p == Packet) {
			t.Fatalf("purpose %s cannot be local", s.name)
		}
	}
	if len(purposes) != len(defined) {
		t.Fatal("purpose table has an entry without a constant")
	}
}

// One peer cannot take a purpose's whole stream limit.
func TestPerPeerStreamShare(t *testing.T) {
	tr := &Transport{limits: newPurposeLimits()}
	a, b := Identity{1}, Identity{2}
	var releases []func()
	for range purposes[Management].perPeer {
		release, ok := tr.acquire(a, Management)
		if !ok {
			t.Fatal("peer share refused early")
		}
		releases = append(releases, release)
	}
	if _, ok := tr.acquire(a, Management); ok {
		t.Fatal("peer exceeded its share")
	}
	release, ok := tr.acquire(b, Management)
	if !ok {
		t.Fatal("other peer blocked by one peer's streams")
	}
	release()
	for _, r := range releases {
		r()
	}
	if len(tr.limits[Management]) != 0 || len(tr.streams.perPeer) != 0 {
		t.Fatal("permits leaked")
	}
	if _, ok := tr.acquire(a, Handshake); ok {
		t.Fatal("handshake has no stream budget")
	}
}

// The table's stream limits are the ones Transport used before S1.
func TestPurposeLimitsUnchanged(t *testing.T) {
	want := map[Purpose]int{NodeShell: 64, Management: 16, Raft: 32, Snapshot: 2, Observation: 8, PathControl: 8, User: 16, Membership: 8, SecretInput: 8, SecretFetch: 4, VolumeTransfer: 1, CheckerArtifact: 2, CheckerProbe: 2, ContainerSession: 8, CertificateMaterial: 2, VolumeFile: 2, ClusterBackup: 1, VaultValue: 4, ImageContent: 2, ChangeWatch: 32, VolumeFS: 64}
	got := newPurposeLimits()
	if len(got) != len(want) {
		t.Fatalf("limits = %d purposes, want %d", len(got), len(want))
	}
	for p, n := range want {
		if cap(got[p]) != n {
			t.Fatalf("purpose %d limit = %d, want %d", p, cap(got[p]), n)
		}
	}
}
