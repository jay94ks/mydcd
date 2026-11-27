// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

func installationIdentityFixture(t *testing.T) (lifecycle.Root, membership.Directory) {
	t.Helper()
	clusterID := [32]byte{91}
	old := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, 32))
	middle := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{93}, 32))
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{94}, 32))
	defer clear(old)
	defer clear(middle)
	defer clear(next)
	oldKey := [32]byte(old.Public().(ed25519.PublicKey))
	root, err := lifecycle.Prepare(lifecycle.Join, clusterID, [32]byte{95}, lifecycle.Member{ID: "node-c", Key: oldKey}, "original-join")
	if err != nil {
		t.Fatal(err)
	}
	root, err = root.Install(clusterID, lifecycle.Configuration{Index: 57, Members: []lifecycle.Member{{ID: "node-a", Key: [32]byte{95}, Voter: true}, {ID: "node-c", Key: oldKey}}}, 57)
	if err != nil {
		t.Fatal(err)
	}
	for i, keys := range [][2]ed25519.PrivateKey{{old, middle}, {middle, next}} {
		proof := lifecycle.IdentityProof{Schema: 1, Cluster: clusterID, Node: "node-c", Operation: []string{"rotation-one", "rotation-two"}[i], Old: [32]byte(keys[0].Public().(ed25519.PublicKey)), New: [32]byte(keys[1].Public().(ed25519.PublicKey)), Prepared: [32]byte{1}}
		proof.OldSignature = ed25519.Sign(keys[0], lifecycle.IdentityProofBytes(proof))
		proof.NewSignature = ed25519.Sign(keys[1], lifecycle.IdentityProofBytes(proof))
		root, err = root.RotateIdentity(proof, uint64(23+i))
		if err != nil {
			t.Fatal(err)
		}
	}
	entry := membership.Entry{Peer: config.Peer{ID: "node-c", Key: hex.EncodeToString(oldKey[:]), Endpoint: "127.0.0.1:1234", Voter: true}, Phase: membership.Active, Keys: lifecycle.OwnIdentityTransitions(root.Keys)}
	// The topology revision is a different coordinate from Root's command
	// index, even though the original activation index and proofs are identical.
	entry.Keys[0].Revision = 70
	entry.Keys[1].Revision = 80
	return root, membership.Directory{Schema: 1, Cluster: clusterID, Entries: []membership.Entry{entry}}
}

func TestInstallationIdentityWaitsOnlyForExactRetainedLocalPrefix(t *testing.T) {
	root, directory := installationIdentityFixture(t)
	original, _ := json.Marshal(root)
	for _, count := range []int{0, 1} {
		prefix := directory
		prefix.Entries = []membership.Entry{directory.Entries[0]}
		prefix.Entries[0].Keys = lifecycle.OwnIdentityTransitions(directory.Entries[0].Keys[:count])
		if err := installationIdentityReady(root, prefix); !errors.Is(err, cluster.ErrRecovering) {
			t.Fatal("prepared/earlier activation prefix failed instead of recovering", count, err)
		}
	}
	// This is the original native failure boundary: a configuration projected
	// from the pre-activation local entry cannot install into the new-key Root.
	stale := lifecycle.Configuration{Index: 76, Members: []lifecycle.Member{{ID: "node-a", Key: [32]byte{95}, Voter: true}, {ID: "node-c", Key: root.OriginalKey(), Voter: true}}}
	if _, err := root.Install(root.Cluster, stale, 91); err == nil {
		t.Fatal("old peer key unexpectedly installed into current Root")
	}
	if err := installationIdentityReady(root, directory); err != nil {
		t.Fatal("exact applied lineage remained blocked", err)
	}
	stale.Members[1].Key = root.Self.Key
	installed, err := root.Install(root.Cluster, stale, 91)
	if err != nil || installed.OriginalKey() != root.OriginalKey() || installed.Self != root.Self || len(installed.Keys) != len(root.Keys) {
		t.Fatal("catch-up changed original identity/role/lineage", err)
	}
	after, _ := json.Marshal(root)
	if !bytes.Equal(original, after) {
		t.Fatal("readiness check changed original Root")
	}
}

func TestInstallationIdentityRejectsDifferentLineageRatherThanWaiting(t *testing.T) {
	root, directory := installationIdentityFixture(t)
	for name, change := range map[string]func(*lifecycle.Root, *membership.Directory){
		"cluster": func(_ *lifecycle.Root, d *membership.Directory) { d.Cluster[0]++ },
		"different-original": func(_ *lifecycle.Root, d *membership.Directory) {
			d.Entries[0].Peer.Key = hex.EncodeToString(make([]byte, 32))
		},
		"invalid-signature": func(_ *lifecycle.Root, d *membership.Directory) { d.Entries[0].Keys[0].Proof.OldSignature[0]++ },
		"other-activation":  func(_ *lifecycle.Root, d *membership.Directory) { d.Entries[0].Keys[0].Index++ },
		"longer-lineage": func(_ *lifecycle.Root, d *membership.Directory) {
			d.Entries[0].Keys = append(d.Entries[0].Keys, d.Entries[0].Keys[1])
		},
		"invalid-selector": func(r *lifecycle.Root, _ *membership.Directory) { r.Self.Key[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			r := root
			r.Keys = lifecycle.OwnIdentityTransitions(root.Keys)
			d := directory
			d.Entries = []membership.Entry{directory.Entries[0]}
			d.Entries[0].Keys = lifecycle.OwnIdentityTransitions(directory.Entries[0].Keys)
			change(&r, &d)
			if err := installationIdentityReady(r, d); err == nil || errors.Is(err, cluster.ErrRecovering) {
				t.Fatal("different authority was accepted or hidden as catch-up", err)
			}
		})
	}
}

func TestInstallationIdentityDoesNotChangeLegacyUnrotatedGate(t *testing.T) {
	root, directory := installationIdentityFixture(t)
	root.Self.Key = root.OriginalKey()
	root.Keys = nil
	for i := range root.Installed.Members {
		if root.Installed.Members[i].ID == root.Self.ID {
			root.Installed.Members[i].Key = root.Self.Key
		}
	}
	if root.Validate() != nil {
		t.Fatal("invalid legacy fixture")
	}
	if err := installationIdentityReady(root, directory); err != nil {
		t.Fatal("rotation helper added an unrelated legacy installation condition", err)
	}
}

func otherMemberInstallationFixture(t *testing.T, middle bool) (lifecycle.Root, membership.Directory, lifecycle.Configuration) {
	t.Helper()
	rotated, directory := installationIdentityFixture(t)
	configuration := lifecycle.Configuration{Index: rotated.Installed.Index, Members: append([]lifecycle.Member(nil), rotated.Installed.Members...)}
	retained := lifecycle.Configuration{Index: configuration.Index, Members: append([]lifecycle.Member(nil), configuration.Members...)}
	retained.Members[1].Key = rotated.OriginalKey()
	if middle {
		retained.Members[1].Key = rotated.Keys[0].Proof.New
	}
	self := retained.Members[0]
	root, err := lifecycle.Prepare(lifecycle.Init, rotated.Cluster, self.Key, self, "original-install")
	if err == nil {
		root, err = root.Install(rotated.Cluster, lifecycle.Configuration{Index: 1, Members: []lifecycle.Member{self}}, 1)
	}
	if err == nil {
		root, err = root.Install(rotated.Cluster, retained, rotated.AppliedIndex)
	}
	if err != nil {
		t.Fatal(err)
	}
	return root, directory, configuration
}

func TestInstallationConfigurationPreservesOtherMemberHistoricalKeyAtSameSDKIndex(t *testing.T) {
	for _, middle := range []bool{false, true} {
		root, directory, current := otherMemberInstallationFixture(t, middle)
		if _, err := root.Install(root.Cluster, current, 91); err == nil {
			t.Fatal("fixture did not reproduce same-index other-member key refusal")
		}
		before, _ := json.Marshal(current)
		projected, err := installationConfiguration(root, directory, current)
		if err != nil || projected.Index != current.Index || projected.Members[1].Key != root.Installed.Members[1].Key {
			t.Fatal("validated original/intermediate key not retained", middle, err)
		}
		installed, err := root.Install(root.Cluster, projected, 91)
		if err != nil || installed.Installed.Index != root.Installed.Index || installed.Self != root.Self || installed.Installed.Members[1].Key != root.Installed.Members[1].Key {
			t.Fatal("same SDK configuration could not resume original installation", middle, err)
		}
		after, _ := json.Marshal(current)
		entry, _ := directory.Entry("node-c")
		key := entry.Keys[len(entry.Keys)-1].Proof.New
		if !bytes.Equal(before, after) || current.Members[1].Key != key || projected.Members[1].Key == key || entry.CurrentPeer().Key != hex.EncodeToString(key[:]) {
			t.Fatal("installation projection changed current peer authority or caller input")
		}
	}
}

func TestInstallationConfigurationRejectsUnprovenKeysAndSameIndexMembershipChanges(t *testing.T) {
	base, directory, configuration := otherMemberInstallationFixture(t, false)
	for name, change := range map[string]func(*lifecycle.Root, *membership.Directory, *lifecycle.Configuration){
		"foreign-cluster": func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) { d.Cluster[0]++ },
		"missing-member":  func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) { d.Entries = nil },
		"other-origin": func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) {
			d.Entries[0].Peer.Key = hex.EncodeToString(bytes.Repeat([]byte{99}, 32))
		},
		"invalid-proof": func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) {
			d.Entries[0].Keys[0].Proof.NewSignature[0]++
		},
		"omitted-prefix": func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) {
			d.Entries[0].Keys = d.Entries[0].Keys[1:]
		},
		"missing-lineage": func(_ *lifecycle.Root, d *membership.Directory, _ *lifecycle.Configuration) { d.Entries[0].Keys = nil },
		"unrelated-retained-key": func(r *lifecycle.Root, _ *membership.Directory, _ *lifecycle.Configuration) {
			r.Installed.Members[1].Key = [32]byte{100}
		},
		"role": func(_ *lifecycle.Root, _ *membership.Directory, c *lifecycle.Configuration) {
			c.Members[1].Voter = !c.Members[1].Voter
		},
		"id": func(_ *lifecycle.Root, _ *membership.Directory, c *lifecycle.Configuration) {
			c.Members[1].ID = "node-d"
		},
		"removed-member": func(_ *lifecycle.Root, _ *membership.Directory, c *lifecycle.Configuration) {
			c.Members = c.Members[:1]
		},
		"swapped-keys": func(_ *lifecycle.Root, _ *membership.Directory, c *lifecycle.Configuration) {
			c.Members[0].Key, c.Members[1].Key = c.Members[1].Key, c.Members[0].Key
		},
		"stale-self": func(_ *lifecycle.Root, _ *membership.Directory, c *lifecycle.Configuration) {
			c.Members[0].Key = [32]byte{101}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.Installed.Members = append([]lifecycle.Member(nil), base.Installed.Members...)
			d := directory
			d.Entries = []membership.Entry{directory.Entries[0]}
			d.Entries[0].Keys = lifecycle.OwnIdentityTransitions(directory.Entries[0].Keys)
			c := lifecycle.Configuration{Index: configuration.Index, Members: append([]lifecycle.Member(nil), configuration.Members...)}
			change(&r, &d, &c)
			if _, err := installationConfiguration(r, d, c); err == nil || errors.Is(err, cluster.ErrRecovering) {
				t.Fatal("unproven key or membership change became historical evidence", err)
			}
		})
	}
}

func TestInstallationConfigurationLeavesNewSDKIndexAndLegacyKeysUnchanged(t *testing.T) {
	root, directory, current := otherMemberInstallationFixture(t, false)
	current.Index++
	projected, err := installationConfiguration(root, directory, current)
	left, _ := json.Marshal(current)
	right, _ := json.Marshal(projected)
	if err != nil || !bytes.Equal(left, right) {
		t.Fatal("new SDK configuration did not use current keys", err)
	}
	root, err = root.Install(root.Cluster, current, 91)
	if err != nil {
		t.Fatal("valid newer SDK configuration could not install", err)
	}
	directory.Entries[0].Peer.Key = directory.Entries[0].CurrentPeer().Key
	directory.Entries[0].Keys = nil
	projected, err = installationConfiguration(root, directory, current)
	right, _ = json.Marshal(projected)
	if err != nil || !bytes.Equal(left, right) {
		t.Fatal("unchanged unrotated member key bytes changed", err)
	}
}
