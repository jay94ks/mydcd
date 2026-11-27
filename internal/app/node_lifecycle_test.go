// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
)

// These are supplied configuration counterexamples, not SDK/quorum evidence.
func TestInstalledTopologyUsesOriginalKnownKeysAndActualNativeVoting(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	peer := config.Peer{ID: "node-a", Key: hex.EncodeToString(private.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:9001", Voter: true}
	directory, err := membership.New([32]byte{72}, peer)
	if err != nil {
		t.Fatal(err)
	}
	original := cluster.InstalledConfiguration{Index: 7, AppliedIndex: 9, Configuration: raft.Configuration{Servers: []raft.Server{{ID: raft.ServerID(peer.ID), Address: raft.ServerAddress(peer.Endpoint), Suffrage: raft.Voter}}}}
	result, err := installedTopology(original, directory)
	if err != nil || result.Index != 7 || result.Quorum() != 1 || !result.Standalone(peer.ID) {
		t.Fatal("known installed mapping", result, err)
	}
	var expected [32]byte
	copy(expected[:], private.Public().(ed25519.PublicKey))
	if result.Members[0].Key != expected {
		t.Fatal("mapping replaced original key")
	}
	for _, mutate := range []func(*cluster.InstalledConfiguration){
		func(c *cluster.InstalledConfiguration) { c.Index = 0 },
		func(c *cluster.InstalledConfiguration) { c.AppliedIndex = 6 },
		func(c *cluster.InstalledConfiguration) { c.Configuration.Servers[0].ID = "unknown" },
		func(c *cluster.InstalledConfiguration) { c.Configuration.Servers[0].Address = "127.0.0.1:9002" },
		func(c *cluster.InstalledConfiguration) { c.Configuration.Servers[0].Suffrage = raft.Staging },
		func(c *cluster.InstalledConfiguration) {
			c.Configuration.Servers = append(c.Configuration.Servers, c.Configuration.Servers[0])
		},
		func(c *cluster.InstalledConfiguration) { c.Configuration.Servers[0].Suffrage = raft.Nonvoter },
	} {
		candidate := original
		candidate.Configuration.Servers = append([]raft.Server(nil), original.Configuration.Servers...)
		mutate(&candidate)
		if _, err := installedTopology(candidate, directory); err == nil {
			t.Fatal("unproven or incompatible configuration accepted", candidate)
		}
	}
	after, _ := installedTopology(original, directory)
	if !reflect.DeepEqual(result, after) {
		t.Fatal("failed mapping changed original inputs")
	}
}
