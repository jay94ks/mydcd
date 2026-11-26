// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func TestNodeInvitationPinnedUnixAndNetworkSource(t *testing.T) {
	source, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(source.Private)
	target, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(target.Private)
	cluster := [32]byte{17}
	control := config.Peer{ID: "control", Key: source.Actor(), Endpoint: "127.0.0.1:7443", Voter: true}
	inv := membership.Invitation{Schema: 1, Cluster: cluster, Admin: source.Public, Genesis: control, Source: control,
		Target: config.Peer{ID: "joining", Key: target.Actor(), Endpoint: "127.0.0.1:7444"}, JoinID: "join-original", ApprovalRevision: 2, MinimumIndex: 7}
	inv.Signature = ed25519.Sign(source.Private, membership.InvitationBytes(inv))
	base := mydcp.Peer{ID: control.ID, Endpoint: control.Endpoint, Policy: mydcp.Policy{Key: mydcp.Identity(source.Public)}}
	cases := []struct {
		name, endpoint, node string
		key                  [32]byte
		change               func(*membership.Invitation)
		pass                 bool
	}{
		{name: "network-exact", endpoint: control.Endpoint, node: "joining", key: source.Public, pass: true},
		{name: "unix-pinned", endpoint: "unix:///var/run/mydc.sock", node: "joining", key: source.Public, pass: true},
		{name: "network-different", endpoint: "127.0.0.1:7445", node: "joining", key: source.Public},
		{name: "unclean-unix", endpoint: "unix:///tmp/../mydc.sock", node: "joining", key: source.Public},
		{name: "wrong-key", endpoint: "unix:///var/run/mydc.sock", node: "joining", key: target.Public},
		{name: "wrong-target", endpoint: "unix:///var/run/mydc.sock", node: "other", key: source.Public},
		{name: "tampered-source", endpoint: "unix:///var/run/mydc.sock", node: "joining", key: source.Public, change: func(i *membership.Invitation) { i.Source.Endpoint = "127.0.0.1:7446" }},
		{name: "tampered-id", endpoint: "unix:///var/run/mydc.sock", node: "joining", key: source.Public, change: func(i *membership.Invitation) { i.Source.ID = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := base
			peer.Endpoint = tc.endpoint
			peer.Key = mydcp.Identity(tc.key)
			candidate := inv
			if tc.change != nil {
				tc.change(&candidate)
			}
			client := Client{Cluster: cluster, Peers: []mydcp.Peer{peer}}
			if got := client.verifyNodeInvitation(candidate, tc.node); (got == nil) != tc.pass {
				t.Fatal("pinned signer/target/endpoint validation", got)
			}
		})
	}
}
