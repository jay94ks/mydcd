// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
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
	base := sfcp.Peer{ID: control.ID, Endpoint: control.Endpoint, Policy: sfcp.Policy{Key: sfcp.Identity(source.Public)}}
	cases := []struct {
		name, endpoint, node string
		key                  [32]byte
		change               func(*membership.Invitation)
		pass                 bool
	}{
		{name: "network-exact", endpoint: control.Endpoint, node: "joining", key: source.Public, pass: true},
		{name: "unix-pinned", endpoint: "unix:///run/sfcdp.sock", node: "joining", key: source.Public, pass: true},
		{name: "network-different", endpoint: "127.0.0.1:7445", node: "joining", key: source.Public},
		{name: "unclean-unix", endpoint: "unix:///tmp/../sfcdp.sock", node: "joining", key: source.Public},
		{name: "wrong-key", endpoint: "unix:///run/sfcdp.sock", node: "joining", key: target.Public},
		{name: "wrong-target", endpoint: "unix:///run/sfcdp.sock", node: "other", key: source.Public},
		{name: "tampered-source", endpoint: "unix:///run/sfcdp.sock", node: "joining", key: source.Public, change: func(i *membership.Invitation) { i.Source.Endpoint = "127.0.0.1:7446" }},
		{name: "tampered-id", endpoint: "unix:///run/sfcdp.sock", node: "joining", key: source.Public, change: func(i *membership.Invitation) { i.Source.ID = "other" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := base
			peer.Endpoint = tc.endpoint
			peer.Key = sfcp.Identity(tc.key)
			candidate := inv
			if tc.change != nil {
				tc.change(&candidate)
			}
			client := Client{Cluster: cluster, Peers: []sfcp.Peer{peer}}
			if got := client.verifyNodeInvitation(candidate, tc.node, nil); (got == nil) != tc.pass {
				t.Fatal("pinned signer/target/endpoint validation", got)
			}
		})
	}
}

// After a leader change the node the CLI talks to relays the request and
// the leader signs as itself. A leader the context does not pin is trusted
// only when the pinned node's member list shows it as a full voting member
// with the same key and address; otherwise the error names the signer and
// says what to do.
func TestNodeInvitationSignedByAMemberThePinnedNodeVouchesFor(t *testing.T) {
	pinned, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(pinned.Private)
	leader, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leader.Private)
	joining, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(joining.Private)
	cluster := [32]byte{17}
	source := config.Peer{ID: "jay3", Key: leader.Actor(), Endpoint: "192.0.2.12:7443", Voter: true}
	inv := membership.Invitation{Schema: 1, Cluster: cluster, Admin: pinned.Public, Genesis: config.Peer{ID: "jay2", Key: pinned.Actor(), Endpoint: "192.0.2.11:7443", Voter: true}, Source: source,
		Target: config.Peer{ID: "vps1", Key: joining.Actor(), Endpoint: "198.51.100.7:7443"}, JoinID: "join-original", ApprovalRevision: 2, MinimumIndex: 7}
	inv.Signature = ed25519.Sign(leader.Private, membership.InvitationBytes(inv))
	client := Client{Cluster: cluster, Peers: []sfcp.Peer{{ID: "jay2", Endpoint: "unix:///run/sfcdp.sock", Policy: sfcp.Policy{Key: sfcp.Identity(pinned.Public)}}}}
	var untrusted *UntrustedSourceError
	if err := client.verifyNodeInvitation(inv, "vps1", nil); !errors.As(err, &untrusted) || !errors.Is(err, sfcp.ErrAdmission) || untrusted.Node != "jay3" || !strings.Contains(err.Error(), "sfcli context trust") {
		t.Fatalf("no member list: %v", err)
	}
	member := membership.Entry{Peer: source, Phase: membership.Active}
	for _, tc := range []struct {
		name   string
		change func(*membership.Entry)
		pass   bool
	}{
		{name: "voting-member", pass: true},
		{name: "not-a-voter", change: func(e *membership.Entry) { e.Peer.Voter = false }},
		{name: "still-joining", change: func(e *membership.Entry) { e.Phase = membership.Learner }},
		{name: "other-key", change: func(e *membership.Entry) { e.Peer.Key = pinned.Actor() }},
		{name: "other-address", change: func(e *membership.Entry) { e.Peer.Endpoint = "192.0.2.99:7443" }},
		{name: "other-node", change: func(e *membership.Entry) { e.Peer.ID = "jay4" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := member
			if tc.change != nil {
				tc.change(&e)
			}
			if got := client.verifyNodeInvitation(inv, "vps1", []membership.Entry{e}); (got == nil) != tc.pass {
				t.Fatal(got)
			}
		})
	}
	// a vouched-for signer still has to have signed it
	forged := inv
	forged.Signature = ed25519.Sign(pinned.Private, membership.InvitationBytes(inv))
	if err := client.verifyNodeInvitation(forged, "vps1", []membership.Entry{member}); err == nil || errors.As(err, &untrusted) {
		t.Fatalf("forged: %v", err)
	}
}
