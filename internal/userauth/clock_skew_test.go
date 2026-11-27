// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A session issued by a node whose clock runs a little ahead of the
// client's (ordinary NTP drift, WSL) is accepted; one from far in the future
// is not.
func TestSessionFromSlightlyFastIssuerClockIsAccepted(t *testing.T) {
	self, err := identity.Create(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, issuerPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := Client{Self: self, Cluster: [32]byte{1}, Peers: []sfcp.Peer{{ID: "node-a", Policy: sfcp.Policy{Key: sfcp.Identity(issuerPublic)}}}}
	now := time.Now().Unix()
	signed := func(issuedAt int64) access.Session {
		s := access.Session{Schema: 1, ID: "s1", Cluster: c.Cluster, User: "u1", Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: [32]byte(issuerPublic), IssuerEpoch: 1, IssuedAt: issuedAt, ExpiresAt: issuedAt + 600}
		s.Signature = ed25519.Sign(issuerPrivate, access.SessionBytes(s))
		return s
	}
	for _, ahead := range []int64{0, 1, 2, access.MaxClockSkewSeconds} {
		if err := c.verifyAt(signed(now+ahead), now); err != nil {
			t.Fatalf("issuer %ds ahead refused: %v", ahead, err)
		}
	}
	if c.verifyAt(signed(now+access.MaxClockSkewSeconds+1), now) == nil {
		t.Fatal("a session from beyond the skew allowance was accepted")
	}
}
