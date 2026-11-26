// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/secrets"
)

func TestCDGroupApprovalUsesExistingPrivateJournalWithoutFakeComposeArtifact(t *testing.T) {
	home, c, session, _ := journalFixture(t)
	begin := control.AppBegin{Tenant: "tenant", App: "app", Deployment: "deploy", Upload: "original", Operation: "original"}
	payload, _ := json.Marshal(begin)
	origin := control.UserOperation{Schema: 1, Session: session, At: session.IssuedAt + 1, Epoch: 1, RequestID: "accept", Change: control.Change{Schema: 1, Principal: session.User, Action: "begin-app", Payload: payload}}
	origin.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(origin))
	target := secrets.Target{Cluster: c.Cluster, Tenant: "tenant", User: session.User, RequesterKey: session.Key, App: "app", Deployment: "deploy", Realm: "tenant", Group: "group", ApprovalID: "approval-original"}
	if err := PrepareComposeApprovals(home, c, session, "original"); err != nil {
		t.Fatal(err)
	}
	selector := &control.AppApprovalSelection{Candidate: &[32]byte{1}}
	peer := config.Peer{ID: c.Peers[0].ID, Key: hex.EncodeToString(c.Peers[0].Key[:]), Endpoint: c.Peers[0].Endpoint}
	a, err := LoadComposeApproval(home, c, session, "original", origin, target, peer, selector)
	if !errors.Is(err, ErrOperationMissing) || a.Selection == nil {
		t.Fatal("missing attempt was not explicit", err)
	}
	selector.Candidate[0] = 2
	if a.Selection.Candidate[0] != 1 {
		t.Fatal("approval retained mutable caller selector")
	}
	if err := StageComposeApproval(home, c, session, a); err != nil {
		t.Fatal(err)
	}
	other := &control.AppApprovalSelection{Operation: "accepted-next"}
	if _, err := LoadComposeApproval(home, c, session, "original", origin, target, peer, other); !errors.Is(err, ErrApprovalUnknown) {
		t.Fatal("new selection bypassed unknown original Group input", err)
	}
	if err := RecordComposeApproval(home, c, session, a, "confirmed"); err != nil {
		t.Fatal(err)
	}
	b, err := LoadComposeApproval(home, c, session, "original", origin, target, peer, other)
	if !errors.Is(err, ErrOperationMissing) || composeApprovalName(a) == composeApprovalName(b) {
		t.Fatal("different selected input adopted another attempt", err)
	}
	if _, err := LoadCompose(home, c, session, "original"); err == nil {
		t.Fatal("approval namespace fabricated an old deployment artifact")
	}
}
