// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/secrets"
)

func TestImageBuildGroupApprovalReusesOriginalJournalAndRejectsForeignScope(t *testing.T) {
	fixtureHome, c, session, _ := journalFixture(t)
	q := control.ImageBuildJobStart{Tenant: "tenant", Context: "source", ID: "job-one", Version: [32]byte{1}, Snapshot: [32]byte{2}, At: uint64(session.IssuedAt + 1)}
	payload, _ := json.Marshal(q)
	origin := control.UserOperation{Schema: 1, Session: session, At: session.IssuedAt + 1, Epoch: 1, RootRevision: 7, RequestID: "submit-one", Change: control.Change{Schema: 1, Principal: session.User, Action: "begin-image-build", Payload: payload}}
	origin.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(origin))
	target := secrets.Target{Purpose: secrets.PurposeImageBuild, Cluster: c.Cluster, Tenant: "tenant", User: session.User, RequesterKey: session.Key, App: control.ImageBuildSecretScope(q.Tenant, q.Context), Deployment: q.ID, Realm: "tenant", Group: "group", ApprovalID: "approval-original"}
	peer := config.Peer{ID: c.Peers[0].ID, Key: hex.EncodeToString(c.Peers[0].Key[:]), Endpoint: c.Peers[0].Endpoint}
	if err := PrepareComposeApprovals(fixtureHome, c, session, origin.RequestID); err != nil {
		t.Fatal(err)
	}
	a, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, origin, target, peer)
	if !errors.Is(err, ErrOperationMissing) || a.Compose != origin.RequestID || a.Target.Deployment != q.ID {
		t.Fatal("build request/job identities were conflated", err)
	}
	if err := StageComposeApproval(fixtureHome, c, session, a); err != nil {
		t.Fatal(err)
	}
	pending, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, origin, target, peer)
	if err != nil || pending.Outcome != "pending" || pending.Origin != a.Origin {
		t.Fatal("original pending approval lost", err)
	}
	changedApproval := target
	changedApproval.ApprovalID = "replacement"
	if _, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, origin, changedApproval, peer); !errors.Is(err, ErrApprovalUnknown) {
		t.Fatal("new approval bypassed the original unknown input", err)
	}
	for _, edit := range []func(*control.UserOperation, *secrets.Target){
		func(_ *control.UserOperation, t *secrets.Target) { t.Purpose = secrets.PurposeRegistrySource },
		func(_ *control.UserOperation, t *secrets.Target) { t.Tenant = "other" },
		func(_ *control.UserOperation, t *secrets.Target) {
			t.App = control.ImageBuildSecretScope(q.Tenant, "other")
		},
		func(_ *control.UserOperation, t *secrets.Target) { t.Deployment = "other-job" },
		func(o *control.UserOperation, _ *secrets.Target) { o.RequestID = "other-request" },
		func(o *control.UserOperation, _ *secrets.Target) { o.Change.Expected = 1 },
		func(o *control.UserOperation, _ *secrets.Target) {
			bad := q
			bad.Snapshot = [32]byte{}
			o.Change.Payload, _ = json.Marshal(bad)
		},
	} {
		op, bad := origin, target
		edit(&op, &bad)
		op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
		if _, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, op, bad, peer); err == nil {
			t.Fatal("foreign build approval scope accepted")
		}
	}
	selection := &control.AppApprovalSelection{Operation: "unrelated-app"}
	if _, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, origin, target, peer, selection); err == nil {
		t.Fatal("app selection accepted for a build approval")
	}
	if err := RecordComposeApproval(fixtureHome, c, session, a, "confirmed"); err != nil {
		t.Fatal(err)
	}
	confirmed, err := LoadComposeApproval(fixtureHome, c, session, origin.RequestID, origin, target, peer)
	if err != nil || confirmed.Outcome != "confirmed" || confirmed.Origin != a.Origin {
		t.Fatal("original confirmation changed", err)
	}
	if _, err := LoadCompose(fixtureHome, c, session, origin.RequestID); err == nil {
		t.Fatal("build approval fabricated an app deployment artifact")
	}
}
