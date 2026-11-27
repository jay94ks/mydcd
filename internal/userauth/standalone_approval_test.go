// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/secrets"
)

func standaloneApprovalFixture(t *testing.T, name string, targeted bool) (string, Client, access.Session, control.UserOperation, secrets.Target, config.Peer) {
	t.Helper()
	home, c, session, _ := journalFixture(t)
	// The scope predates a possible pin/public rename. Approval must retain it.
	scope := deployment.StandaloneScopeName("tenant", "original-name")
	begin := control.AppBegin{Standalone: &control.StandaloneDefinition{Name: name, Lifetime: "fixed", Mode: "entrypoint", Restart: "on-failure"}, Tenant: "tenant", App: scope, Deployment: "deploy", Upload: "service-create", Operation: "service-create"}
	if targeted {
		begin.Target = &[32]byte{7}
	}
	payload, _ := json.Marshal(begin)
	origin := control.UserOperation{Schema: 1, Session: session, At: session.IssuedAt + 1, Epoch: 1, RootRevision: 7, RequestID: "standalone/service-create/accept", Change: control.Change{Schema: 1, Principal: session.User, Action: "standalone-up", Expected: 4, Payload: payload}}
	origin.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(origin))
	target := secrets.Target{Cluster: c.Cluster, Tenant: "tenant", User: session.User, RequesterKey: session.Key, App: scope, Deployment: "deploy", Realm: "tenant", Group: "group", ApprovalID: "approval-original"}
	peer := config.Peer{ID: c.Peers[0].ID, Key: hex.EncodeToString(c.Peers[0].Key[:]), Endpoint: c.Peers[0].Endpoint}
	if err := PrepareComposeApprovals(home, c, session, begin.Operation); err != nil {
		t.Fatal(err)
	}
	if _, err := StageOperation(home, c, origin); err != nil {
		t.Fatal(err)
	}
	return home, c, session, origin, target, peer
}

func TestStandaloneGroupApprovalStagesOriginalAndReplaysConfirmedOrNotSent(t *testing.T) {
	for _, name := range []string{"original-name", "pinned-name"} {
		for _, targeted := range []bool{false, true} {
			label := name + "/legacy"
			if targeted {
				label = name + "/targeted"
			}
			t.Run(label, func(t *testing.T) {
				home, c, session, origin, target, peer := standaloneApprovalFixture(t, name, targeted)
				const id = "service-create"
				a, err := LoadComposeApproval(home, c, session, id, origin, target, peer)
				command, commandErr := origin.Command()
				raw, _ := json.Marshal(command)
				if !errors.Is(err, ErrOperationMissing) || commandErr != nil || a.Origin != sha256.Sum256(raw) || a.Target.App != target.App || a.Selection != nil {
					t.Fatal("standalone approval did not preserve exact original command/scope", err, commandErr)
				}
				if err = StageComposeApproval(home, c, session, a); err != nil {
					t.Fatal(err)
				}
				pending, err := LoadComposeApproval(home, c, session, id, origin, target, peer)
				if err != nil || pending.Outcome != "pending" || pending.Origin != a.Origin {
					t.Fatal("lost durable before-send identity", err)
				}
				if err = RecordComposeApproval(home, c, session, a, "not-sent"); err != nil {
					t.Fatal(err)
				}
				notSent, err := LoadComposeApproval(home, c, session, id, origin, target, peer)
				if err != nil || notSent.Outcome != "not-sent" || notSent.Origin != a.Origin {
					t.Fatal("lost positive not-sent outcome", err)
				}
				// Only explicit replay stages the same original after not-sent.
				if err = StageComposeApproval(home, c, session, a); err != nil {
					t.Fatal(err)
				}
				if err = RecordComposeApproval(home, c, session, a, "confirmed"); err != nil {
					t.Fatal(err)
				}
				confirmed, err := LoadComposeApproval(home, c, session, id, origin, target, peer)
				if err != nil || confirmed.Outcome != "confirmed" || confirmed.Origin != a.Origin || confirmed.Target.App != target.App {
					t.Fatal("confirmed original approval changed", err)
				}
				if StageComposeApproval(home, c, session, a) == nil || RecordComposeApproval(home, c, session, a, "confirmed") != nil {
					t.Fatal("confirmed approval was resent or lost idempotent outcome")
				}
				stored, err := LoadOperation(home, c, session, origin.RequestID)
				if err != nil || stored.Result != nil || !sameOperation(stored.Operation, origin) {
					t.Fatal("Group journal rewrote or accepted original management operation", err)
				}
				if _, err := LoadCompose(home, c, session, id); err == nil {
					t.Fatal("approval manufactured a standalone artifact")
				}
			})
		}
	}
}

func TestStandaloneGroupApprovalUnknownCannotAdoptChangedTargetOrSelection(t *testing.T) {
	home, c, session, origin, target, peer := standaloneApprovalFixture(t, "pinned-name", true)
	a, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer)
	if !errors.Is(err, ErrOperationMissing) || StageComposeApproval(home, c, session, a) != nil {
		t.Fatal("stage original pending", err)
	}
	// An interrupted private send stays pending. No new approval, policy path,
	// or approver may bypass that unknown send for the same realm/Group.
	for _, mode := range []string{"approval-id", "policy-path", "approver"} {
		t.Run(mode, func(t *testing.T) {
			other, node := target, peer
			switch mode {
			case "approval-id":
				other.ApprovalID = "replacement"
			case "policy-path":
				other.Path = []secrets.PolicyRef{{ID: "parent", Generation: 1, PolicyRevision: 1, AuthPolicy: 1}}
			case "approver":
				node.Key = hex.EncodeToString(bytes.Repeat([]byte{9}, 32))
			}
			if _, err := LoadComposeApproval(home, c, session, "service-create", origin, other, node); !errors.Is(err, ErrApprovalUnknown) {
				t.Fatal("unknown original input bypassed", err)
			}
		})
	}
	for _, selection := range []*control.AppApprovalSelection{{Operation: "cd-sync"}, {Candidate: &[32]byte{1}}} {
		if _, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer, selection); !errors.Is(err, ErrPrivateState) {
			t.Fatal("standalone adopted a CD selection", err)
		}
	}
	pending, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer)
	if err != nil || pending.Outcome != "pending" || pending.Origin != a.Origin {
		t.Fatal("unknown handling replaced original pending journal", err)
	}
}

func TestStandaloneGroupApprovalRejectsForgedIdentityModeDigestAndPath(t *testing.T) {
	home, c, session, origin, target, peer := standaloneApprovalFixture(t, "pinned-name", true)
	a, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer)
	if !errors.Is(err, ErrOperationMissing) || StageComposeApproval(home, c, session, a) != nil {
		t.Fatal("stage original pending", err)
	}
	for _, mode := range []string{"app", "tenant", "requester", "purpose", "origin", "digest", "mode", "valid-mode", "name", "lifetime", "valid-lifetime", "definition", "upload", "operation", "signed-scope", "path"} {
		t.Run(mode, func(t *testing.T) {
			op, other, id := origin, target, "service-create"
			var begin control.AppBegin
			if err := json.Unmarshal(origin.Change.Payload, &begin); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "app":
				other.App = "foreign-app"
			case "tenant":
				other.Tenant = "foreign-tenant"
			case "requester":
				other.RequesterKey[0] ^= 1
			case "purpose":
				other.Purpose = secrets.PurposeImageBuild
			case "origin":
				op.RootRevision++
			case "digest":
				begin.Target = &[32]byte{8}
			case "mode":
				begin.Standalone.Mode = "foreign-mode"
			case "valid-mode":
				begin.Standalone.Mode = "shell"
			case "name":
				begin.Standalone.Name = "foreign-name"
			case "lifetime":
				begin.Standalone.Lifetime = "forever"
			case "valid-lifetime":
				begin.Standalone.Lifetime, begin.Standalone.Restart = "temp", "no"
			case "definition":
				begin.Standalone = nil
			case "upload":
				begin.Upload = "other-upload"
			case "operation":
				begin.Operation = "other-operation"
			case "signed-scope":
				begin.App, other.App = "foreign-app", "foreign-app"
			case "path":
				id = "../service-create"
			}
			op.Change.Payload, _ = json.Marshal(begin)
			op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
			if _, err := LoadComposeApproval(home, c, session, id, op, other, peer); err == nil {
				t.Fatal("forged identity adopted the original pending approval")
			}
		})
	}
	// A modified operation without a matching user signature cannot even
	// construct the approval identity, regardless of the persisted outcome.
	forged := origin
	forged.Signature = append([]byte(nil), origin.Signature...)
	forged.Signature[0] ^= 1
	if _, err := LoadComposeApproval(home, c, session, "service-create", forged, target, peer); err == nil {
		t.Fatal("invalid original signature admitted")
	}
}

func TestStandaloneGroupApprovalRejectsTamperedJournalIdentity(t *testing.T) {
	home, c, session, origin, target, peer := standaloneApprovalFixture(t, "pinned-name", true)
	a, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer)
	if !errors.Is(err, ErrOperationMissing) || StageComposeApproval(home, c, session, a) != nil {
		t.Fatal("stage original pending", err)
	}
	root, err := composeRoot(home, c, session.User, "service-create", false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, mode := range []string{"origin-digest", "policy-path", "user", "profile", "compose-id", "cd-selection"} {
		t.Run(mode, func(t *testing.T) {
			bad := a
			switch mode {
			case "origin-digest":
				bad.Origin[0] ^= 1
			case "policy-path":
				bad.Target.Path = []secrets.PolicyRef{{ID: "forged-parent", Generation: 1}}
			case "user":
				bad.User = "foreign-user"
			case "profile":
				bad.Profile[0] ^= 1
			case "compose-id":
				bad.Compose = "foreign-operation"
			case "cd-selection":
				bad.Selection = &control.AppApprovalSelection{Operation: "cd-sync"}
			}
			if err := writePrivate(root, composeApprovalName(a), bad); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadComposeApproval(home, c, session, "service-create", origin, target, peer); !errors.Is(err, ErrPrivateState) {
				t.Fatal("tampered journal adopted original identity", err)
			}
			if err := writePrivate(root, composeApprovalName(a), a); err != nil {
				t.Fatal(err)
			}
		})
	}
}
