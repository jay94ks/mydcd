// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/containerops"
)

func TestContainerSessionPermitNeedsUserIntentAndExactLiveOwner(t *testing.T) {
	f, _, selection := logClearPlanFixture(t, "local")
	spec := containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"custom-cli"}, Stdin: true}}
	target, err := f.p.ContainerSessionTarget(f.s, ContainerSessionPlan{Session: f.session, Tenant: "tenant", Selection: selection, Spec: spec}, 11)
	if err != nil {
		t.Fatal("current exec target", err)
	}
	i := containerops.SessionIntent{Schema: 1, Request: "exec-original", User: f.session.User, Session: access.ExactSessionDigest(f.session), At: 11, Target: target, Spec: spec}
	i.Signature = ed25519.Sign(f.admin, containerops.SessionIntentBytes(i))
	q := ContainerSessionPermit{Session: f.session, Original: f.session, Intent: i}
	if _, err = f.p.ContainerSessionPermit(f.s, target.Owner, q, 11); err != nil {
		t.Fatal("original user execution", err)
	}
	for _, mutation := range []string{"member-forgery", "native", "generation", "started", "intent-user", "current-user", "original-session", "other-owner"} {
		bad := q
		caller := target.Owner
		switch mutation {
		case "member-forgery":
			bad.Intent.Signature = ed25519.Sign(f.node, containerops.SessionIntentBytes(bad.Intent))
		case "native":
			bad.Intent.Target.NativeID = "replacement"
			bad.Intent.Signature = ed25519.Sign(f.admin, containerops.SessionIntentBytes(bad.Intent))
		case "generation":
			bad.Intent.Target.Generation++
			bad.Intent.Signature = ed25519.Sign(f.admin, containerops.SessionIntentBytes(bad.Intent))
		case "started":
			bad.Intent.Target.StartedAt = "2026-01-01T00:00:00Z"
			bad.Intent.Signature = ed25519.Sign(f.admin, containerops.SessionIntentBytes(bad.Intent))
		case "intent-user":
			bad.Intent.User = "another-user"
		case "current-user":
			bad.Session.User = "another-user"
		case "original-session":
			bad.Original.ID = "another-session"
		case "other-owner":
			caller = [32]byte{99}
		}
		if _, err = f.p.ContainerSessionPermit(f.s, caller, bad, 11); err == nil {
			t.Fatal("unbound exec admitted", mutation)
		}
	}
	readOnly := f.session
	readOnly.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	readOnly.Signature = ed25519.Sign(f.node, access.SessionBytes(readOnly))
	if _, err = f.p.ContainerSessionTarget(f.s, ContainerSessionPlan{Session: readOnly, Tenant: "tenant", Selection: selection, Spec: spec}, 11); err == nil {
		t.Fatal("Read gained exec")
	}
	q.Session = readOnly
	q.Status = true
	if _, err = f.p.ContainerSessionPermit(f.s, target.Owner, q, 11); err == nil {
		t.Fatal("Read gained exec status")
	}
}

func TestContainerExecStatusUsesCurrentLoginAndRetainedOriginalProof(t *testing.T) {
	f, _, selection := logClearPlanFixture(t, "json-file")
	spec := containerops.SessionSpec{Kind: "exec", Exec: &containerops.ExecSpec{Argv: []string{"custom-cli"}}}
	target, err := f.p.ContainerSessionTarget(f.s, ContainerSessionPlan{Session: f.session, Tenant: "tenant", Selection: selection, Spec: spec}, 11)
	if err != nil {
		t.Fatal(err)
	}
	i := containerops.SessionIntent{Schema: 1, Request: "exec-original", User: f.session.User, Session: access.ExactSessionDigest(f.session), At: 11, Target: target, Spec: spec}
	i.Signature = ed25519.Sign(f.admin, containerops.SessionIntentBytes(i))
	current := f.session
	current.ID = "later-login"
	current.Key = [32]byte{13}
	current.Signature = ed25519.Sign(f.node, access.SessionBytes(current))
	q := ContainerSessionPermit{Session: current, Original: f.session, Intent: i, Status: true}
	if _, err = f.p.ContainerSessionPermit(f.s, target.Owner, q, 12); err != nil {
		t.Fatal("new login lost original status", err)
	}
	q.Status = false
	if _, err = f.p.ContainerSessionPermit(f.s, target.Owner, q, 12); err == nil {
		t.Fatal("later login became an original start permit")
	}
}
