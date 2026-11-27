// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

// This verifies signed identity/linkage only. Current role admission, actual
// held target, owner/fence/copy and native activation remain separate contracts.
func TestCDMoveProofKeepsRequesterWhileAnotherAdministratorSigns(t *testing.T) {
	f, entry, proof := deliverySyncProofFixture(t, false)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{67}, 32))
	session := f.session
	session.User, session.Key = "operator", [32]byte(key.Public().(ed25519.PublicKey))
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	scope := f.scope
	scope.App, scope.ID = "source-app", "data"
	target := volumeFact(t, scope, "node-a", f.node).Spec
	target.Materialization = "m-" + proof.Choice.Operation
	anchor := &AppCDMoveSource{Registration: appRegistrationDigest(entry.Origin), Principal: entry.Delivery.Principal(), Requester: entry.Origin.Session.Key, PolicyRevision: entry.Delivery.PolicyRevision(), OverrideRevision: entry.Delivery.OverrideRevision(), Intent: proof.Intent, Input: proof.Artifact}
	move := VolumeMoveBegin{Scope: scope, ID: proof.Choice.Operation, Target: target, App: &VolumeMoveApp{Operation: "run-source-app", Revision: entry.Inventory.Revision(), Plan: [32]byte{5}, CD: anchor, Target: &VolumeMoveTargetApp{Upload: proof.Choice.Operation, Operation: proof.Choice.Operation, Plan: [32]byte{6}}}}
	payload, _ := json.Marshal(move)
	origin := *proof.User
	origin.Session, origin.Change.Principal, origin.Change.Action, origin.Change.Payload = session, session.User, "begin-volume-move", payload
	origin.Signature = ed25519.Sign(key, OperationBytes(origin))
	proof.User = &origin
	if err := proof.verify(entry.Origin, entry.Inventory.Scope()); err != nil {
		t.Fatal("explicit move required changing source requester", err)
	}
	identity, err := appExecutionOrigin(entry.Origin, &proof, entry.Inventory.Scope())
	old, _ := entry.Origin.Command()
	operator, _ := origin.Command()
	if err != nil || identity.Submitter != old.Actor || identity.Submitter == operator.Actor {
		t.Fatal("move signer replaced original execution namespace", identity, err)
	}
	entry.Sync = &proof
	if !sameMoveExecution(entry, origin) || !sameMoveBinding(AppBindingSource{Origin: entry.Origin, Sync: &proof}, origin) {
		t.Fatal("move could not consume its original target/binding proof")
	}
	if !cdMoveSourceMatches(entry, anchor, true) {
		t.Fatal("current source anchor not recognized")
	}
	for _, mutate := range []func(*AppCDMoveSource){
		func(s *AppCDMoveSource) { s.Registration[0] ^= 1 },
		func(s *AppCDMoveSource) { s.Principal = "operator" },
		func(s *AppCDMoveSource) { s.Requester = session.Key },
		func(s *AppCDMoveSource) { s.PolicyRevision++ },
	} {
		changed := *anchor
		mutate(&changed)
		if cdMoveSourceMatches(entry, &changed, true) {
			t.Fatal("move adopted another source/current policy")
		}
	}
	bad := proof
	bad.Artifact[0] ^= 1
	if bad.verify(entry.Origin, entry.Inventory.Scope()) == nil {
		t.Fatal("signed target accepted another public input")
	}
}
