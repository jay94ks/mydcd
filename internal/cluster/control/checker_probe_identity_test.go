// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

// Installation reports are modeled facts. The same production membership/FSM
// reducers process each rotation; this is not a TLS/native execution proof.
func rotateCheckerProbeOwner(t *testing.T, f *backupCoreFixture, node string, old ed25519.PrivateKey, seed byte) ed25519.PrivateKey {
	t.Helper()
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	operation := fmt.Sprintf("checker-rotation-%s-%d", node, seed)
	members, _ := f.p.Members(f.s)
	entry, _ := members.Entry(node)
	f.apply(operation, "rotate-node-identity", entry.Revision, NodeIdentityChange{ID: node, Operation: operation}, state.Applied)
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: f.p.Cluster, Node: node, Operation: operation, Old: [32]byte(old.Public().(ed25519.PublicKey)), New: [32]byte(next.Public().(ed25519.PublicKey)), Prepared: [32]byte{seed}}
	proof.OldSignature = ed25519.Sign(old, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	for _, action := range []string{"identity-prepared", "identity-activate", "identity-installed"} {
		key := old
		if action == "identity-installed" {
			key = next
		}
		members, _ = f.p.Members(f.s)
		report := MemberReport{Schema: 1, Cluster: f.p.Cluster, Reporter: [32]byte(key.Public().(ed25519.PublicKey)), Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(MembersKey).Revision, RequestID: operation + "-" + action, Action: action, Node: node, Operation: operation, Expected: members.Revision}
		if action == "identity-prepared" {
			report.Identity = &proof
		}
		report.Signature = ed25519.Sign(key, MemberReportBytes(report))
		command, err := report.Command()
		if err != nil {
			t.Fatal(err)
		}
		nextState, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
		if err != nil || result.Code != state.Applied {
			t.Fatal(node, action, result, err)
		}
		f.s = nextState
	}
	return next
}

func TestCheckerProbeRetainedOwnersUseCurrentKeysAndKeepFrozenRequest(t *testing.T) {
	f, q, call, consumer, provider := checkerProbePermitFixture(t)
	before, err := f.p.CheckerProbePermit(f.s, consumer, q)
	if err != nil {
		t.Fatal(err)
	}
	queryBytes, _ := json.Marshal(q)
	originalApps := f.s.Object(AppsKey)
	routeReportControlConfiguration(t, f)
	a, b := f.node, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{125}, ed25519.SeedSize))
	obsolete := [][32]byte{consumer, provider}
	for i := byte(0); i < 2; i++ {
		a = rotateCheckerProbeOwner(t, f, "node-a", a, 181+i*2)
		b = rotateCheckerProbeOwner(t, f, "node-b", b, 182+i*2)
		currentA, currentB := [32]byte(a.Public().(ed25519.PublicKey)), [32]byte(b.Public().(ed25519.PublicKey))
		for _, caller := range [][32]byte{currentA, currentB} {
			permit, err := f.p.CheckerProbePermit(f.s, caller, q)
			original := before
			original.Index = permit.Index
			if err != nil || !permit.Matches(q, call) || permit != original || permit.Consumer != consumer || permit.Provider != provider {
				t.Fatal("rotation changed original run/call/target", err, permit)
			}
		}
		for _, caller := range append(obsolete, [32]byte{99}) {
			if _, err := f.p.CheckerProbePermit(f.s, caller, q); err == nil {
				t.Fatal("historical/foreign key authenticated current probe")
			}
		}
		if currentApps := f.s.Object(AppsKey); currentApps != originalApps {
			t.Fatal("rotation rewrote accepted original Task/binding/receipt")
		}
		after, _ := json.Marshal(q)
		if !bytes.Equal(queryBytes, after) {
			t.Fatal("permit rewrote frozen request")
		}
		obsolete = append(obsolete, currentA, currentB)
	}
	// Current authorization stays mandatory after either owner rotates.
	users, _ := f.p.Catalog(f.s)
	tenant, _ := users.Tenant("tenant")
	managedDNSChange(t, f, "checker-revoke-node-b", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}}, state.Applied)
	for _, caller := range [][32]byte{[32]byte(a.Public().(ed25519.PublicKey)), [32]byte(b.Public().(ed25519.PublicKey))} {
		if _, err := f.p.CheckerProbePermit(f.s, caller, q); err == nil {
			t.Fatal("old probe survived current tenant/node revocation")
		}
	}
}

func TestCheckerShutdownRetainedTaskUsesCurrentKeyWithoutActivation(t *testing.T) {
	f, q, original := shutdownPermitFixture(t)
	before, err := f.p.CheckerShutdownPermit(f.s, original, q)
	if err != nil {
		t.Fatal(err)
	}
	apps := f.s.Object(AppsKey)
	routeReportControlConfiguration(t, f)
	key := rotateCheckerProbeOwner(t, f, "node-a", f.node, 185)
	current := [32]byte(key.Public().(ed25519.PublicKey))
	permit, err := f.p.CheckerShutdownPermit(f.s, current, q)
	before.Index = permit.Index
	if err != nil || !reflect.DeepEqual(before, permit) || f.s.Object(AppsKey) != apps {
		t.Fatal("current shutdown changed original stop/task/binding", err)
	}
	if _, err := f.p.CheckerShutdownPermit(f.s, original, q); err == nil {
		t.Fatal("historical key authenticated current shutdown")
	}
	if _, err := f.p.AppBindingPermit(f.s, current, AppBindingRequest{Task: q.Task, Digest: q.Binding, At: q.At}); err == nil {
		t.Fatal("shutdown permission revived activation")
	}
	changed := q
	changed.Task.Revision++
	if _, err := f.p.CheckerShutdownPermit(f.s, current, changed); err == nil {
		t.Fatal("current key adopted a different original Task")
	}
}
