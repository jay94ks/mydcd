// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"testing"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
)

func TestBuiltinSecretObservationNeedsVoterMajority(t *testing.T) {
	f := newBackupCore(t)
	voter := [32]byte(f.node.Public().(ed25519.PublicKey))
	other := [32]byte(f.admin.Public().(ed25519.PublicKey))
	applied := secrets.WriteObservation{Outcome: reconcile.EffectApplied, Reporter: voter, Holders: []secrets.HolderReceipt{{Voter: voter}}}
	if !f.p.builtinHolders(f.s, applied) {
		t.Fatal("the only voter holds it")
	}
	applied.Reporter = other
	if f.p.builtinHolders(f.s, applied) {
		t.Fatal("a non-voter reported")
	}
	applied.Reporter, applied.Holders = voter, nil
	if f.p.builtinHolders(f.s, applied) {
		t.Fatal("no holder majority")
	}
	applied.Holders = []secrets.HolderReceipt{{Voter: voter}, {Voter: other}}
	if f.p.builtinHolders(f.s, applied) {
		t.Fatal("a non-voter holder")
	}
	unknown := secrets.WriteObservation{Outcome: reconcile.EffectUnknown, Reporter: voter}
	if !f.p.builtinHolders(f.s, unknown) {
		t.Fatal("a voter cannot report unknown")
	}
}

func TestBuiltinLeafNeedsAPublishedHoldingAndAVoterProvider(t *testing.T) {
	f := newBackupCore(t)
	voter := [32]byte(f.node.Public().(ed25519.PublicKey))
	other := [32]byte(f.admin.Public().(ed25519.PublicKey))
	builtin := secrets.BuiltinWriteProfile()
	if !f.p.servesProvider(f.s, voter, builtin) || f.p.servesProvider(f.s, other, builtin) {
		t.Fatal("only a current voter serves builtin leaves")
	}
	tree, err := secrets.NewTree(f.p.Cluster, "tenant", "root")
	if err != nil {
		t.Fatal(err)
	}
	plan := secrets.UsePlan{Leaves: []secrets.Leaf{{Secret: "token", Reference: secrets.Reference{Profile: secrets.BuiltinProfile, Object: "token", Revision: 1, Keys: []string{"TOKEN"}}}}}
	if _, err = f.p.inputProfiles(f.s, tree, plan); err == nil {
		t.Fatal("builtin leaf with no published holding")
	}
}
