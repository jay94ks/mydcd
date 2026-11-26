// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func TestCheckerModuleIntentCASPreservesSourceSignatureAndRootProgress(t *testing.T) {
	home, c, session, issuer := journalFixture(t)
	pin := checker.ModulePin{Path: "example.invalid/safe", Version: "v1.0.0", Length: 1, Digest: [32]byte{1}}
	data := []byte("package checker\n")
	d := streamedSource(data)
	d.Modules = []checker.ModulePin{pin}
	peer := c.Peers[0]
	i, err := StageCheckerScript(home, c, session, "module-source", "ready", peer, d, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := ReplaceCheckerModule(home, c, session, i, pin.Path, CheckerModuleProgress{Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staged.Signature, i.Signature) || !bytes.Equal(checkerIntentBytes(staged), checkerIntentBytes(i)) || staged.Sequence != 0 || staged.Fact != nil {
		t.Fatal("module attempt mutated root/public origin")
	}
	rootChange := i
	rootChange.Sequence = 1
	if err := ReplaceCheckerScript(home, c, session, i, rootChange); err == nil {
		t.Fatal("root CAS erased concurrent module attempt")
	}
	if _, err := ReplaceCheckerModule(home, c, session, i, pin.Path, CheckerModuleProgress{Sequence: 1}); err == nil {
		t.Fatal("duplicate stale sender claimed same module")
	}
	fact := checker.ModuleFact{Schema: 1, Cluster: c.Cluster, Owner: issuer.Public, Tenant: d.Tenant, Module: pin}
	fact.Signature = ed25519.Sign(issuer.Private, checker.ModuleFactBytes(fact))
	done, err := ReplaceCheckerModule(home, c, session, staged, pin.Path, CheckerModuleProgress{Sequence: 1, Fact: &fact})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceCheckerModule(home, c, session, done, pin.Path, CheckerModuleProgress{Sequence: 2}); err == nil {
		t.Fatal("settled module fact reset for resend")
	}
	if _, err := LoadOperation(home, c, session, i.ID); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("module cache write created Raft mutation", err)
	}
	changed := done
	changed.ModuleProgress = nil
	if err := ReplaceCheckerScript(home, c, session, done, changed); err == nil {
		t.Fatal("root replace deleted module receipts")
	}
}
