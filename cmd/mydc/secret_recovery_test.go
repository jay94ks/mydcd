// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/secrets"
	"github.com/jay94ks/mydcd/internal/userauth"
)

func TestRealSecretManagementCLIOrphanAndOriginalCAS(t *testing.T) {
	testRealComposeGroups(t, true, true)
}

func testSecretManagementCLIOrphanAndCAS(t *testing.T, f secretManagementFixture, apply func(string, string, uint64, any)) {
	secret := func(want int, stdin string, args ...string) {
		t.Helper()
		f.cmd(want, stdin, append([]string{"secret"}, args...)...)
	}
	secret(0, "", "create", "orphan", "--tenant", "tenant", "--parent", "root", "--profile", "values", "--object", "tenant/orphan", "--key", "key")
	c, stored := f.client()
	plan, e := c.PlanVaultWrite(f.ctx, f.peer, stored.Session, control.VaultWritePlanRequest{Realm: "tenant", ID: "external", Object: "orphan", Kind: secrets.ValueWrite})
	if e != nil {
		t.Fatal(e)
	}
	apply("external-prepare", "vault-prepare-write", plan.TreeRevision, control.VaultWrite{Realm: "tenant", Request: plan.Request})
	apply("external-dispatch", "vault-dispatch-write", f.current().Trees["tenant"].Revision(), control.VaultWriteAction{Realm: "tenant", ID: "external", Epoch: plan.Request.Epoch})
	f.lose.Store(true)
	reply, err := c.WriteVault(f.ctx, f.peer, stored.Session, userauth.SecretRequest{Realm: "tenant", ID: "external", Mode: "execute", Values: map[string][]byte{"key": []byte("private-external-original")}})
	if err == nil || reply.VaultObservation == nil || f.puts.Load() != 1 {
		t.Fatal("external original unknown", err)
	}
	apply("external-observe", "vault-observe-write", f.current().Trees["tenant"].Revision(), control.VaultObserve{Observation: *reply.VaultObservation})
	if _, e = userauth.LoadSecretWrite(f.home, *c, stored.Session, "tenant", "external"); !errors.Is(e, userauth.ErrOperationMissing) {
		t.Fatal("fixture accidentally created a CLI intent", e)
	}
	f.login()
	// This computer has no record of the write: the same command follows it
	// to its end and never sends a value (standard input is not read).
	secret(0, "private-external-original-again", "put", "orphan", "--tenant", "tenant", "--id", "external")
	c, stored = f.client()
	i, e := userauth.LoadSecretWrite(f.home, *c, stored.Session, "tenant", "external")
	w, _ := f.current().Trees["tenant"].Write("external")
	if e != nil || !i.Attempted || i.Sequence != 1 || w.Status() != "Published" || w.Observation.ProviderRevision != 1 || !sameJSON(plan.Request, w.Request) || f.puts.Load() != 1 {
		t.Fatal("orphan recovery replayed/rebound original", e)
	}
	secret(1, "other", "put", "data", "--tenant", "tenant", "--id", "external")
	if f.puts.Load() != 1 {
		t.Fatal("write ID rebound to another object")
	}
	// Retain a local original, then change its tree before the first management
	// send. Explicit resume must keep the original rejected CAS/signature.
	plan, e = c.PlanVaultWrite(f.ctx, f.peer, stored.Session, control.VaultWritePlanRequest{Realm: "tenant", ID: "stale", Object: "orphan", Kind: secrets.ValueWrite})
	if e != nil {
		t.Fatal(e)
	}
	window, e := c.Query(f.ctx, f.peer, stored.Session, "whoami", "")
	if e != nil {
		t.Fatal(e)
	}
	i, e = userauth.StageSecretWrite(f.home, *c, stored.Session, plan, max(1, window.ModuleEpoch), false)
	if e != nil {
		t.Fatal(e)
	}
	secret(0, "", "group", "create", "tree-changed", "--tenant", "tenant", "--parent", "root")
	secret(3, "private-stale", "put", "orphan", "--tenant", "tenant", "--id", "stale")
	id := secretPhaseID("tenant", "stale", "prepare")
	original, e := userauth.LoadOperation(f.home, *c, stored.Session, id)
	if e != nil || original.Result == nil || original.Operation.Change.Expected != i.ExpectedTree {
		t.Fatal("original rejected CAS not retained", e)
	}
	before := f.read().Index()
	secret(3, "private-stale", "put", "orphan", "--tenant", "tenant", "--id", "stale")
	after, e := userauth.LoadOperation(f.home, *c, stored.Session, id)
	if e != nil || !sameJSON(original.Operation, after.Operation) || f.read().Index() != before || f.puts.Load() != 1 {
		t.Fatal("rejected original automatically resubmitted/rebased", e)
	}
	if _, found := f.current().Trees["tenant"].Write("stale"); found {
		t.Fatal("rejected write created provider metadata")
	}
	// A conservative BEFORE-SEND marker can never be reset, even if no private
	// call followed it. Stale concurrent snapshots cannot both cross this CAS.
	next := i
	next.Attempted = true
	if e = userauth.ReplaceSecretWrite(f.home, *c, stored.Session, i, next); e != nil {
		t.Fatal(e)
	}
	if e = userauth.ReplaceSecretWrite(f.home, *c, stored.Session, i, next); e == nil {
		t.Fatal("stale concurrent private CAS accepted")
	}
	if e = userauth.ReplaceSecretWrite(f.home, *c, stored.Session, next, i); e == nil {
		t.Fatal("BEFORE-SEND marker reset")
	}
	t.Log("actual current authenticated orphan original readback; no private FD access/new PUT; original stale-CAS rejection/signature/ID retained; private BEFORE-SEND CAS cannot reset")
}
