// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"
)

// Metadata/core fixture; fake native closure is signed here. It is not a real
// Docker journal, filesystem cleanup, source staging or quorum observation.
func buildJobFixture(t *testing.T) (Catalog, Use, BuildIntent, CompileBatch, ed25519.PrivateKey) {
	t.Helper()
	input, policy := compilationFixture(t)
	book, err := NewCatalog([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	book.d.Policies[policy.Tenant] = []TenantPolicy{policy}
	book.d.Revision = 1
	fact := signedSource(44, compileTestSource, nil)
	parent := Use{Tenant: "tenant", ID: "app", Kind: "app-binding", Principal: "alice", Node: "consumer", Owner: [32]byte{2}, Parent: [32]byte{3}, PolicyRevision: 1, Sources: []SourceFact{fact}}
	book, err = book.Reserve(parent)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := NewCompileBatch(hashText("original-build"), time.Now().Add(time.Minute).UnixMilli(), policy, policy.Build.Image, []*Compilation{input})
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{44}, 32))
	b, err := book.PlanBuild(parent, "builder", [32]byte(private.Public().(ed25519.PublicKey)), Selection{PolicyRevision: 1, Sources: []SourceFact{fact}}, batch)
	if err != nil {
		t.Fatal(err)
	}
	return book, parent, b, batch, private
}

func buildClosure(b BuildIntent, private ed25519.PrivateKey, disposition string) BuildClosure {
	c := BuildClosure{Schema: 1, Cluster: b.Cluster, Job: b.Digest(), Owner: b.Owner, Journal: [32]byte{7}, Disposition: disposition}
	if disposition == "removed" {
		c.Native = hashText("actual-container-id")
	}
	c.Signature = ed25519.Sign(private, BuildClosureBytes(c))
	return c
}

func TestCheckerEquivalentPolicyAdmissionKeepsOriginalBindingAndBuild(t *testing.T) {
	original, parent, intent, batch, _ := buildJobFixture(t)
	raw, err := original.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"restored", "disabled", "changed", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			book, err := DecodeCatalog(raw)
			if err != nil {
				t.Fatal(err)
			}
			accepted, _ := book.Policy(parent.Tenant, 1)
			disabled := accepted.Clone()
			disabled.Revision = 2
			disabled.Enabled = false
			current := accepted.Clone()
			current.Revision = 3
			if mode == "disabled" {
				current.Enabled = false
			}
			if mode == "changed" {
				current.Execution.OutputBytes++
			}
			// Fake catalog storage supplies the real historical policy sequence.
			// Admission/reservation/planning/dispatch remain the product core.
			book.d.Policies[parent.Tenant] = []TenantPolicy{accepted, disabled, current}
			book.d.Revision += 2
			if book.Validate() != nil {
				t.Fatal("invalid policy history fixture")
			}
			next := parent
			next.ID = "replacement-app"
			next.Parent[0]++
			if mode == "unknown" {
				next.PolicyRevision = 999
			}
			reserved, err := book.Reserve(next)
			if mode != "restored" {
				if err == nil {
					t.Fatal("changed/disabled/missing policy admitted original recipe")
				}
				if _, ok := book.AdmissionPolicy(parent.Tenant, next.PolicyRevision); ok {
					t.Fatal("policy mismatch accepted")
				}
				if mode != "unknown" {
					if _, err := book.PlanBuild(parent, intent.Node, intent.Owner, intent.Selection, batch); err == nil {
						t.Fatal("current policy change admitted an original build plan")
					}
					if _, err := book.ReserveBuild(intent); err == nil {
						t.Fatal("current policy change admitted an original build reservation")
					}
				}
				return
			}
			if err != nil {
				t.Fatal("equivalent restored policy blocked replacement binding", err)
			}
			use, ok := reserved.Use(next.Tenant, next.ID)
			if !ok || use.PolicyRevision != 1 || use.Digest() != next.Digest() {
				t.Fatal("original binding identity rewritten")
			}
			planned, err := reserved.PlanBuild(parent, intent.Node, intent.Owner, intent.Selection, batch)
			if err != nil || planned.Digest() != intent.Digest() {
				t.Fatal("original build intent changed", err)
			}
			reserved, err = reserved.ReserveBuild(planned)
			if err != nil {
				t.Fatal("equivalent restored policy blocked original build reservation", err)
			}
			job, _ := reserved.BuildJob(planned.Tenant, planned.ID)
			reserved, err = reserved.DispatchBuild(planned.Tenant, planned.ID, job.Revision, planned.Owner)
			if err != nil {
				t.Fatal("equivalent restored policy blocked original dispatch", err)
			}
			if _, err = reserved.Encode(); err != nil {
				t.Fatal("restored policy catalog checkpoint", err)
			}
		})
	}
}

func TestCheckerBuildReservationIsAtomicOriginalAndBlocksParentRelease(t *testing.T) {
	book, parent, b, batch, private := buildJobFixture(t)
	before, _ := book.Encode()
	reserved, err := book.ReserveBuild(b)
	if err != nil || reserved.Revision() != book.Revision()+1 {
		t.Fatal("atomic reservation", err)
	}
	if _, err := book.Release(parent); err != nil {
		t.Fatal("original catalog mutated", err)
	}
	after, _ := book.Encode()
	if !bytes.Equal(before, after) {
		t.Fatal("immutable input catalog")
	}
	if _, err := reserved.Release(parent); err == nil {
		t.Fatal("live build lost parent")
	}
	use, ok := reserved.Use(b.Tenant, b.ID)
	if !ok || use.Kind != "build-job" || use.Parent != b.Digest() {
		t.Fatal("missing job pin")
	}
	if _, err := reserved.Release(use); err == nil {
		t.Fatal("generic release bypassed closure")
	}
	if _, err := book.Reserve(use); err == nil {
		t.Fatal("free-standing build pin accepted")
	}
	repeated, err := reserved.ReserveBuild(b)
	if err != nil || repeated.Revision() != reserved.Revision() {
		t.Fatal("duplicate re-reserved", err)
	}
	changed := b.Clone()
	changed.Manifest[0]++
	if _, err := reserved.ReserveBuild(changed); err == nil {
		t.Fatal("same ID changed manifest")
	}
	batch.Items[0].Recipe.Flags[0] = "generate"
	if b.ValidateBatch(batch) == nil {
		t.Fatal("manifest/recipe substitution")
	}
	raw, err := reserved.Encode()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeCatalog(raw)
	if err != nil {
		t.Fatal("snapshot pin", err)
	}
	// Revocation cannot be converted to cancellation/no-effect evidence.
	p, _ := restored.Policy("tenant", 0)
	p.Revision, p.Enabled = 2, false
	restored.d.Policies["tenant"] = append(restored.d.Policies["tenant"], p)
	restored.d.Revision++
	if _, err := restored.DispatchBuild(b.Tenant, b.ID, 1, b.Owner); err == nil {
		t.Fatal("dispatch after revoke")
	}
	closed, err := restored.CloseBuild(b.Tenant, b.ID, 1, buildClosure(b, private, "never-dispatched"))
	if err != nil {
		t.Fatal("closure after revoke", err)
	}
	if _, ok := closed.Use(b.Tenant, b.ID); ok {
		t.Fatal("closed pin")
	}
	closed, err = closed.Release(parent)
	if err != nil || !closed.Quiescent() {
		t.Fatal("parent settlement", err)
	}
	raw, err = closed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	closed, err = DecodeCatalog(raw)
	if err != nil {
		t.Fatal(err)
	}
	job, ok := closed.BuildJob(b.Tenant, b.ID)
	if !ok || job.Phase != "closed" || job.Closure == nil {
		t.Fatal("lost original closure")
	}
	closedAgain, err := closed.ReserveBuild(b)
	if err != nil || closedAgain.Revision() != closed.Revision() {
		t.Fatal("original acceptance restarted", err)
	}
}

func TestCheckerBuildDispatchCapacityAndExactNativeClosure(t *testing.T) {
	book, _, b, _, private := buildJobFixture(t)
	book, err := book.ReserveBuild(b)
	if err != nil {
		t.Fatal(err)
	}
	other := b.Clone()
	other.ID = hashText("other-build")
	if _, err := book.ReserveBuild(other); err == nil {
		t.Fatal("concurrent slot overflow")
	}
	book, err = book.DispatchBuild(b.Tenant, b.ID, 1, b.Owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := book.CloseBuild(b.Tenant, b.ID, 2, buildClosure(b, private, "never-dispatched")); err == nil {
		t.Fatal("dispatched treated as unstarted")
	}
	closure := buildClosure(b, private, "removed")
	wrong := closure
	wrong.Signature = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	if _, err := book.CloseBuild(b.Tenant, b.ID, 2, wrong); err == nil {
		t.Fatal("foreign closure")
	}
	wrong = closure
	wrong.Native = hashText("different-container")
	if _, err := book.CloseBuild(b.Tenant, b.ID, 2, wrong); err == nil {
		t.Fatal("native ID changed")
	}
	closed, err := book.CloseBuild(b.Tenant, b.ID, 2, closure)
	if err != nil {
		t.Fatal(err)
	}
	copy, ok := closed.BuildJob(b.Tenant, b.ID)
	if !ok {
		t.Fatal("lost job")
	}
	copy.Intent.Inputs[0].Recipe[0]++
	copy.Closure.Signature[0]++
	if closed.Validate() != nil {
		t.Fatal("public job aliases catalog")
	}
	reserved, err := closed.ReserveBuild(other)
	if err != nil {
		t.Fatal("closed slot not released", err)
	}
	orphan := reserved.clone()
	delete(orphan.d.Builds, catalogKey(other.Tenant, other.ID))
	if orphan.Validate() == nil {
		t.Fatal("orphan build use restored")
	}
	raw, _ := json.Marshal(orphan.d)
	if _, err := DecodeCatalog(raw); err == nil {
		t.Fatal("snapshot erased job parent")
	}
}
