// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func networkChangeCandidate(t *testing.T, f *backupCoreFixture) (tenancy.Network, NetworkChangePlan) {
	t.Helper()
	r, err := f.p.Resources(f.s)
	if err != nil {
		t.Fatal(err)
	}
	original, ok := r.Networks.NamedNetwork("tenant", "services", "node-a")
	if !ok {
		t.Fatal("original managed member")
	}
	target := original
	target.Generation, target.Revision = 0, 0
	target.Pools = append([]tenancy.Subnet(nil), original.Pools...)
	target.Pools[0].Prefix = netip.MustParsePrefix("10.81.1.0/24")
	target.Pools[0].Gateway = netip.MustParseAddr("10.81.1.1")
	target.Owner = [32]byte{} // resolve only from the installed member
	return original, NetworkChangePlan{Tenant: "tenant", ID: original.ID, Change: "replace-services", Target: target}
}

func networkCandidateCancellation(t *testing.T, f *backupCoreFixture, original tenancy.Network) NetworkChangeCancel {
	t.Helper()
	r, err := f.p.Resources(f.s)
	change, ok := r.Networks.Change(original.Tenant, original.ID)
	if err != nil || !ok || !change.MetadataOnly || tenancy.CandidateNativeID(change) != "" {
		t.Fatal("reserved candidate", err)
	}
	return NetworkChangeCancel{Tenant: original.Tenant, ID: original.ID, Generation: change.Generation}
}

// All native/installation/closure observations are injected model facts.
// The real reducer, accepted app, quota, references and snapshot are reused.
func TestNetworkCandidateTransactionRetainsAppAndDNSButClosesFreshGroupUse(t *testing.T) {
	f := managedDNSTaskCoreFixture(t)
	task := managedDNSTaskCoreBegin(t, f, "first", "10.80.1.10", "first")
	refKey := deployment.ResourceKey("network-ref", "tenant", "first", "lan/node-a")
	managedDNSTaskCoreSubmit(t, f, "first", refKey, true, state.Applied)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	managedDNSTaskCoreSubmit(t, f, "first", task, true, state.Applied)
	managedDNSTaskCoreProgress(t, f, "first", "bind-inputs", task, nil)
	applyDNSCoreReport(t, f, managedDNSCoreReport(t, f, f.node), state.Applied)
	apps, err := f.p.Apps(f.s)
	o := f.s.Object(task)
	taskRef := deployment.ObjectRef{Key: task, Generation: o.Generation, Revision: o.Revision}
	binding, found := apps.Binding(taskRef)
	if err != nil || !found {
		t.Fatal("accepted Task binding", err)
	}
	owner := [32]byte(f.node.Public().(ed25519.PublicKey))
	request := AppBindingRequest{Task: taskRef, Digest: binding.Digest(), At: 10}
	if _, err = f.p.AppBindingPermit(f.s, owner, request); err != nil {
		t.Fatal("original Start authority", err)
	}
	before := f.s
	projection, err := f.p.ProjectResources(before)
	if err != nil {
		t.Fatal(err)
	}
	addresses := projection.Addresses.Checkpoint()
	original, plan := networkChangeCandidate(t, f)
	command, receipt := managedDNSChange(t, f, "reserve-services-candidate", "plan-network-change", original.Revision, plan, state.Applied)
	r, err := f.p.Resources(f.s)
	current, _ := r.Networks.Network(original.Tenant, original.ID)
	change, ok := r.Networks.Change(original.Tenant, original.ID)
	if err != nil || !ok || current.PendingChange != change.Generation || current.Generation != original.Generation || current.Revision != original.Revision || change.Target.Owner != owner || r.Networks.ReservedCount("tenant", "node-a") != 2 {
		t.Fatal("candidate did not reserve the original and target together", err)
	}
	for key := range projection.ManagedSources {
		if before.Object(key) != f.s.Object(key) {
			t.Fatal("candidate rewrote native source", key)
		}
	}
	for _, key := range []string{task, refKey, AppsKey} {
		if before.Object(key) != f.s.Object(key) {
			t.Fatal("candidate rewrote accepted app", key)
		}
	}
	currentProjection, err := f.p.ProjectResources(f.s)
	a, _ := json.Marshal(addresses)
	b, _ := json.Marshal(currentProjection.Addresses.Checkpoint())
	if err != nil || !currentProjection.Compatible || !bytes.Equal(a, b) {
		t.Fatal("candidate invalidated projection or reset the address Book", err)
	}
	if _, err = f.p.AppTaskMaterial(f.s, taskRef); err != nil {
		t.Fatal("original metadata unavailable for settlement", err)
	}
	if _, err = f.p.ManagedTaskDNS(f.s, taskRef); err != nil {
		t.Fatal("candidate invalidated the original published DNS view", err)
	}
	if updates, err := f.p.ManagedDNSUpdates(f.s, owner); err != nil || len(updates) != 0 {
		t.Fatal("candidate invented a DNS policy/name update", len(updates), err)
	}
	if _, err = f.p.AppBindingPermit(f.s, owner, request); err == nil {
		t.Fatal("old binding granted a new Task Start while changing")
	}
	for key, source := range currentProjection.ManagedSources {
		o := f.s.Object(key)
		q := NativeRequest{Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}}
		if _, err := f.p.NativePermit(f.s, source.Network.Owner, q); err == nil {
			t.Fatal("changing group granted fresh local/remote native use", key)
		}
	}
	refObject := f.s.Object(refKey)
	refRequest := NativeRequest{Source: deployment.ObjectRef{Key: refKey, Generation: refObject.Generation, Revision: refObject.Revision}}
	if _, err = f.p.NativePermit(f.s, owner, refRequest); err == nil {
		t.Fatal("accepted network-ref became a fresh native permission")
	}
	competing := tenancy.Network{Tenant: "tenant", ID: "other-network", Node: "node-b", Pools: append([]tenancy.Subnet(nil), plan.Target.Pools...)}
	managedDNSChange(t, f, "candidate-cidr-competition", "create-network", r.Networks.Revision(), competing, state.ConditionFailed)
	catalog, _ := f.p.Catalog(f.s)
	page, _, err := r.Page(catalog, "admin", "tenant", "")
	listed := false
	for _, row := range page {
		if row.Network != nil && row.Network.ID == original.ID {
			listed = row.Change != nil && row.Change.ID == change.ID && row.Change.Generation == change.Generation && row.Change.Revision == change.Revision && row.Change.MetadataOnly && row.Change.Native == "" && tenancy.ChangeTargetHash(row.Change.Target) == tenancy.ChangeTargetHash(change.Target)
		}
	}
	if err != nil || !listed {
		t.Fatal("same resource page omitted exact candidate metadata", err)
	}
	encoded, err := state.Encode(f.s)
	restored, decodeErr := state.Decode(encoded)
	if err != nil || decodeErr != nil {
		t.Fatal("candidate snapshot", err, decodeErr)
	}
	if _, err = f.p.ProjectResources(restored); err != nil {
		t.Fatal("snapshot lost retained references", err)
	}
	cancel := networkCandidateCancellation(t, f, original)
	bad := cancel
	bad.Candidate.NoPending = true
	bad.Candidate.Signature = ed25519.Sign(f.node, tenancy.ChangeCandidateBytes(bad.Candidate))
	managedDNSChange(t, f, "candidate-still-pending", "cancel-network-change", change.Revision, bad, state.ConditionFailed)
	managedDNSChange(t, f, "cancel-services-candidate", "cancel-network-change", change.Revision, cancel, state.Applied)
	if _, err = f.p.AppBindingPermit(f.s, owner, request); err != nil {
		t.Fatal("explicit metadata cancellation failed to restore current admission", err)
	}
	// Replaying the original operation returns its stored receipt, never a new
	// candidate or a replacement identity after the explicit cancellation.
	next, replay, err := state.ApplyTransactional(f.s, f.s.Index()+1, command, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || replay != receipt {
		t.Fatal("original candidate receipt was not preserved", replay, receipt, err)
	}
	r, _ = f.p.Resources(next)
	change, _ = r.Networks.Change(original.Tenant, original.ID)
	current, _ = r.Networks.Network(original.Tenant, original.ID)
	if change.Phase != tenancy.ChangeCancelled || current.PendingChange != 0 || r.Networks.ReservedCount("tenant", "node-a") != 1 {
		t.Fatal("replay revived a cancelled target or retained its budget")
	}
}

func TestNetworkCandidateRejectsQuotaCIDRCASOwnerAndSessionScopeConflicts(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	original, plan := networkChangeCandidate(t, f)
	badOwner := plan
	badOwner.Target.Owner = [32]byte{99}
	managedDNSChange(t, f, "candidate-foreign-owner", "plan-network-change", original.Revision, badOwner, state.Forbidden)
	managedDNSChange(t, f, "candidate-stale-network", "plan-network-change", original.Revision+1, plan, state.ConditionFailed)
	badCIDR := plan
	badCIDR.Target.Pools = append([]tenancy.Subnet(nil), plan.Target.Pools...)
	badCIDR.Target.Pools[0].Prefix = netip.MustParsePrefix("10.80.2.0/24")
	badCIDR.Target.Pools[0].Gateway = netip.MustParseAddr("10.80.2.1")
	managedDNSChange(t, f, "candidate-foreign-cidr", "plan-network-change", original.Revision, badCIDR, state.ConditionFailed)
	for _, scope := range []string{"", "tenant"} {
		r, _ := f.p.Resources(f.s)
		limit, _ := r.Quotas.Limit(scope, "node-a")
		expected := limit.Revision
		limit.Revision, limit.Networks = 0, 1
		f.apply("candidate-quota-"+scope, "set-node-quota", expected, limit, state.Applied)
	}
	managedDNSChange(t, f, "candidate-no-free-slot", "plan-network-change", original.Revision, plan, state.ConditionFailed)
	r, _ := f.p.Resources(f.s)
	if current, _ := r.Networks.Network(original.Tenant, original.ID); current.PendingChange != 0 {
		t.Fatal("failed candidate partially reserved the source")
	}
	// A system administrator's account does not widen its signed actions.
	f.session.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	managedDNSChange(t, f, "candidate-session-scope", "plan-network-change", original.Revision, plan, state.Forbidden)
}

func TestNetworkMetadataCandidateCancelPreservesIntentAfterNodeGrantRemoval(t *testing.T) {
	f, _, _ := managedDNSProjectionFixture(t)
	original, plan := networkChangeCandidate(t, f)
	managedDNSChange(t, f, "candidate-before-revocation", "plan-network-change", original.Revision, plan, state.Applied)
	r, _ := f.p.Resources(f.s)
	change, _ := r.Networks.Change(original.Tenant, original.ID)
	cancel := networkCandidateCancellation(t, f, original)
	bad := cancel
	bad.Candidate.Owner = [32]byte(f.admin.Public().(ed25519.PublicKey))
	bad.Candidate.Signature = ed25519.Sign(f.admin, tenancy.ChangeCandidateBytes(bad.Candidate))
	managedDNSChange(t, f, "candidate-foreign-closure", "cancel-network-change", change.Revision, bad, state.ConditionFailed)
	bad = cancel
	bad.Generation++
	managedDNSChange(t, f, "candidate-stale-generation", "cancel-network-change", change.Revision, bad, state.ConditionFailed)
	catalog, _ := f.p.Catalog(f.s)
	tenant, _ := catalog.Tenant("tenant")
	f.apply("candidate-revoke-node", "set-nodes", tenant.Revision, NodeAssignment{Tenant: "tenant", Nodes: []string{"node-b"}}, state.Applied)
	managedDNSChange(t, f, "candidate-cleanup-revoked-node", "cancel-network-change", change.Revision, cancel, state.Applied)
	r, _ = f.p.Resources(f.s)
	change, _ = r.Networks.Change(original.Tenant, original.ID)
	expectedTarget := plan.Target
	expectedTarget.Owner = change.Target.Owner
	if !change.MetadataOnly || change.CandidateClosed != nil || change.Phase != tenancy.ChangeCancelled || tenancy.ChangeTargetHash(change.Target) != tenancy.ChangeTargetHash(expectedTarget) {
		t.Fatal("cleanup lost metadata intent or fabricated native closure")
	}
}

func TestNetworkCandidateInputKeepsResourcesCAS(t *testing.T) {
	payload := NetworkChangePlan{Tenant: "tenant", ID: "lan", Change: "change-lan", Target: tenancy.Network{Tenant: "tenant", ID: "lan", Node: "node-a", Pools: []tenancy.Subnet{{ID: "pool", Prefix: netip.MustParsePrefix("10.81.1.0/24"), Gateway: netip.MustParseAddr("10.81.1.1"), MTU: 1280}}}}
	change, err := InputChange(changeInput("plan-network-change", 12, payload), "admin")
	if err != nil || CommandKey(change.Action) != ResourcesKey || change.Expected != 12 {
		t.Fatal("typed candidate lost its CAS namespace", err)
	}
	commit := NetworkChangeCommit{Tenant: "tenant", Network: "services", Members: []tenancy.NetworkChangeVersion{{Tenant: "tenant", ID: "member-a", Generation: 2, Revision: 4}}}
	if _, err := InputChange(changeInput("commit-network-change", 12, commit), "admin"); err != nil {
		t.Fatal("explicit target metadata commit rejected", err)
	}
	for action, closure := range map[string]any{
		"cancel-network-change": NetworkChangeCancel{Tenant: "tenant", ID: "lan", Generation: 1, Candidate: tenancy.ChangeCandidateClose{Signature: []byte{1}}},
		"fence-network-change":  NetworkChangeFence{Tenant: "tenant", ID: "lan", Generation: 1, Closed: tenancy.NetworkClosure{Tenant: "tenant", Network: "lan", Signature: []byte{1}}},
	} {
		if _, err := InputChange(changeInput(action, 12, closure), "admin"); err != nil {
			t.Fatal("explicit management boundary rejected the typed closure shape", action, err)
		}
	}
}
