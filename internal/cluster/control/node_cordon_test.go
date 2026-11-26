// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
	"testing"
)

func TestCordonBlocksNewPlansButPreservesAcceptedTaskBindingAndControl(t *testing.T) {
	f, o, selection := restartCoreFixture(t)
	apps, err := f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := apps.Inventory("tenant", "source-app")
	ref := deployment.ObjectRef{Key: o.Key, Generation: o.Generation, Revision: o.Revision}
	claim, ok := apps.Claim("tenant", "source-app", ref)
	if !ok {
		t.Fatal("missing original")
	}
	node := claim.Step.Node
	members, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	member, _ := members.Entry(node)
	originalRuntime, err := json.Marshal(members.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	op, _ := managedDNSChange(t, f, "cordon-node", "cordon-node", 0, NodeSelection{ID: node}, state.Applied)
	members, err = f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	if !members.Cordon(node).Enabled || !members.WorkKey(o.Owner) || !members.MemberKey(o.Owner) {
		t.Fatal("scheduling flag withdrew runtime authority")
	}
	current, _ := members.Entry(node)
	runtime, err := json.Marshal(members.Runtime)
	if err != nil || current.Peer != member.Peer || current.Revision != member.Revision || string(runtime) != string(originalRuntime) {
		t.Fatal("cordon changed installed membership")
	}
	ctx, err := f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil || !ctx.Nodes[node].Draining {
		t.Fatal("new plans still admit node", err)
	}
	if _, err = f.p.PlanTaskRestart(f.s, f.session, 10, "tenant", selection); err != nil {
		t.Fatal("existing Task control withdrawn", err)
	}
	binding, exists := apps.Binding(ref)
	if !exists {
		t.Fatal("original Binding absent")
	}
	if _, err = f.p.AppBindingPermit(f.s, o.Owner, AppBindingRequest{Task: ref, Digest: binding.Digest(), At: 10}); err != nil {
		t.Fatal("cordon revoked accepted native/Secret/Volume permit", err)
	}
	apps, err = f.p.Apps(f.s)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := apps.Inventory("tenant", "source-app")
	preserved, _ := apps.Claim("tenant", "source-app", ref)
	if before.Revision() != after.Revision() || claim.Command != preserved.Command {
		t.Fatal("cordon changed existing Task/Binding")
	}
	applyRestartCore(t, f, op, state.Applied) // retained original result
	managedDNSChange(t, f, "stale-uncordon", "uncordon-node", 0, NodeSelection{ID: node}, state.ConditionFailed)
	managedDNSChange(t, f, "uncordon-node", "uncordon-node", 1, NodeSelection{ID: node}, state.Applied)
	ctx, err = f.p.AppPlanning(f.s, "admin", "tenant")
	if err != nil || ctx.Nodes[node].Draining {
		t.Fatal("new placement not restored", err)
	}
}
