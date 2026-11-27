// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/reconcile"
)

// Native configurations and closure counts in this file are modeled inputs.
// These tests exercise the product Directory/lifecycle/A2 cores, not an SDK
// removal, process stop, resource census or real quorum.
func runtimeMembers(t *testing.T) (Directory, ed25519.PrivateKey, ed25519.PrivateKey) {
	t.Helper()
	d, b, ak, bk := fixture(t)
	a := lifecycle.Member{ID: "a", Key: memberKey(ak), Voter: true}
	n, err := d.InstallConfiguration(lifecycle.Configuration{Index: 10, Members: []lifecycle.Member{a}})
	d = checked(t, n, err)
	d = invite(t, d, b)
	d = dispatch(t, d, "b", ak, 10)
	d = observe(t, d, "b", 12, b)
	d = installed(t, d, "b", bk, 12)
	if d.MemberKey(memberKey(bk)) {
		t.Fatal("whole configuration not yet published")
	}
	c := lifecycle.Configuration{Index: 12, Members: []lifecycle.Member{a, {ID: "b", Key: memberKey(bk)}}}
	n, err = d.InstallConfiguration(c)
	d = checked(t, n, err)
	e, _ := d.Entry("b")
	n, err = d.Promote("b", e.Revision)
	d = checked(t, n, err)
	d = dispatch(t, d, "b", ak, 12)
	b.Voter = true
	d = observe(t, d, "b", 14, b)
	c.Index, c.Members[1].Voter = 14, true
	n, err = d.InstallConfiguration(c)
	return checked(t, n, err), ak, bk
}

func beginRuntimeNode(t *testing.T, d Directory, node, operation string, action lifecycle.Action) Directory {
	t.Helper()
	topology, _ := d.Topology()
	current, _ := topology.Node(node)
	n, err := d.BeginNode(node, operation, action, current.Revision, topology.Epoch(), json.RawMessage(`{"original":true}`))
	return checked(t, n, err)
}
func runtimeNodeProof(t *testing.T, d Directory, node string, private ed25519.PrivateKey) lifecycle.Proof {
	t.Helper()
	topology, _ := d.Topology()
	current, _ := topology.Node(node)
	if current.Pending == nil {
		t.Fatal("missing original lifecycle operation")
	}
	p := lifecycle.Proof{Cluster: d.Cluster, Node: node, Operation: current.Pending.ID, Generation: current.Generation, Revision: current.Pending.Revision, ConfigurationIndex: topology.Configuration().Index, Closed: current.Pending.Action != lifecycle.Restore, Ready: current.Pending.Action == lifecycle.Restore}
	p.Signature = ed25519.Sign(private, lifecycle.ProofBytes(p))
	return p
}
func observeRuntimeNode(t *testing.T, d Directory, node string, key ed25519.PrivateKey) Directory {
	t.Helper()
	n, err := d.ObserveNode(runtimeNodeProof(t, d, node, key))
	return checked(t, n, err)
}

func TestRuntimeQuiescenceKeepsUnsettledNodeAndNativeRemovalRequests(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	if !d.Quiescent() {
		t.Fatal("settled original configuration blocked expiry")
	}
	d = beginRuntimeNode(t, d, "b", "isolate-b", lifecycle.Isolate)
	if d.Quiescent() {
		t.Fatal("pending isolation allowed request expiry")
	}
	d = observeRuntimeNode(t, d, "b", bk)
	if !d.Quiescent() {
		t.Fatal("positive isolated closure was treated as unresolved work")
	}
	d = beginRuntimeNode(t, d, "b", "restore-b", lifecycle.Restore)
	if d.Quiescent() {
		t.Fatal("pending readiness allowed original authorization expiry")
	}
	d = observeRuntimeNode(t, d, "b", bk)
	d = beginRuntimeNode(t, d, "b", "remove-b", lifecycle.Remove)
	d = observeRuntimeNode(t, d, "b", bk)
	if d.Quiescent() {
		t.Fatal("owner closure replaced actual SDK removal")
	}
	topology, _ := d.Topology()
	n, err := d.DispatchRemoval("remove-b", d.Revision, topology.Configuration().Index, memberKey(ak))
	d = checked(t, n, err)
	n, err = d.UnknownRemoval("remove-b", d.Revision)
	d = checked(t, n, err)
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err = Decode(raw)
	if err != nil || d.Quiescent() {
		t.Fatal("restored Unknown allowed original request expiry", err)
	}
	before, _ := d.NodeOperation("remove-b")
	topology, _ = d.Topology()
	configuration := topology.Configuration()
	configuration.Index++
	configuration.Members = []lifecycle.Member{{ID: "a", Key: memberKey(ak), Voter: true}}
	n, err = d.InstallConfiguration(configuration)
	d = checked(t, n, err)
	after, _ := d.NodeOperation("remove-b")
	if !d.Quiescent() || !bytes.Equal(before.Origin, after.Origin) || before.Job.LastID != after.Job.LastID || after.Job.Pending != nil {
		t.Fatal("actual configuration input did not settle the same original")
	}
}

func TestRuntimeIsolationKeepsConsensusAndOriginalResultIdentity(t *testing.T) {
	d, _, bk := runtimeMembers(t)
	d = beginRuntimeNode(t, d, "b", "isolate-b", lifecycle.Isolate)
	key := memberKey(bk)
	if d.WorkKey(key) || !d.MemberKey(key) || !d.ReplicationKey(key) || len(d.Issuers()) != 2 {
		t.Fatal("business isolation changed consensus or existing session verification")
	}
	status, ok := d.NodeView("b")
	if !ok || status.Node.Phase != lifecycle.Isolating || status.Node.Pending.ID != "isolate-b" || status.AdmitsWork || status.Node.Closure != nil {
		t.Fatal("intent was reported as actual closure", status)
	}
	for _, mutate := range []func(*lifecycle.Proof){
		func(p *lifecycle.Proof) { p.Resources = 1 },
		func(p *lifecycle.Proof) { p.Flows = 1 },
		func(p *lifecycle.Proof) { p.Writers = 1 },
		func(p *lifecycle.Proof) { p.Leases = 1 },
		func(p *lifecycle.Proof) { p.CDJobs = 1 },
		func(p *lifecycle.Proof) { p.Generation++ },
		func(p *lifecycle.Proof) { p.Operation = "different" },
		func(p *lifecycle.Proof) { p.Closed, p.Ready = false, true },
	} {
		proof := runtimeNodeProof(t, d, "b", bk)
		mutate(&proof)
		proof.Signature = ed25519.Sign(bk, lifecycle.ProofBytes(proof))
		n, err := d.ObserveNode(proof)
		assertRejected(t, d, n, err)
	}
	d = observeRuntimeNode(t, d, "b", bk)
	status, _ = d.NodeView("b")
	if status.Node.Phase != lifecycle.Isolated || status.Node.Pending != nil || d.WorkKey(key) {
		t.Fatal("modeled closure did not isolate original node")
	}
	old := *status.Node.Closure
	d = beginRuntimeNode(t, d, "b", "restore-b", lifecycle.Restore)
	n, err := d.ObserveNode(old)
	assertRejected(t, d, n, err)
	if d.WorkKey(key) {
		t.Fatal("restore admission before fresh owner readiness")
	}
	d = observeRuntimeNode(t, d, "b", bk)
	if !d.WorkKey(key) {
		t.Fatal("fresh modeled readiness did not restore work")
	}
	topology, _ := d.Topology()
	n, err = d.RotateNodeOperations(topology.Revision(), topology.Epoch())
	d = checked(t, n, err)
	if len(d.Runtime.Operations) != 1 || d.Runtime.Operations[0].ID != "restore-b" {
		t.Fatal("rotation lost original current closure or kept unbounded history")
	}
	currentTopology, _ := d.Topology()
	currentNode, _ := currentTopology.Node("b")
	n, err = d.BeginNode("b", "old-window", lifecycle.Isolate, currentNode.Revision, topology.Epoch(), json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
}

func TestRuntimeRemovalRetainsUnknownAndHistoricalJoinSource(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	d = beginRuntimeNode(t, d, "a", "remove-a", lifecycle.Remove)
	topology, _ := d.Topology()
	c := topology.Configuration()
	c.Index++
	c.Members = c.Members[1:]
	n, err := d.InstallConfiguration(c)
	assertRejected(t, d, n, err)
	n, err = d.DispatchRemoval("remove-a", d.Revision, 14, memberKey(bk))
	assertRejected(t, d, n, err) // Intent and silence cannot replace owner closure.
	d = observeRuntimeNode(t, d, "a", ak)
	n, err = d.InstallConfiguration(c)
	assertRejected(t, d, n, err) // Closure is not a native RemoveServer dispatch.
	n, err = d.DispatchRemoval("remove-a", d.Revision, 14, memberKey(bk))
	d = checked(t, n, err)
	original, _ := d.NodeOperation("remove-a")
	n, err = d.UnknownRemoval("remove-a", d.Revision)
	d = checked(t, n, err)
	unknown, _ := d.NodeOperation("remove-a")
	if unknown.Job.Pending.Phase != reconcile.RecoveryRequired || unknown.Job.Pending.ID != original.Job.Pending.ID || unknown.Job.Pending.Target != original.Job.Pending.Target {
		t.Fatal("unknown changed original native effect")
	}
	n, err = d.DispatchRemoval("remove-a", d.Revision, 14, memberKey(bk))
	assertRejected(t, d, n, err)
	status, _ := d.NodeView("a")
	n, err = d.ResumeNode("a", "remove-a", status.Node.Revision, unknown.Epoch, json.RawMessage(`{"renewal":true}`))
	d = checked(t, n, err)
	renewed, _ := d.NodeOperation("remove-a")
	if !bytes.Equal(renewed.Origin, original.Origin) || !bytes.Equal(renewed.Authorization, []byte(`{"renewal":true}`)) || !reflect.DeepEqual(renewed.Job, unknown.Job) {
		t.Fatal("authorization renewal replaced original operation or SDK target")
	}
	n, err = d.InstallConfiguration(c)
	d = checked(t, n, err)
	finished, _ := d.NodeOperation("remove-a")
	status, _ = d.NodeView("a")
	if finished.Job.Pending != nil || finished.ObservedIndex != c.Index || status.Node.Phase != lifecycle.Removed || d.MemberKey(memberKey(ak)) || d.ReplicationKey(memberKey(ak)) || !d.HistoricalMemberKey(memberKey(ak)) {
		t.Fatal("actual configuration input did not settle original removal")
	}
	joined, _ := d.Entry("b")
	if joined.Source != memberKey(ak) || !d.WorkKey(memberKey(bk)) || len(d.Issuers()) != 1 {
		t.Fatal("removing historical join source invalidated its admitted successor")
	}
	// The same native/configuration observation is not another state mutation.
	n, err = d.InstallConfiguration(c)
	if err != nil || !reflect.DeepEqual(n, d) {
		t.Fatal("unchanged configuration was rewritten", err)
	}
	topology, _ = d.Topology()
	b, _ := topology.Node("b")
	n, err = d.BeginNode("b", "remove-last", lifecycle.Remove, b.Revision, topology.Epoch(), json.RawMessage(`{}`))
	assertRejected(t, d, n, err)
}

func TestRuntimeRemovalRequiresClosureForCurrentConfigurationAndCrossLinks(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	d = beginRuntimeNode(t, d, "a", "remove-a", lifecycle.Remove)
	d = observeRuntimeNode(t, d, "a", ak)
	topology, _ := d.Topology()
	c := topology.Configuration()
	c.Index++
	n, err := d.InstallConfiguration(c)
	d = checked(t, n, err)
	n, err = d.DispatchRemoval("remove-a", d.Revision, c.Index, memberKey(bk))
	assertRejected(t, d, n, err)
	d = observeRuntimeNode(t, d, "a", ak)
	n, err = d.DispatchRemoval("remove-a", d.Revision, c.Index, memberKey(bk))
	d = checked(t, n, err)
	for _, corrupt := range []func(*Directory){
		func(d *Directory) { d.Runtime.Operations = nil },
		func(d *Directory) { d.Runtime.Operations[0].Generation++ },
		func(d *Directory) { d.Runtime.Operations[0].Job.Desired.Revision++ },
		func(d *Directory) { d.Runtime.Operations[0].Job.Desired.Spec += "changed" },
		func(d *Directory) { d.Runtime.Operations[0].Node = "b" },
		func(d *Directory) { d.Runtime.Operations[0].Authorization = json.RawMessage(`broken`) },
	} {
		broken := clone(d)
		corrupt(&broken)
		if broken.Validate() == nil {
			t.Fatal("inconsistent lifecycle/A2 checkpoint accepted")
		}
	}
}
