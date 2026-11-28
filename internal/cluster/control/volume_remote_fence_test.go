// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// removeNode takes node-b out of f's membership by the normal path
// (closure proof, then a configuration without it): Directory.Gone is the
// same for a removed and a retired server.
func removeNode(t *testing.T, f *backupCoreFixture) {
	t.Helper()
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	step := func(n membership.Directory, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("membership step", err)
		}
		d = n
	}
	inject := func(id string) {
		t.Helper()
		writes, code := f.p.memberCheckpoint(f.s, d)
		if code != state.Applied {
			t.Fatal(code)
		}
		var result state.Result
		f.s, result, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: f.s.ModuleEpoch(), RequestID: id, Key: MembersKey, Expected: f.s.Object(MembersKey).Revision, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
		if err != nil || result.Code != state.Applied {
			t.Fatal(id, result, err)
		}
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{124}, 32))
	akey := [32]byte(f.node.Public().(ed25519.PublicKey))
	bkey := [32]byte(private.Public().(ed25519.PublicKey))
	base := uint64(1)
	for _, e := range d.Entries {
		base = max(base, e.NativeIndex+1)
	}
	a := lifecycle.Member{ID: "node-a", Key: akey, Voter: true}
	step(d.InstallConfiguration(lifecycle.Configuration{Index: base, Members: []lifecycle.Member{a, {ID: "node-b", Key: bkey}}}))
	inject("runtime")
	plan, err := f.p.nodeRemovalPlan(f.s, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	f.apply("remove-b", "remove-node", plan.Expected, NodeLifecycleChange{ID: "node-b", Operation: "remove-b", Epoch: plan.Epoch}, state.Applied)
	if d, err = f.p.Members(f.s); err != nil {
		t.Fatal(err)
	}
	topology, _ := d.Topology()
	node, _ := topology.Node("node-b")
	proof := lifecycle.Proof{Cluster: d.Cluster, Node: "node-b", Operation: node.Pending.ID, Generation: node.Generation, Revision: node.Pending.Revision, ConfigurationIndex: topology.Configuration().Index, Closed: true}
	proof.Signature = ed25519.Sign(private, lifecycle.ProofBytes(proof))
	step(d.ObserveNode(proof))
	step(d.DispatchRemoval("remove-b", d.Revision, base, akey))
	step(d.InstallConfiguration(lifecycle.Configuration{Index: base + 1, Members: []lifecycle.Member{a}}))
	inject("removed")
	if d, err = f.p.Members(f.s); err != nil || !d.Gone("node-b") {
		t.Fatal("node-b not removed", err)
	}
}

// The home's fence releases a remote consumer only once its runner is
// out of the cluster, only signed by the Volume's owner and sent by that owner, and
// the grant for the retired runner is already refused.
func TestRemoteFenceAfterRunnerRetired(t *testing.T) {
	f, writer, runner := remoteConsumerCore(t)
	home := [32]byte(f.node.Public().(ed25519.PublicKey))
	mine := func(k [32]byte) bool { return k == home }
	report := func(signer ed25519.PrivateKey) []byte {
		proof := volumes.RemoteFence{Schema: 1, Scope: f.scope, Consumer: writer}
		proof.Signature = ed25519.Sign(signer, volumes.RemoteFenceBytes(proof))
		raw, _ := json.Marshal(VolumeRemoteFenceReport{Schema: 1, Operation: "remote-fence", Epoch: f.s.ModuleEpoch(), RootRevision: f.s.Object(VolumesKey).Revision, At: 1, Proof: proof})
		return raw
	}
	if work, err := f.p.VolumeRemoteFences(f.s, mine); err != nil || len(work) != 0 {
		t.Fatal("fence work for a live runner", work, err)
	}
	if _, err := f.p.ResolveVolumeRemoteFenceReport(f.s, home, report(f.node)); err == nil {
		t.Fatal("fence accepted while the runner is a member")
	}

	removeNode(t, f)
	if _, _, err := f.p.VolumeRemoteGrant(f.s, home, runner, f.scope, writer.ID); err == nil {
		t.Fatal("retired runner granted")
	}
	work, err := f.p.VolumeRemoteFences(f.s, mine)
	if err != nil || len(work) != 1 || work[0].Consumer != writer || work[0].Owner != home {
		t.Fatal("fence work", work, err)
	}
	if w, _ := f.p.VolumeRemoteFences(f.s, func([32]byte) bool { return false }); len(w) != 0 {
		t.Fatal("work for another owner")
	}
	if _, err := f.p.ResolveVolumeRemoteFenceReport(f.s, runner, report(f.node)); err == nil {
		t.Fatal("fence sent by the runner")
	}
	if _, err := f.p.ResolveVolumeRemoteFenceReport(f.s, home, report(f.admin)); err == nil {
		t.Fatal("fence signed by another key")
	}
	cmd, err := f.p.ResolveVolumeRemoteFenceReport(f.s, home, report(f.node))
	if err != nil || cmd.Actor != "node/"+hex.EncodeToString(home[:]) {
		t.Fatal(cmd.Actor, err)
	}
	var result state.Result
	f.s, result, err = state.ApplyAdmitted(f.s, f.s.Index()+1, cmd, f.p.Validate, f.p.Reduce, f.p.AdmitModule)
	if err != nil || result.Code != state.Applied {
		t.Fatal(result.Code, err)
	}
	v := f.view()
	e := v.entries[volumeKey(f.scope)]
	if len(e.State.Consumers()) != 0 || len(e.Grants) != 0 {
		t.Fatal("consumer left after the fence", e.State.Consumers(), e.Grants)
	}
	if w, _ := f.p.VolumeRemoteFences(f.s, mine); len(w) != 0 {
		t.Fatal("work after the fence", w)
	}
}
