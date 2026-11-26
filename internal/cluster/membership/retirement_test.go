// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Probe failures and SDK configurations are injected facts, not real network
// silence, native stop, or a writable Volume fence.
func TestForceRetirementPreservesUnknownAndNeverAssertsNativeClosure(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	topology, _ := d.Topology()
	b, _ := topology.Node("b")
	probe := lifecycle.RemovalProbe{Schema: 1, Cluster: d.Cluster, Node: "b", Operation: "force-b", Target: memberKey(bk), Observer: memberKey(ak), Epoch: topology.Epoch(), Expected: b.Revision, ConfigurationIndex: 14, RootRevision: 7, StartedAt: 10, FinishedAt: 13, Challenge: [32]byte{1}}
	probe.Signature = ed25519.Sign(ak, lifecycle.RemovalProbeBytes(probe))
	origin := json.RawMessage(`{"original":"force-b"}`)
	n, err := d.BeginForceRemoval("b", "force-b", b.Revision, topology.Epoch(), origin, probe)
	d = checked(t, n, err)
	status, _ := d.NodeView("b")
	if status.Node.Phase != lifecycle.Retiring || status.Node.Closure != nil || status.Node.Retirement == nil || status.AdmitsWork {
		t.Fatal("logical retirement fabricated native closure")
	}
	if _, err = d.ObserveNode(runtimeNodeProof(t, d, "b", bk)); err == nil {
		t.Fatal("force removal accepted a synthetic normal closure")
	}
	n, err = d.DispatchRemoval("force-b", d.Revision, 14, memberKey(ak))
	d = checked(t, n, err)
	original, _ := d.NodeOperation("force-b")
	n, err = d.UnknownRemoval("force-b", d.Revision)
	d = checked(t, n, err)
	unknown, _ := d.NodeOperation("force-b")
	if unknown.Job.Pending.Phase != reconcile.RecoveryRequired || unknown.Job.Pending.Target != original.Job.Pending.Target || unknown.Job.Pending.ID != original.Job.Pending.ID {
		t.Fatal("force removal lost original unknown")
	}
	n, err = d.DispatchRemoval("force-b", d.Revision, 14, memberKey(ak))
	assertRejected(t, d, n, err)
	topology, _ = d.Topology()
	c := topology.Configuration()
	c.Index = 15
	c.Members = c.Members[:1]
	n, err = d.InstallConfiguration(c)
	d = checked(t, n, err)
	status, _ = d.NodeView("b")
	finished, _ := d.NodeOperation("force-b")
	if status.Node.Phase != lifecycle.Retired || status.Node.Closure != nil || status.Node.Retirement == nil || finished.Job.Pending != nil || !bytes.Equal(finished.Origin, original.Origin) || d.MemberKey(memberKey(bk)) || d.ReplicationKey(memberKey(bk)) || !d.HistoricalMemberKey(memberKey(bk)) {
		t.Fatal("retired identity leaked current authority or lost original history")
	}
	topology, _ = d.Topology()
	n, err = d.RotateNodeOperations(topology.Revision(), topology.Epoch())
	d = checked(t, n, err)
	if _, found := d.NodeOperation("force-b"); !found {
		t.Fatal("rotation forgot logical retirement evidence")
	}
}

func TestForceRetirementRequiresExactSignedProbeAndRespondingNodeRefuses(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	topology, _ := d.Topology()
	b, _ := topology.Node("b")
	base := lifecycle.RemovalProbe{Schema: 1, Cluster: d.Cluster, Node: "b", Operation: "force-b", Target: memberKey(bk), Observer: memberKey(ak), Epoch: topology.Epoch(), Expected: b.Revision, ConfigurationIndex: 14, StartedAt: 10, FinishedAt: 13, Challenge: [32]byte{1}}
	for _, mutate := range []func(*lifecycle.RemovalProbe){func(p *lifecycle.RemovalProbe) { p.Responding = true }, func(p *lifecycle.RemovalProbe) { p.Target = memberKey(ak) }, func(p *lifecycle.RemovalProbe) { p.Operation = "other" }, func(p *lifecycle.RemovalProbe) { p.ConfigurationIndex++ }, func(p *lifecycle.RemovalProbe) { p.Observer = memberKey(bk) }, func(p *lifecycle.RemovalProbe) { p.Challenge = [32]byte{} }} {
		p := base
		mutate(&p)
		p.Signature = ed25519.Sign(ak, lifecycle.RemovalProbeBytes(p))
		n, err := d.BeginForceRemoval("b", "force-b", b.Revision, topology.Epoch(), json.RawMessage(`{}`), p)
		assertRejected(t, d, n, err)
	}
}
