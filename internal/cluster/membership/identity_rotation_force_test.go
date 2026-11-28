// SPDX-License-Identifier: Apache-2.0

package membership

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
)

// A server whose key rotation was activated but that died before reporting
// it installed (lab jay3, 2026-11-28) can still be force-removed: only that
// server can finish the rotation. A plain removal still waits for it, and
// the abandoned rotation takes no further step and blocks nothing.
func TestForceRemovalAbandonsTheServersOwnStuckRotation(t *testing.T) {
	d, ak, bk := runtimeMembers(t)
	entry, _ := d.Entry("b")
	next := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{92}, ed25519.SeedSize))
	proof := lifecycle.IdentityProof{Schema: 1, Cluster: d.Cluster, Node: "b", Operation: "replace-b", Old: memberKey(bk), New: memberKey(next), Prepared: [32]byte{1}}
	proof.OldSignature = ed25519.Sign(bk, lifecycle.IdentityProofBytes(proof))
	proof.NewSignature = ed25519.Sign(next, lifecycle.IdentityProofBytes(proof))
	n, err := d.BeginIdentityRotation("b", "replace-b", entry.Revision, 20, json.RawMessage(`{"original":"replace-b"}`))
	d = checked(t, n, err)
	n, err = d.PrepareIdentityRotation("b", "replace-b", proof)
	d = checked(t, n, err)
	n, err = d.ActivateIdentityRotation("b", "replace-b", 22)
	d = checked(t, n, err)

	plain, err := d.PlanNodeChange("b", true)
	if err != nil || !slices.Contains(plain.Blockers, "NODE_OPERATION_PENDING") {
		t.Fatal("a plain removal did not wait for the rotation", plain, err)
	}
	forced, err := d.PlanForceRemoval("b")
	if err != nil || slices.Contains(forced.Blockers, "NODE_OPERATION_PENDING") {
		t.Fatal("the server's own stuck rotation blocks its forced removal", forced, err)
	}
	topology, _ := d.Topology()
	b, _ := topology.Node("b")
	probe := lifecycle.RemovalProbe{Schema: 1, Cluster: d.Cluster, Node: "b", Operation: "force-b", Target: memberKey(next), Observer: memberKey(ak), Epoch: topology.Epoch(), Expected: b.Revision, ConfigurationIndex: 14, RootRevision: 7, StartedAt: 10, FinishedAt: 13, Challenge: [32]byte{1}}
	probe.Signature = ed25519.Sign(ak, lifecycle.RemovalProbeBytes(probe))
	n, err = d.BeginForceRemoval("b", "force-b", b.Revision, topology.Epoch(), json.RawMessage(`{"original":"force-b"}`), probe)
	d = checked(t, n, err)
	row, _ := d.IdentityRotation("b", "replace-b")
	if !row.Abandoned || row.Phase != "Activated" || !row.Settled() {
		t.Fatal("the stuck rotation was not closed", row)
	}
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if d, err = Decode(raw); err != nil {
		t.Fatal("an abandoned rotation does not decode", err)
	}
	n, err = d.InstalledIdentityRotation("b", "replace-b", 30)
	assertRejected(t, d, n, err)
	n, err = d.FailIdentityRotation("b", "replace-b", "IDENTITY_ACTIVATE_FAILED")
	assertRejected(t, d, n, err)
	// Other servers' changes do not wait for it.
	other, err := d.PlanNodeChange("a", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range d.Rotations {
		if !row.Settled() {
			t.Fatal("a rotation is still pending", row, other)
		}
	}
}
