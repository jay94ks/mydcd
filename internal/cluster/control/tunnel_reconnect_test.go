// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/membership"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/observability"
)

func tunnelCoreFixture(t *testing.T) (*backupCoreFixture, TunnelPlan) {
	t.Helper()
	f := newBackupCore(t)
	b := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	d, err := f.p.Members(f.s)
	if err != nil {
		t.Fatal(err)
	}
	peer := config.Peer{ID: "node-b", Key: hex.EncodeToString(b.Public().(ed25519.PublicKey)), Endpoint: "127.0.0.1:8002"}
	d, err = d.Invite(peer, "tunnel-join-b", nil)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := d.Entry(peer.ID)
	d, err = d.Dispatch(peer.ID, e.Revision, e.Job.Pending.ID, 1, f.p.TrustRoot)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = d.Entry(peer.ID)
	d, err = d.Observe(peer.ID, e.Revision, e.Job.Pending.ID, 4, peer)
	if err != nil {
		t.Fatal(err)
	}
	e, _ = d.Entry(peer.ID)
	ack := membership.Ack{Schema: 1, Cluster: f.p.Cluster, Node: peer.ID, JoinID: e.JoinID, Key: [32]byte(b.Public().(ed25519.PublicKey)), ConfigurationIndex: 4, AppliedIndex: 5}
	ack.Signature = ed25519.Sign(b, membership.AckBytes(ack))
	d, err = d.Installed(ack, e.Revision)
	if err != nil {
		t.Fatal(err)
	}
	writes, code := f.p.memberCheckpoint(f.s, d)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.s, _, err = state.ApplyReduced(f.s, f.s.Index()+1, state.Command{Kind: state.Module, Actor: "anchor", Epoch: 1, RequestID: "tunnel-members-fixture", Key: MembersKey, Value: "fixture"}, f.p.Validate, func(state.State, state.Command) (map[string][]byte, state.Code) { return writes, state.Applied })
	if err != nil {
		t.Fatal(err)
	}
	r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: f.p.Cluster, Node: "node-a", Key: f.p.TrustRoot, Index: f.s.Index(), At: 2000, Link: &observability.Link{ID: "node-a/node-b", Peer: "node-b", State: "down", Measurement: "quic-connection-cumulative", LastHandshakeAt: 1000, LastChangeAt: 1900}}
	r.Signature = ed25519.Sign(f.node, observability.SigningBytes(r))
	plan, err := f.p.PlanTunnelReconnect(f.s, f.session, 2, TunnelQuery{Node: "node-a", Peer: "node-b"}, []observability.Report{r})
	if err != nil || !plan.Valid() {
		t.Fatal("original signed down plan", err)
	}
	return f, plan
}
func tunnelCoreReport(t *testing.T, f *backupCoreFixture, id, action string, result *TunnelResult, want state.Code) {
	t.Helper()
	jobs, err := f.p.TunnelReconnections(f.s)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := jobs.Record(id)
	if !ok {
		t.Fatal("original absent")
	}
	r := TunnelReport{Schema: 1, Cluster: f.p.Cluster, Owner: row.Plan.Owner, Operation: id, Action: action, Expected: row.Revision, RootRevision: f.s.Object(TunnelReconnectKey).Revision, Epoch: f.s.ModuleEpoch(), At: 3, Result: result}
	r.Signature = ed25519.Sign(f.node, TunnelReportBytes(r))
	cmd, err := r.Command()
	if err != nil {
		t.Fatal(err)
	}
	applyRestartCore(t, f, cmd, want)
}
func TestTunnelReconnectPinsOriginalPairGrantAndOwnerProgressWithoutNewNodeAuthority(t *testing.T) {
	f, plan := tunnelCoreFixture(t)
	before, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _ := managedDNSChange(t, f, "tunnel-original", "reconnect-tunnel", 0, TunnelChange{Operation: "restore-link", Plan: plan}, state.Applied)
	pending, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil || pending.Resources != before.Resources+1 {
		t.Fatal("original missing from owner closure", err)
	}
	if f.p.storageQuiescent(f.s) {
		t.Fatal("pending original ledger reclaimed")
	}
	managedDNSChange(t, f, "tunnel-other", "reconnect-tunnel", 0, TunnelChange{Operation: "same-pair-race", Plan: plan}, state.ConditionFailed)
	work, err := f.p.TunnelWork(f.s, plan.Owner, TunnelWorkRequest{Operation: "restore-link"})
	if err != nil || !work.Allowed || work.Plan.Target != plan.Target {
		t.Fatal("current original work", err)
	}
	if _, err := f.p.TunnelWork(f.s, plan.PeerKey, TunnelWorkRequest{Operation: "restore-link"}); err == nil {
		t.Fatal("peer borrowed owner effect authority")
	}
	tunnelCoreReport(t, f, "restore-link", "finish", &TunnelResult{State: "already-connected", PairID: plan.PairID, HandshakeAt: 3000, KeptExisting: true}, state.ConditionFailed)
	tunnelCoreReport(t, f, "restore-link", "begin", nil, state.Applied)
	tunnelCoreReport(t, f, "restore-link", "finish", &TunnelResult{State: "already-connected", PairID: plan.PairID, HandshakeAt: 3000, KeptExisting: true}, state.Applied)
	applyRestartCore(t, f, cmd, state.Applied)
	status, err := f.p.TunnelStatus(f.s, f.session, 3, TunnelQuery{Operation: "restore-link"})
	if err != nil || status.State != "done" || status.Result == nil || status.Result.State != "already-connected" {
		t.Fatal("original result changed", err)
	}
	raw, _ := json.Marshal(status)
	if bytes.Contains(raw, []byte("Session")) || bytes.Contains(raw, []byte("Origin")) {
		t.Fatal("public result exposed accepted grant")
	}
	current, err := f.p.NodeActivity(f.s, plan.Owner)
	if err != nil || current.Resources != before.Resources {
		t.Fatal("settled owner still pinned", err)
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.TunnelReconnections(restored); err != nil {
		t.Fatal("snapshot lost original", err)
	}
}
func TestTunnelReconnectRevocationCancelsOnlyUnsentAndPlanRequiresFreshAuthenticDown(t *testing.T) {
	f, plan := tunnelCoreFixture(t)
	clipped := f.session
	clipped.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	clipped.Signature = ed25519.Sign(f.node, access.SessionBytes(clipped))
	q := TunnelQuery{Node: plan.Node, Peer: plan.Peer}
	if _, err := f.p.PlanTunnelReconnect(f.s, clipped, 2, q, []observability.Report{plan.Observation}); err == nil {
		t.Fatal("tenant read gained repair")
	}
	if _, err := f.p.PlanTunnelReconnect(f.s, f.session, 200, q, []observability.Report{plan.Observation}); err == nil {
		t.Fatal("stale down planned")
	}
	forged := plan.Observation
	forged.Signature = bytes.Clone(forged.Signature)
	forged.Signature[0] ^= 1
	if _, err := f.p.PlanTunnelReconnect(f.s, f.session, 2, q, []observability.Report{forged}); err == nil {
		t.Fatal("forged down planned")
	}
	if !tunnelObservationFresh(2500, 2) || tunnelObservationFresh(3000, 2) {
		t.Fatal("mixed ms/sec freshness boundary")
	}
	managedDNSChange(t, f, "revoke-original", "reconnect-tunnel", 0, TunnelChange{Operation: "revoked-link", Plan: plan}, state.Applied)
	restricted := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{163}, ed25519.SeedSize))
	f.replaceOwnKey("key", "restricted", [32]byte(restricted.Public().(ed25519.PublicKey)), []string{"cordon-node"})
	work, err := f.p.TunnelWork(f.s, plan.Owner, TunnelWorkRequest{Operation: "revoked-link"})
	if err != nil || work.Allowed {
		t.Fatal("revoked original permitted Dial", err)
	}
	tunnelCoreReport(t, f, "revoked-link", "begin", nil, state.Forbidden)
	tunnelCoreReport(t, f, "revoked-link", "cancel", &TunnelResult{State: "failed", Code: "authority-revoked", PairID: plan.PairID}, state.Applied)
}
