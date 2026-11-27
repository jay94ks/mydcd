// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

// RQ4 node-pair link reconnect in sfcd's real shape
// (docs/reference/tunnel-reconnect.md): `tunnel-reconnect-plan` →
// signed `reconnect-tunnel` control.TunnelChange{Operation, Plan}
// (Expected 0, root of control.TunnelReconnectKey) →
// `tunnel-reconnect-status`. System admin (ManageCluster) only.
//
// Fake-only:
//   - The link of a pair is the w.links FixtureLink row. Fake.SetMeshLinkDown
//     breaks or mends it and records one tenant-scoped tunnel-down/-up per
//     TUN network that has both nodes.
//   - The plan's Observation is a fresh node-observation Report signed
//     with FixtureKey(node); Owner/PeerKey are the member keys.
//   - Accepted jobs are queued, running after 1 s and settled after 3 s
//     (FinishTunnelReconnects settles now, HoldTunnelReconnects keeps them).
//     A pair still down is reconnected (link up, HandshakeAt now); a pair
//     already up gives already-connected; FailTunnelReconnect makes the
//     next run of a pair fail with that code. A settled job records the
//     node-scoped tunnel-reconnected (failed: tunnel-down) event.

type tunnelJobs struct {
	records  []control.TunnelRecord
	accepted map[string]int64  // operation → accept time
	fail     map[string]string // pair ID → code of the next run
	hold     bool
}

func (w *world) tunJobsState() *tunnelJobs {
	if w.tunJobs.accepted == nil {
		w.tunJobs.accepted, w.tunJobs.fail = map[string]int64{}, map[string]string{}
	}
	return &w.tunJobs
}

// HoldTunnelReconnects keeps accepted jobs queued/running until released.
func (f *Fake) HoldTunnelReconnects(hold bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.tunJobsState().hold = hold
}

// FinishTunnelReconnects settles every pending job now.
func (f *Fake) FinishTunnelReconnects() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.tunJobsState().hold = false
	f.w.settleTunnels(f.now().Unix(), true)
}

// FailTunnelReconnect makes the next run for the pair fail with code
// (e.g. "dial-failed", "peer-changed", "authority-revoked").
func (f *Fake) FailTunnelReconnect(node, peer, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.tunJobsState().fail[observability.PairID(node, peer)] = code
}

// SetMeshLinkDown breaks (or mends) the link of a node pair.
func (f *Fake) SetMeshLinkDown(a, b string, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.w.meshLink(a, b) == nil {
		panic("sfcli fake: no mesh link " + observability.PairID(a, b))
	}
	f.w.setPairDown(a, b, down, f.now().Unix())
}

func (w *world) meshLink(a, b string) *FixtureLink {
	if a > b {
		a, b = b, a
	}
	for i := range w.links {
		l := &w.links[i]
		x, y := l.NodeA, l.NodeB
		if x > y {
			x, y = y, x
		}
		if x == a && y == b {
			return l
		}
	}
	return nil
}

// setPairDown flips the pair's mesh link, with one tunnel-down/-up event
// per network the pair carries.
func (w *world) setPairDown(a, b string, down bool, now int64) {
	l := w.meshLink(a, b)
	if l == nil || (l.State == "down") == down {
		return
	}
	l.State, l.LastChangeAt, l.ObservedAt = "up", now, now
	l.LossPercent = 0
	if down {
		l.State = "down"
	} else {
		l.LastHandshakeAt = now
	}
	if a > b {
		a, b = b, a
	}
	kind := "tunnel-up"
	if down {
		kind = "tunnel-down"
	}
	for _, key := range w.pairNetworks(a, b) {
		w.addEvent(tunnelEvent(kind, key[0], key[1], a, b, now))
	}
}

// pairNetworks: tenant/network of every TUN network with both nodes.
func (w *world) pairNetworks(a, b string) [][2]string {
	var out [][2]string
	for _, e := range w.resources {
		n := e.Network
		if n == nil || n.Kind != "tun" || !slices.Contains(n.Nodes, a) || !slices.Contains(n.Nodes, b) {
			continue
		}
		key := [2]string{e.Tenant, n.Name}
		if !slices.Contains(out, key) {
			out = append(out, key)
		}
	}
	return out
}

func memberKey32(m FixtureMember) (out [32]byte) {
	raw, _ := hex.DecodeString(m.Key)
	copy(out[:], raw)
	return out
}

// tunnelPlanTarget: control's tunnelTarget.
func tunnelPlanTarget(p control.TunnelPlan) [32]byte {
	p.Target = [32]byte{}
	raw, _ := json.Marshal(p)
	return sha256.Sum256(append([]byte("sfc-tunnel-plan-1\x00"), raw...))
}

func (w *world) tunnelPlan(node, peer string, now int64) (control.TunnelPlan, Code) {
	i, j := w.memberIndex(node), w.memberIndex(peer)
	if i < 0 || j < 0 || w.members[i].Phase != NodePhaseActive || w.members[j].Phase != NodePhaseActive {
		return control.TunnelPlan{}, CodeConflict
	}
	l := w.meshLink(node, peer)
	if l == nil || l.State != "down" {
		return control.TunnelPlan{}, CodeConflict
	}
	at := uint64(now) * 1000
	link := observability.Link{ID: observability.PairID(node, peer), Peer: peer, State: "down", Measurement: "quic-connection-cumulative",
		LastHandshakeAt: uint64(max(l.LastHandshakeAt, 0)) * 1000, LastChangeAt: uint64(max(l.LastChangeAt, 1)) * 1000}
	link.LastHandshakeAt, link.LastChangeAt = min(link.LastHandshakeAt, at), min(link.LastChangeAt, at)
	link.Outages = []observability.Outage{{StartedAt: link.LastChangeAt}}
	r := observability.Report{Kind: "node-observation", Schema: 1, Cluster: w.cluster, Node: node, Key: memberKey32(w.members[i]), Index: max(w.root, 1), At: at, Link: &link}
	r.Signature = ed25519.Sign(FixtureKey(node), observability.SigningBytes(r))
	p := control.TunnelPlan{Schema: 1, Cluster: w.cluster, Node: node, Peer: peer, Endpoint: w.members[j].Endpoint, PairID: link.ID,
		Owner: r.Key, PeerKey: memberKey32(w.members[j]), Observation: r}
	p.Target = tunnelPlanTarget(p)
	return p, ""
}

// PlanTunnelReconnect: `tunnel-reconnect-plan` Tunnel:{Node, Peer}.
func (c *fakeConn) PlanTunnelReconnect(ctx context.Context, node, peer string) (control.TunnelPlan, error) {
	const m = "tunnel-reconnect-plan"
	if !(control.TunnelQuery{Node: node, Peer: peer}).Valid(true) {
		return control.TunnelPlan{}, fail(m, CodeInvalid, "query")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.TunnelPlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(user) {
		return control.TunnelPlan{}, fail(m, CodeDenied, "")
	}
	now := c.f.now().Unix()
	w.settleTunnels(now, false)
	p, code := w.tunnelPlan(node, peer, now)
	if code != "" {
		return control.TunnelPlan{}, fail(m, code, "link is not down")
	}
	return p, nil
}

// TunnelReconnectStatus: `tunnel-reconnect-status` Tunnel:{Operation}.
func (c *fakeConn) TunnelReconnectStatus(ctx context.Context, operation string) (control.TunnelStatus, error) {
	const m = "tunnel-reconnect-status"
	if !(control.TunnelQuery{Operation: operation}).Valid(false) {
		return control.TunnelStatus{}, fail(m, CodeInvalid, "operation")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return control.TunnelStatus{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(user) {
		return control.TunnelStatus{}, fail(m, CodeDenied, "")
	}
	w.settleTunnels(c.f.now().Unix(), false)
	row, ok := (control.TunnelReconnections{Records: w.tunJobsState().records}).Record(operation)
	if !ok {
		return control.TunnelStatus{}, fail(m, CodeConflict, "")
	}
	return control.TunnelStatus{Schema: 1, Operation: row.Operation, User: row.Origin.Session.User, State: row.State, Plan: row.Plan,
		Revision: row.Revision, RootRevision: w.keyRoot(control.TunnelReconnectKey), At: row.At, Reason: row.Origin.Reason, Result: row.Result}, nil
}

func (c *fakeConn) applyTunnelReconnect(op UserOperation, actor string) error {
	w := c.f.w
	var q control.TunnelChange
	if decodePayload(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 || q.Plan.Cluster != w.cluster {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	now := c.f.now().Unix()
	w.settleTunnels(now, false)
	p := q.Plan
	i, j := w.memberIndex(p.Node), w.memberIndex(p.Peer)
	if i < 0 || j < 0 || memberKey32(w.members[i]) != p.Owner || memberKey32(w.members[j]) != p.PeerKey || w.members[j].Endpoint != p.Endpoint {
		return errCAS
	}
	if !observability.Fresh(p.Observation.At, uint64(now)*1000) {
		return errCAS
	}
	jobs := w.tunJobsState()
	if _, dup := jobs.accepted[q.Operation]; dup || len(jobs.records) >= 128 {
		return errCAS
	}
	for _, r := range jobs.records {
		if (r.State == "queued" || r.State == "running") && r.Plan.PairID == p.PairID {
			return errCAS
		}
	}
	jobs.records = append(jobs.records, control.TunnelRecord{Origin: op, Operation: q.Operation, Plan: p, Revision: 1, At: uint64(now), State: "queued"})
	jobs.accepted[q.Operation] = now
	return nil
}

func (w *world) settleTunnels(now int64, all bool) {
	jobs := w.tunJobsState()
	for i := range jobs.records {
		r := &jobs.records[i]
		if r.State != "queued" && r.State != "running" || jobs.hold && !all {
			continue
		}
		accepted := jobs.accepted[r.Operation]
		if all || now-accepted >= 3 {
			r.Result = w.runTunnel(r.Plan, now)
			r.State = "done"
			kind := "tunnel-reconnected"
			if r.Result.State == "failed" {
				r.State, kind = "failed", "tunnel-down"
			}
			r.Revision++
			r.At = uint64(now)
			w.bumpKey(control.TunnelReconnectKey)
			detail := r.Result.State
			if r.Result.Code != "" {
				detail = r.Result.Code
			}
			w.addEvent(FixtureEvent{Time: now, Scope: "node", Node: r.Plan.Node, Kind: kind, Target: r.Plan.PairID, PairID: r.Plan.PairID, Detail: detail})
		} else if now-accepted >= 1 && r.State == "queued" {
			r.State, r.At = "running", uint64(now)
			r.Revision++
		}
	}
}

func (w *world) runTunnel(p control.TunnelPlan, now int64) *control.TunnelResult {
	jobs := w.tunJobsState()
	if code, ok := jobs.fail[p.PairID]; ok {
		delete(jobs.fail, p.PairID)
		return &control.TunnelResult{State: "failed", Code: code, Error: "fake: " + code, PairID: p.PairID}
	}
	l := w.meshLink(p.Node, p.Peer)
	at := uint64(now) * 1000
	if l != nil && l.State != "down" {
		hs := max(uint64(max(l.LastHandshakeAt, 0))*1000, p.Observation.Link.LastHandshakeAt)
		if hs == 0 {
			hs = at
		}
		return &control.TunnelResult{State: "already-connected", PairID: p.PairID, HandshakeAt: hs, KeptExisting: true}
	}
	w.setPairDown(p.Node, p.Peer, false, now)
	return &control.TunnelResult{State: "reconnected", PairID: p.PairID, HandshakeAt: max(at, p.Observation.Link.LastHandshakeAt)}
}
