// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/eventlog"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/observability"
)

const TunnelReconnectKey = "control/tunnel-reconnects"

type TunnelQuery struct{ Node, Peer, Operation string }

func (q TunnelQuery) Valid(plan bool) bool {
	if plan {
		return lifecycle.ValidID(q.Node) && lifecycle.ValidID(q.Peer) && q.Node != q.Peer && q.Operation == ""
	}
	return q.Node == "" && q.Peer == "" && lifecycle.ValidID(q.Operation)
}

type TunnelPlan struct {
	Schema                       uint8
	Cluster                      [32]byte
	Node, Peer, Endpoint, PairID string
	Owner, PeerKey, Target       [32]byte
	Observation                  observability.Report
}

func tunnelTarget(plan TunnelPlan) [32]byte {
	plan.Target = [32]byte{}
	raw, _ := json.Marshal(plan)
	return sha256.Sum256(append([]byte("sfc-tunnel-plan-1\x00"), raw...))
}
func (p TunnelPlan) Valid() bool {
	r := p.Observation
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > 8<<10 {
		return false
	}
	return p.Schema == 1 && p.Cluster != ([32]byte{}) && lifecycle.ValidID(p.Node) && lifecycle.ValidID(p.Peer) && p.Node != p.Peer && p.Endpoint != "" && len(p.Endpoint) <= 512 && p.Owner != ([32]byte{}) && p.PeerKey != ([32]byte{}) && p.Owner != p.PeerKey && p.PairID == observability.PairID(p.Node, p.Peer) && r.Valid() && r.Cluster == p.Cluster && r.Key == p.Owner && r.Node == p.Node && r.Link != nil && r.Link.Peer == p.Peer && r.Link.ID == p.PairID && r.Link.State == "down" && p.Target == tunnelTarget(p)
}

type TunnelChange struct {
	Operation string
	Plan      TunnelPlan
}

func (q TunnelChange) Valid() bool { return lifecycle.ValidID(q.Operation) && q.Plan.Valid() }

type TunnelResult struct {
	State, Code, Error, PairID string
	HandshakeAt                uint64
	KeptExisting               bool
}

func (r TunnelResult) Valid(plan TunnelPlan) bool {
	raw, err := json.Marshal(r)
	if !plan.Valid() || err != nil || len(raw) > 4<<10 || !utf8.ValidString(r.Error) || r.PairID != plan.PairID || len(r.Error) > 512 || len(r.Code) > 64 {
		return false
	}
	switch r.State {
	case "reconnected":
		return r.HandshakeAt >= plan.Observation.Link.LastHandshakeAt && r.HandshakeAt > 0 && !r.KeptExisting && r.Code == "" && r.Error == ""
	case "already-connected":
		return r.HandshakeAt >= plan.Observation.Link.LastHandshakeAt && r.HandshakeAt > 0 && r.KeptExisting && r.Code == "" && r.Error == ""
	case "failed":
		return validCompactCode(r.Code) && !r.KeptExisting && r.HandshakeAt == 0
	}
	return false
}

type TunnelRecord struct {
	Origin       UserOperation
	Operation    string
	Plan         TunnelPlan
	Revision, At uint64
	State        string
	Result       *TunnelResult `json:",omitempty"`
}
type TunnelReconnections struct {
	Schema   uint8
	Cluster  [32]byte
	Revision uint64
	Records  []TunnelRecord
}

func (t TunnelReconnections) Record(id string) (TunnelRecord, bool) {
	for _, row := range t.Records {
		if row.Operation == id {
			raw, _ := json.Marshal(row)
			var out TunnelRecord
			_ = json.Unmarshal(raw, &out)
			return out, true
		}
	}
	return TunnelRecord{}, false
}
func (t TunnelReconnections) Quiescent() bool {
	for _, row := range t.Records {
		if row.State == "queued" || row.State == "running" {
			return false
		}
	}
	return true
}
func (p Policy) TunnelReconnections(s state.State) (TunnelReconnections, error) {
	out := TunnelReconnections{Schema: 1, Cluster: p.Cluster}
	raw, revision, err := readCheckpoint(s, TunnelReconnectKey, p.Cluster, p.TrustRoot)
	if err != nil || raw == nil {
		return out, err
	}
	if canonical(raw, &out) != nil || out.Schema != 1 || out.Cluster != p.Cluster || out.Revision != revision || len(out.Records) > 128 {
		return out, ErrCatalog
	}
	seen := map[string]bool{}
	for _, r := range out.Records {
		var change TunnelChange
		if r.Origin.VerifyOriginal(p.Cluster) != nil || r.Origin.Change.Action != "reconnect-tunnel" || canonical(r.Origin.Change.Payload, &change) != nil || !change.Valid() || r.Operation != change.Operation || r.Plan.Target != change.Plan.Target || !r.Plan.Valid() || r.Plan.Cluster != p.Cluster || r.Revision == 0 || r.At < uint64(r.Origin.At) || seen[r.Operation] {
			return out, ErrCatalog
		}
		seen[r.Operation] = true
		switch r.State {
		case "queued", "running":
			if r.Result != nil {
				return out, ErrCatalog
			}
		case "done", "failed":
			if r.Result == nil || !r.Result.Valid(r.Plan) || (r.State == "done") != (r.Result.State != "failed") {
				return out, ErrCatalog
			}
		default:
			return out, ErrCatalog
		}
	}
	return out, nil
}
func (p Policy) currentTunnel(s state.State, plan TunnelPlan) error {
	d, err := p.Members(s)
	if err != nil {
		return err
	}
	for _, target := range []struct {
		id  string
		key [32]byte
	}{{plan.Node, plan.Owner}, {plan.Peer, plan.PeerKey}} {
		entry, ok := d.Entry(target.id)
		key, e := identity.ParseKey(entry.CurrentPeer().Key)
		if !ok || e != nil || key != target.key || !d.MemberKey(key) {
			return access.ErrDenied
		}
		if target.id == plan.Peer && entry.Peer.Endpoint != plan.Endpoint {
			return access.ErrConflict
		}
	}
	return nil
}
func (p Policy) tunnelAuthorized(s state.State, session access.Session, at int64, accepted bool) error {
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if err = c.OperationAllowed(session, "reconnect-tunnel"); err != nil {
		return err
	}
	if accepted {
		return c.AuthorizeAccepted(session, p.Cluster, at, "", access.ManageCluster, "")
	}
	return c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "")
}
func (p Policy) PlanTunnelReconnect(s state.State, session access.Session, at int64, q TunnelQuery, reports []observability.Report) (TunnelPlan, error) {
	var out TunnelPlan
	p, err := p.Current(s)
	if err != nil || !q.Valid(true) || at <= 0 {
		return out, access.ErrDenied
	}
	if err = p.tunnelAuthorized(s, session, at, false); err != nil {
		return out, err
	}
	d, err := p.Members(s)
	if err != nil {
		return out, err
	}
	entry, ok := d.Entry(q.Peer)
	peerKey, e := identity.ParseKey(entry.CurrentPeer().Key)
	if !ok || e != nil {
		return out, access.ErrDenied
	}
	var latest *observability.Report
	for _, r := range reports {
		if r.Node == q.Node && r.Link != nil && r.Link.Peer == q.Peer && (latest == nil || r.At > latest.At) {
			own := r
			latest = &own
		}
	}
	if latest == nil || !latest.Valid() || latest.Cluster != p.Cluster || !tunnelObservationFresh(latest.At, at) || latest.Link.State != "down" || latest.Index > s.Index() {
		return out, access.ErrConflict
	}
	out = TunnelPlan{Schema: 1, Cluster: p.Cluster, Node: q.Node, Peer: q.Peer, Owner: latest.Key, PeerKey: peerKey, Endpoint: entry.Peer.Endpoint, PairID: observability.PairID(q.Node, q.Peer), Observation: *latest}
	out.Target = tunnelTarget(out)
	if !out.Valid() {
		return out, access.ErrConflict
	}
	return out, p.currentTunnel(s, out)
}
func (p Policy) tunnelCheckpoint(s state.State, jobs TunnelReconnections) (map[string][]byte, state.Code) {
	if jobs.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	jobs.Revision++
	raw, err := json.Marshal(jobs)
	if err != nil || len(raw) > 4<<20 {
		return nil, state.ConditionFailed
	}
	return writeCheckpoint(s, TunnelReconnectKey, p.Cluster, p.TrustRoot, jobs.Revision, raw)
}
func (p Policy) reduceTunnelReconnect(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if cmd.Kind == state.ModuleReport {
		return p.reduceTunnelReport(s, cmd)
	}
	p, err := p.Current(s)
	if err != nil || cmd.Kind != state.Module || cmd.Key != TunnelReconnectKey {
		return nil, state.Forbidden
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || op.Change.Action != "reconnect-tunnel" || p.tunnelAuthorized(s, op.Session, op.At, false) != nil {
		return nil, state.Forbidden
	}
	var q TunnelChange
	if canonical(op.Change.Payload, &q) != nil || !q.Valid() || q.Plan.Cluster != p.Cluster || op.Change.Expected != 0 {
		return nil, state.Invalid
	}
	if p.currentTunnel(s, q.Plan) != nil || !tunnelObservationFresh(q.Plan.Observation.At, op.At) || q.Plan.Observation.Index > s.Index() {
		return nil, state.ConditionFailed
	}
	jobs, err := p.TunnelReconnections(s)
	if err != nil {
		return nil, state.Invalid
	}
	if len(jobs.Records) >= 128 {
		return nil, state.ConditionFailed
	}
	for _, r := range jobs.Records {
		if r.Operation == q.Operation || (r.State == "queued" || r.State == "running") && r.Plan.PairID == q.Plan.PairID {
			return nil, state.ConditionFailed
		}
	}
	jobs.Records = append(jobs.Records, TunnelRecord{Origin: op, Operation: q.Operation, Plan: q.Plan, Revision: 1, At: uint64(op.At), State: "queued"})
	raw, budgetErr := json.Marshal(jobs)
	reserved := 0
	for _, row := range jobs.Records {
		if row.State == "queued" || row.State == "running" {
			reserved += 6 << 10
		}
	}
	if budgetErr != nil || len(raw)+reserved > 4<<20 {
		return nil, state.ConditionFailed
	}
	return p.tunnelCheckpoint(s, jobs)
}

func tunnelObservationFresh(observed uint64, at int64) bool {
	return at > 0 && uint64(at) <= (^uint64(0)-999)/1000 && observability.Fresh(observed, uint64(at)*1000+999)
}

// tunnelReconnectBook is the TunnelReconnectKey Raft book (see book.go).
var tunnelReconnectBook = Book{
	Key:       TunnelReconnectKey,
	Actions:   []string{"reconnect-tunnel"},
	Reduce:    Policy.reduceTunnelReconnect,
	Authorize: authorizeCluster,
	AdmitReport: func(p Policy, s state.State, cmd state.Command) error {
		_, err := p.tunnelReport(s, cmd)
		return err
	},
	Events: tunnelReconnectEvents,
}

func tunnelReconnectEvents(p Policy, before, after state.State, emit eventEmitter) error {
	old, err := p.TunnelReconnections(before)
	if err != nil {
		return err
	}
	next, err := p.TunnelReconnections(after)
	if err != nil {
		return err
	}
	for _, row := range next.Records {
		previous, _ := old.Record(row.Operation)
		if row.Result == nil || previous.Result != nil {
			continue
		}
		kind := "tunnel-reconnected"
		if row.Result.State == "failed" {
			kind = "tunnel-down"
		}
		d := eventlog.Detail{Operation: row.Operation, State: row.Result.State, Code: row.Result.Code}
		eventReason(&d, row.Origin)
		emit(kind, "node", eventlog.Target{Node: row.Plan.Node, PairID: row.Plan.PairID}, d)
	}
	return nil
}
