// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

type TunnelReport struct {
	Schema                            uint8
	Cluster, Owner                    [32]byte
	Operation, Action                 string
	Expected, RootRevision, Epoch, At uint64
	Result                            *TunnelResult `json:",omitempty"`
	Signature                         []byte
}

func TunnelReportBytes(r TunnelReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-tunnel-report-1\x00"), raw...)
}
func (r TunnelReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Owner[:]), Epoch: r.Epoch, Key: TunnelReconnectKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) tunnelReport(s state.State, cmd state.Command) (TunnelReport, error) {
	var r TunnelReport
	if cmd.Kind != state.ModuleReport || cmd.Key != TunnelReconnectKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.Expected == 0 || r.At == 0 || r.At > math.MaxInt64 || !ed25519.Verify(r.Owner[:], TunnelReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	if err != nil || cmd != want {
		return r, ErrCatalog
	}
	d, err := p.Members(s)
	if err != nil || !d.MemberKey(r.Owner) {
		return r, access.ErrDenied
	}
	jobs, err := p.TunnelReconnections(s)
	if err != nil {
		return r, err
	}
	row, ok := jobs.Record(r.Operation)
	if !ok || row.Plan.Owner != r.Owner {
		return r, access.ErrDenied
	}
	switch r.Action {
	case "begin":
		if r.Result != nil {
			return r, ErrCatalog
		}
	case "finish", "cancel":
		if r.Result == nil || !r.Result.Valid(row.Plan) {
			return r, ErrCatalog
		}
		if r.Action == "cancel" && (r.Result.State != "failed" || r.Result.Code != "authority-revoked") {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) ResolveTunnelReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r TunnelReport
	if canonical(raw, &r) != nil || r.Owner != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.tunnelReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceTunnelReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.tunnelReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	jobs, err := p.TunnelReconnections(s)
	if err != nil {
		return nil, state.Invalid
	}
	for i, row := range jobs.Records {
		if row.Operation != r.Operation {
			continue
		}
		if row.Revision != r.Expected || row.Revision == ^uint64(0) {
			return nil, state.ConditionFailed
		}
		switch r.Action {
		case "begin":
			if row.State != "queued" {
				return nil, state.ConditionFailed
			}
			if p.currentTunnel(s, row.Plan) != nil || p.tunnelAuthorized(s, row.Origin.Session, row.Origin.At, true) != nil {
				return nil, state.Forbidden
			}
			row.State = "running"
		case "cancel":
			if row.State != "queued" {
				return nil, state.ConditionFailed
			}
			if p.tunnelAuthorized(s, row.Origin.Session, row.Origin.At, true) == nil && p.currentTunnel(s, row.Plan) == nil {
				return nil, state.ConditionFailed
			}
			row.State, row.Result = "failed", r.Result
		case "finish":
			if row.State != "running" {
				return nil, state.ConditionFailed
			}
			row.State, row.Result = "done", r.Result
			if r.Result.State == "failed" {
				row.State = "failed"
			}
		}
		row.Revision++
		row.At = max(row.At, r.At)
		jobs.Records[i] = row
		return p.tunnelCheckpoint(s, jobs)
	}
	return nil, state.ConditionFailed
}

type TunnelWorkRequest struct{ Operation string }
type TunnelWork struct {
	Schema                               uint8
	Cluster, Owner                       [32]byte
	Operation, State                     string
	Expected, RootRevision, Epoch, Index uint64
	Plan                                 TunnelPlan
	Allowed                              bool
}

func (p Policy) TunnelWork(s state.State, caller [32]byte, q TunnelWorkRequest) (TunnelWork, error) {
	var out TunnelWork
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	d, err := p.Members(s)
	if err != nil || !d.MemberKey(caller) {
		return out, access.ErrDenied
	}
	jobs, err := p.TunnelReconnections(s)
	if err != nil {
		return out, err
	}
	row, ok := jobs.Record(q.Operation)
	if !ok || row.Plan.Owner != caller {
		return out, access.ErrDenied
	}
	allowed := p.currentTunnel(s, row.Plan) == nil && p.tunnelAuthorized(s, row.Origin.Session, row.Origin.At, true) == nil
	return TunnelWork{Schema: 1, Cluster: p.Cluster, Owner: caller, Operation: q.Operation, State: row.State, Expected: row.Revision, RootRevision: s.Object(TunnelReconnectKey).Revision, Epoch: s.ModuleEpoch(), Index: s.Index(), Plan: row.Plan, Allowed: allowed}, nil
}

type TunnelStatus struct {
	Schema                     uint8
	Operation, User, State     string
	Plan                       TunnelPlan
	Revision, RootRevision, At uint64
	Reason                     *OperationReason `json:",omitempty"`
	Result                     *TunnelResult    `json:",omitempty"`
}

func (p Policy) TunnelStatus(s state.State, session access.Session, at int64, q TunnelQuery) (TunnelStatus, error) {
	var out TunnelStatus
	if !q.Valid(false) {
		return out, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return out, access.ErrDenied
	}
	jobs, err := p.TunnelReconnections(s)
	if err != nil {
		return out, err
	}
	row, ok := jobs.Record(q.Operation)
	if !ok {
		return out, access.ErrConflict
	}
	return TunnelStatus{Schema: 1, Operation: row.Operation, User: row.Origin.Session.User, State: row.State, Plan: row.Plan, Revision: row.Revision, RootRevision: s.Object(TunnelReconnectKey).Revision, At: row.At, Reason: row.Origin.Reason, Result: row.Result}, nil
}
