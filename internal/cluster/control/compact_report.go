// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/maintenance"
	"math"
)

type CompactReport struct {
	Schema                            uint8
	Cluster, Reporter                 [32]byte
	Operation, Node, Action, Leader   string
	Expected, RootRevision, Epoch, At uint64
	Result                            *maintenance.CompactResult `json:",omitempty"`
	Code                              string                     `json:",omitempty"`
	Signature                         []byte
}

func CompactReportBytes(r CompactReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-raft-compact-report-1\x00"), raw...)
}
func (r CompactReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: CompactKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}
func (p Policy) ResolveCompactReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r CompactReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, ErrCatalog
	}
	cmd, err := r.Command()
	if err != nil {
		return cmd, err
	}
	_, err = p.compactReport(s, cmd)
	return cmd, err
}
func (p Policy) compactReport(s state.State, cmd state.Command) (CompactReport, error) {
	var r CompactReport
	if cmd.Kind != state.ModuleReport || cmd.Key != CompactKey || canonical([]byte(cmd.Value), &r) != nil || r.Schema != 1 || r.Cluster != p.Cluster || r.Epoch != s.ModuleEpoch() || r.At == 0 || r.At > math.MaxInt64 || r.Expected == 0 || !ed25519.Verify(r.Reporter[:], CompactReportBytes(r), r.Signature) {
		return r, ErrCatalog
	}
	want, err := r.Command()
	members, me := p.Members(s)
	if err != nil || want != cmd || me != nil || !members.MemberKey(r.Reporter) {
		return r, ErrCatalog
	}
	c, err := p.Compactions(s)
	if err != nil {
		return r, err
	}
	record, ok := c.Record(r.Operation)
	if !ok {
		return r, ErrCatalog
	}
	node, ok := record.Job.Node(r.Node)
	if !ok {
		return r, ErrCatalog
	}
	switch r.Action {
	case "begin":
		leader, exists := members.Entry(r.Leader)
		leaderKey, le := identity.ParseKey(leader.CurrentPeer().Key)
		if !exists || le != nil || !leader.Peer.Voter || !members.MemberKey(leaderKey) {
			return r, ErrCatalog
		}
		if node.Key != r.Reporter || r.Result != nil || r.Code != "" {
			return r, ErrCatalog
		}
	case "cancel":
		if node.Key != r.Reporter || r.Leader != "" || r.Code != "authority-revoked" || r.Result != nil {
			return r, ErrCatalog
		}
	case "finish":
		if node.Key != r.Reporter || r.Leader != "" || r.Result == nil && r.Code == "" || r.Result != nil && r.Result.Validate() != nil {
			return r, ErrCatalog
		}
	case "skip":
		leader, ok := members.Entry(r.Leader)
		key, err := identity.ParseKey(leader.CurrentPeer().Key)
		if !ok || err != nil || !leader.Peer.Voter || key != r.Reporter || r.Result != nil || r.Code != "unreachable" {
			return r, ErrCatalog
		}
	default:
		return r, ErrCatalog
	}
	return r, nil
}
func (p Policy) reduceCompactReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.compactReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	c, err := p.Compactions(s)
	if err != nil {
		return nil, state.Invalid
	}
	for i, record := range c.Records {
		if record.Job.Operation != r.Operation {
			continue
		}
		switch r.Action {
		case "begin":
			users, err := p.Catalog(s)
			if err != nil || users.OperationAllowed(record.Origin.Session, "raft-compact") != nil || users.AuthorizeAccepted(record.Origin.Session, p.Cluster, record.Origin.At, "", access.ManageCluster, "") != nil {
				return nil, state.Forbidden
			}
			record.Job, err = record.Job.Begin(r.Node, r.Leader, r.Expected)
		case "finish":
			record.Job, err = record.Job.Finish(r.Node, r.Expected, r.Result, r.Code)
		case "cancel":
			record.Job, err = record.Job.CancelQueued(r.Node, r.Expected)
		case "skip":
			record.Job, err = record.Job.Skip(r.Node, r.Expected)
		}
		if err != nil {
			return nil, state.ConditionFailed
		}
		record.At = max(record.At, r.At)
		c.Records[i] = record
		return p.compactCheckpoint(s, c)
	}
	return nil, state.ConditionFailed
}
