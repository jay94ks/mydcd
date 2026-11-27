// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/maintenance"
	"strings"
)

type CompactQuery struct {
	Selection *CompactSelection `json:",omitempty"`
	Operation string
	After     string
}

func (q CompactQuery) Valid(plan bool) bool {
	if len(q.After) > 128 {
		return false
	}
	if plan {
		return q.Selection != nil && q.Selection.Valid() && q.Operation == ""
	}
	return q.Selection == nil && lifecycle.ValidID(q.Operation)
}

type CompactSummary struct {
	Operation, User                               string
	At                                            uint64
	AcceptedIndex                                 uint64
	Options                                       maintenance.CompactOptions
	Sequential, Complete                          bool
	Total, Queued, Running, Done, Failed, Skipped int
}
type CompactPlanPage struct {
	Schema    uint8
	Cluster   [32]byte
	Selection CompactSelection
	Target    [32]byte
	Total     int
	Nodes     []maintenance.CompactNode
	Next      string
}
type CompactStatusPage struct {
	Schema       uint8
	Cluster      [32]byte
	RootRevision uint64
	Summary      CompactSummary
	Target       [32]byte
	Reason       *OperationReason `json:",omitempty"`
	Nodes        []maintenance.CompactNode
	Next         string
}

func (r CompactRecord) Summary() CompactSummary {
	s := CompactSummary{Operation: r.Job.Operation, User: r.Origin.Session.User, At: r.At, AcceptedIndex: r.AcceptedIndex, Options: r.Job.Options, Sequential: r.Job.Sequential, Complete: r.Job.Terminal(), Total: len(r.Job.Nodes)}
	for _, n := range r.Job.Nodes {
		switch n.State {
		case "queued":
			s.Queued++
		case "running":
			s.Running++
		case "done":
			s.Done++
		case "failed":
			s.Failed++
		case "skipped":
			s.Skipped++
		}
	}
	return s
}
func compactCursor(basis [32]byte, offset int) string {
	raw := append([]byte{1}, basis[:]...)
	return base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint32(raw, uint32(offset)))
}
func compactOffset(cursor string, basis [32]byte, total int) (int, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(raw) != 37 || raw[0] != 1 || base64.RawURLEncoding.EncodeToString(raw) != cursor || string(raw[1:33]) != string(basis[:]) {
		return 0, access.ErrConflict
	}
	offset := int(binary.BigEndian.Uint32(raw[33:]))
	if offset <= 0 || offset >= total {
		return 0, access.ErrConflict
	}
	return offset, nil
}
func (p Policy) CompactPlanPage(s state.State, session access.Session, at int64, q CompactQuery) (CompactPlanPage, error) {
	var out CompactPlanPage
	if !q.Valid(true) {
		return out, access.ErrInvalid
	}
	plan, err := p.PlanCompact(s, session, at, *q.Selection)
	if err != nil {
		return out, err
	}
	offset, err := compactOffset(q.After, plan.Target, len(plan.Nodes))
	if err != nil {
		return out, err
	}
	end := min(offset+64, len(plan.Nodes))
	out = CompactPlanPage{Schema: 1, Cluster: p.Cluster, Selection: plan.Selection, Target: plan.Target, Total: len(plan.Nodes), Nodes: plan.Nodes[offset:end]}
	if end < len(plan.Nodes) {
		out.Next = compactCursor(plan.Target, end)
	}
	return out, nil
}
func (p Policy) CompactStatusPage(s state.State, session access.Session, at int64, q CompactQuery) (CompactStatusPage, error) {
	var out CompactStatusPage
	if !q.Valid(false) {
		return out, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	users, err := p.Catalog(s)
	if err != nil || users.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil {
		return out, access.ErrDenied
	}
	c, err := p.Compactions(s)
	if err != nil {
		return out, err
	}
	record, ok := c.Record(q.Operation)
	if !ok {
		return out, access.ErrConflict
	}
	raw, _ := json.Marshal(struct {
		Root      uint64
		Operation string
		Cluster   [32]byte
	}{c.Revision, q.Operation, p.Cluster})
	basis := sha256.Sum256(append([]byte("sfc-compact-status-1\x00"), raw...))
	offset, err := compactOffset(q.After, basis, len(record.Job.Nodes))
	if err != nil {
		return out, err
	}
	end := min(offset+4, len(record.Job.Nodes))
	out = CompactStatusPage{Schema: 1, Cluster: p.Cluster, RootRevision: c.Revision, Summary: record.Summary(), Target: record.Plan.Target, Reason: record.Origin.Reason, Nodes: record.Job.Nodes[offset:end]}
	if end < len(record.Job.Nodes) {
		out.Next = compactCursor(basis, end)
	}
	return out, nil
}
func (c Compactions) Latest() *CompactSummary {
	if len(c.Records) == 0 {
		return nil
	}
	s := c.Records[len(c.Records)-1].Summary()
	return &s
}
func validCompactCode(code string) bool {
	return len(code) > 0 && len(code) <= 64 && !strings.ContainsAny(code, "\x00\r\n")
}
