// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// raftView: raft-status shaped for the screen (Unix seconds). suffrage is
// voter unless sfcd says non-voter or pending (not installed yet); role
// is sfcd's (leader/follower/candidate/non-voter/pending). Index and size
// fields are absent when the server did not report them.
type raftView struct {
	Leader             string           `json:"leader"`
	ObservedBy         string           `json:"observedBy"`
	Term               uint64           `json:"term"`
	CommitIndex        uint64           `json:"commitIndex"`
	AppliedIndex       uint64           `json:"appliedIndex"`
	ConfigurationIndex uint64           `json:"configurationIndex"`
	Voters             int              `json:"voters"`
	Quorum             int              `json:"quorum"`
	RespondingVoters   int              `json:"respondingVoters"`
	Stale              bool             `json:"stale"`
	Servers            []raftServerView `json:"servers"`
	LastSnapshotIndex  uint64           `json:"lastSnapshotIndex,omitempty"`
	LastSnapshotAt     int64            `json:"lastSnapshotAt,omitempty"`
	Elections          []raftElection   `json:"elections"`
	ElectionsDropped   uint64           `json:"electionsDropped,omitempty"`
	ObservedAt         int64            `json:"observedAt"`
}

type raftServerView struct {
	Node          string  `json:"node"`
	Suffrage      string  `json:"suffrage"`
	Role          string  `json:"role"`
	MatchIndex    *uint64 `json:"matchIndex,omitempty"`
	AppliedIndex  *uint64 `json:"appliedIndex,omitempty"`
	Lag           *uint64 `json:"lag,omitempty"`
	SnapshotIndex *uint64 `json:"snapshotIndex,omitempty"`
	LogEntries    *uint64 `json:"logEntries,omitempty"`
	LogBytes      *uint64 `json:"logBytes,omitempty"`
	LastContactAt int64   `json:"lastContactAt,omitempty"`
	Stale         bool    `json:"stale"`
}

type raftElection struct {
	Term   uint64 `json:"term"`
	Leader string `json:"leader"`
	At     int64  `json:"at"`
	Reason string `json:"reason"`
}

func newRaftView(st sfc.RaftStatus) raftView {
	v := raftView{Leader: st.Leader, ObservedBy: st.ObservedBy, Term: st.Term, CommitIndex: st.CommitIndex, AppliedIndex: st.AppliedIndex,
		ConfigurationIndex: st.ConfigurationIndex, Voters: st.Voters, Quorum: st.Quorum, RespondingVoters: st.RespondingVoters, Stale: st.Stale,
		Servers: []raftServerView{}, Elections: []raftElection{}, ElectionsDropped: st.ElectionEventsDropped, ObservedAt: int64(st.ObservedAt / 1000)}
	if st.Local.SnapshotKnown {
		v.LastSnapshotIndex, v.LastSnapshotAt = st.Local.SnapshotIndex, int64(st.Local.SnapshotAt/1000)
	}
	for _, n := range st.Nodes {
		suffrage := "voter"
		if n.Role == "non-voter" || n.Role == "pending" {
			suffrage = "non-voter"
		}
		v.Servers = append(v.Servers, raftServerView{Node: n.Node, Suffrage: suffrage, Role: n.Role, MatchIndex: n.MatchIndex, AppliedIndex: n.AppliedIndex,
			Lag: n.Lag, SnapshotIndex: n.SnapshotIndex, LogEntries: n.LogEntries, LogBytes: n.LogBytes, LastContactAt: int64(n.LastContact / 1000), Stale: n.Stale})
	}
	for _, e := range st.Elections {
		at := e.ElectedAt
		if at == 0 {
			at = e.ObservedAt
		}
		v.Elections = append(v.Elections, raftElection{Term: e.Term, Leader: e.Leader, At: int64(at / 1000), Reason: e.Reason})
	}
	return v
}

// GET /raft → raftView (raft-status).
func (s *Server) handleRaftStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (raftView, error) {
		st, err := c.RaftStatus(ctx)
		return newRaftView(st), err
	})
}
