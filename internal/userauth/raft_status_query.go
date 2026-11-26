// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/raft"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/observability"
)

type RaftNodeStatus struct {
	LastManualCompact                                             *RaftCompactNode `json:",omitempty"`
	Node, Role                                                    string
	Term                                                          uint64
	MatchIndex, AppliedIndex, SnapshotIndex, LogBytes, LogEntries *uint64 `json:",omitempty"`
	LastContact, ObservedAt                                       uint64
	Lag                                                           *uint64 `json:",omitempty"`
	Stale                                                         bool
}

type RaftStatus struct {
	LastManualCompact                                   *control.CompactSummary `json:",omitempty"`
	ObservationStorageError                             string                  `json:",omitempty"`
	NodesNext                                           string
	NodesRootRevision                                   uint64
	Leader, ObservedBy                                  string
	Term, CommitIndex, AppliedIndex, ConfigurationIndex uint64
	Voters, Quorum, RespondingVoters                    int
	ObservedAt, ContactMaxAge                           uint64
	Stale, LocalLastAppliedAuthorization                bool
	Local                                               observability.Consensus
	Nodes                                               []RaftNodeStatus
	Elections                                           []cluster.ElectionObservation
	ElectionEventsDropped                               uint64
	Ledger                                              control.Storage
	// Writes counts the Raft entries this server appended as leader in the
	// current term, by kind (R14). Empty on a follower. WritesSince is when
	// the counts started, Unix milliseconds.
	Writes      []cluster.WriteCount `json:",omitempty"`
	WritesSince uint64               `json:",omitempty"`
}

func (c Client) RaftStatus(ctx context.Context, peer mydcp.Peer, session access.Session) (Reply, error) {
	return c.query(ctx, peer, session, Request{Method: "raft-status"})
}

func (s Service) raftStatusReply(ctx context.Context, view cluster.View, session access.Session, after string) Reply {
	p, err := s.Policy.Current(view.State)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	catalog, err := p.Catalog(view.State)
	if err != nil || catalog.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), time.Now().Unix(), "", access.ManageCluster, "") != nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	directory, err := p.Members(view.State)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	local, err := s.Engine.ConsensusObservation(ctx)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	now := uint64(time.Now().UnixMilli())
	status := RaftStatus{Leader: local.Leader, ObservedBy: s.Engine.ObservedNodeID(), Term: local.Term, CommitIndex: local.CommitIndex, AppliedIndex: local.AppliedIndex, ObservedAt: now, ContactMaxAge: s.Engine.ContactObservationMaxAge(), Stale: true, LocalLastAppliedAuthorization: true, Local: local, Nodes: []RaftNodeStatus{}}
	if writes, since := s.Engine.WriteCounts(); len(writes) != 0 {
		status.Writes, status.WritesSince = writes, uint64(since.UnixMilli())
	}
	installed, known := s.Engine.PublishedConfiguration()
	servers := map[string]raft.Server{}
	if known {
		status.ConfigurationIndex = installed.Index
		for _, server := range installed.Configuration.Servers {
			servers[string(server.ID)] = server
			if server.Suffrage == raft.Voter {
				status.Voters++
			}
		}
	}
	status.Quorum = status.Voters/2 + 1
	progress := map[string]cluster.ReplicationObservation{}
	for _, fact := range s.Engine.ReplicationObservations() {
		if fact.Term == local.Term {
			progress[fact.Node] = fact
		}
	}
	reports := []observability.Report{}
	if s.NodeObservations != nil {
		reports, err = s.NodeObservations(ctx, view)
		if err != nil {
			return Reply{Schema: 1, Code: "unavailable"}
		}
	}
	remote := map[string]observability.Report{}
	for _, report := range reports {
		entry, known := directory.Entry(report.Node)
		key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
		if !known || keyErr != nil || key != report.Key {
			continue
		}
		if report.Consensus != nil && report.Cluster == p.Cluster && report.Valid() {
			if old, exists := remote[report.Node]; !exists || old.At < report.At {
				remote[report.Node] = report
			}
		}
	}
	// A follower has direct evidence of two voters only: itself and the leader
	// whose heartbeat it accepted within the same contact limit the leader uses
	// for its ACKs. It never counts other followers from older reports.
	leaderContact := uint64(0)
	if local.Role == "follower" && local.Leader != "" {
		if at := s.Engine.LeaderContact(); at != 0 && at <= now && now-at <= status.ContactMaxAge {
			leaderContact = at
		}
	}
	for _, entry := range directory.Entries {
		row := RaftNodeStatus{Node: entry.Peer.ID, Role: "pending", Stale: true}
		server, installed := servers[row.Node]
		if installed {
			if server.Suffrage == raft.Voter {
				row.Role = "follower"
			} else {
				row.Role = "non-voter"
			}
		}
		if report, found := remote[row.Node]; found {
			fact := report.Consensus
			row.Term, row.ObservedAt = fact.Term, report.At
			row.Stale = !observability.Fresh(report.At, now) || fact.Term != local.Term
			applied := fact.AppliedIndex
			row.AppliedIndex = &applied
			if fact.SnapshotKnown {
				snapshot := fact.SnapshotIndex
				row.SnapshotIndex = &snapshot
			}
			if fact.LogKnown {
				entries := fact.LogEntries
				row.LogEntries = &entries
			}
			if fact.LogBytesKnown {
				bytes := fact.LogBytes
				row.LogBytes = &bytes
			}
			if installed && server.Suffrage == raft.Voter && fact.Role == "candidate" {
				row.Role = "candidate"
			}
		}
		if row.Node == s.Engine.ObservedNodeID() {
			row.Term, row.ObservedAt, row.Stale = local.Term, now, false
			if installed {
				row.Role = local.Role
				if server.Suffrage != raft.Voter {
					row.Role = "non-voter"
				}
			}
			applied, snapshot, bytes, entries := local.AppliedIndex, local.SnapshotIndex, local.LogBytes, local.LogEntries
			row.AppliedIndex = &applied
			if local.SnapshotKnown {
				row.SnapshotIndex = &snapshot
			}
			if local.LogBytesKnown {
				row.LogBytes = &bytes
			}
			if local.LogKnown {
				row.LogEntries = &entries
			}
			if installed && server.Suffrage == raft.Voter && local.Role == "leader" {
				status.RespondingVoters++
			}
			if local.Role == "leader" {
				matched, lag := local.LastIndex, uint64(0)
				row.MatchIndex, row.Lag = &matched, &lag
				row.LastContact = now
			}
			if leaderContact != 0 {
				row.LastContact = leaderContact
				if installed && server.Suffrage == raft.Voter {
					status.RespondingVoters++
				}
			}
		} else if leaderContact != 0 && row.Node == local.Leader {
			row.LastContact = leaderContact
			if installed && server.Suffrage == raft.Voter {
				row.Role = "leader"
				status.RespondingVoters++
			}
		} else if local.Role == "leader" {
			if fact, found := progress[row.Node]; found {
				row.LastContact = fact.ContactAt
				fresh := fact.ContactAt <= now && now-fact.ContactAt <= status.ContactMaxAge
				if installed && server.Suffrage == raft.Voter && fresh {
					status.RespondingVoters++
				}
				if fact.MatchKnown {
					matched := fact.MatchIndex
					row.MatchIndex = &matched
					if matched <= local.LastIndex {
						lag := local.LastIndex - matched
						row.Lag = &lag
					}
				}
				row.Stale = row.Stale || !fresh
			}
		}
		status.Nodes = append(status.Nodes, row)
	}
	status.Stale = !known || local.Role != "leader" && leaderContact == 0 || status.RespondingVoters < status.Quorum || local.Term != s.Engine.CurrentObservedTerm()
	status.Elections, status.ElectionEventsDropped = s.Engine.ElectionObservations()
	status.ObservationStorageError = s.Engine.ObservationStorageError()
	status.Ledger, err = p.Storage(view.State)
	if err != nil {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	slices.SortFunc(status.Nodes, func(a, b RaftNodeStatus) int { return strings.Compare(a.Node, b.Node) })
	basisRaw, _ := json.Marshal(struct {
		Term, Configuration, Catalog, Members uint64
		User                                  string
		Scopes                                []access.Scope
	}{status.Term, status.ConfigurationIndex, view.State.Object(control.CatalogKey).Revision, view.State.Object(control.MembersKey).Revision, session.User, session.Scopes})
	basis := sha256.Sum256(append([]byte("mydc-raft-status-page-1\x00"), basisRaw...))
	offset := uint32(0)
	if after != "" {
		raw, err := base64.RawURLEncoding.DecodeString(after)
		if err != nil || len(raw) != 37 || raw[0] != 1 || base64.RawURLEncoding.EncodeToString(raw) != after {
			return Reply{Schema: 1, Code: "denied"}
		}
		if [32]byte(raw[1:33]) != basis {
			return Reply{Schema: 1, Code: "conflict"}
		}
		offset = binary.LittleEndian.Uint32(raw[33:])
	}
	if uint64(offset) > uint64(len(status.Nodes)) {
		return Reply{Schema: 1, Code: "denied"}
	}
	end := min(int(offset)+32, len(status.Nodes))
	if end < len(status.Nodes) {
		raw := append([]byte{1}, basis[:]...)
		status.NodesNext = base64.RawURLEncoding.EncodeToString(binary.LittleEndian.AppendUint32(raw, uint32(end)))
	}
	status.Nodes = status.Nodes[int(offset):end]
	if jobs, err := p.Compactions(view.State); err == nil {
		status.LastManualCompact = jobs.Latest()
		for i := range status.Nodes {
			status.Nodes[i].LastManualCompact = lastNodeCompaction(jobs, status.Nodes[i].Node)
		}
	} else {
		return Reply{Schema: 1, Code: "unavailable"}
	}
	status.NodesRootRevision = view.State.Object(control.MembersKey).Revision
	return Reply{Schema: 1, Code: "ok", RaftStatus: &status}
}

func (c Client) RaftStatusPage(ctx context.Context, peer mydcp.Peer, session access.Session, after string) (Reply, error) {
	return c.query(ctx, peer, session, Request{Method: "raft-status", After: after})
}
