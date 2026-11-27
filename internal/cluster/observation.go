// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/storage"

	"github.com/hashicorp/raft"
)

type ReplicationObservation struct {
	MatchKnown                              bool
	Node                                    string
	Term, MatchIndex, ContactAt, ObservedAt uint64
	RTTMillis                               float64
	Reply, Accepted                         bool
}

type ElectionObservation struct {
	Term                             uint64
	Leader, Role                     string
	StartedAt, ElectedAt, ObservedAt uint64
	Reason                           string
}

type raftObservations struct {
	storageError string
	mu           sync.Mutex
	events       []ElectionObservation
	observer     *raft.Observer
}

// Only SDK notifications are recorded. The nonblocking observer cannot pause
// consensus. Missing events and the dropped count remain explicit diagnostics.
func (e *Engine) observeRaft() error {
	if raw, err := e.db.Get("observations/raft-events"); err == nil {
		var old []ElectionObservation
		if json.Unmarshal(raw, &old) != nil || len(old) > 32 {
			e.observations.storageError = "saved-history-invalid"
		} else {
			e.observations.events = old
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		e.observations.storageError = "history-read-failed"
		log.Printf("raft diagnostic history read failed: node=%s cause=%v", e.id, err)
	}
	ch := make(chan raft.Observation, 64)
	o := raft.NewObserver(ch, false, func(o *raft.Observation) bool {
		switch o.Data.(type) {
		case raft.RaftState, raft.LeaderObservation:
			return true
		}
		return false
	})
	e.observations.observer = o
	e.raft.RegisterObserver(o)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer e.raft.DeregisterObserver(o)
		for {
			select {
			case <-e.done:
				return
			case event := <-ch:
				now := uint64(time.Now().UnixMilli())
				row := ElectionObservation{Term: e.raft.CurrentTerm(), ObservedAt: now, Reason: "sdk-observation"}
				switch value := event.Data.(type) {
				case raft.RaftState:
					row.Role = strings.ToLower(value.String())
					if value == raft.Candidate {
						row.StartedAt = now
					}
				case raft.LeaderObservation:
					row.Leader = string(value.LeaderID)
					if row.Leader != "" {
						row.ElectedAt = now
					}
				}
				e.observations.mu.Lock()
				next := append(append([]ElectionObservation(nil), e.observations.events...), row)
				if len(next) > 32 {
					next = next[len(next)-32:]
				}
				raw, _ := json.Marshal(next)
				if err := e.db.Write(map[string][]byte{"observations/raft-events": raw}); err != nil {
					e.observations.storageError = "history-write-failed"
					log.Printf("raft diagnostic history write failed: node=%s cause=%v", e.id, err)
				}
				e.observations.events = next
				e.observations.mu.Unlock()
			}
		}
	}()
	return nil
}

func (e *Engine) ElectionObservations() ([]ElectionObservation, uint64) {
	e.observations.mu.Lock()
	defer e.observations.mu.Unlock()
	var dropped uint64
	if e.observations.observer != nil {
		dropped = e.observations.observer.GetNumDropped()
	}
	return append([]ElectionObservation(nil), e.observations.events...), dropped
}

// ConsensusObservation does not call Stats/GetConfiguration or perform a quorum
// barrier. Those paths may wait during the very outage this query diagnoses.
// AppliedIndex is the durable published FSM position, extended over the
// committed suffix that holds no state entry (barriers and no-ops), never SDK
// dispatch alone.
func (e *Engine) ConsensusObservation(ctx context.Context) (observability.Consensus, error) {
	if err := ctx.Err(); err != nil {
		return observability.Consensus{}, err
	}
	c := observability.Consensus{Role: strings.ToLower(e.raft.State().String()), Term: e.raft.CurrentTerm(), SnapshotIntervalMillis: uint64(e.snapshotInterval / time.Millisecond), TrailingLogs: e.raft.ReloadableConfig().TrailingLogs}
	_, leader := e.Leader()
	c.Leader = string(leader)
	if published := e.fsm.readView.Load(); published != nil {
		c.AppliedIndex = published.index
		if published.ready && published.err == nil {
			c.AppliedIndex = e.appliedThrough(published.index, e.raft.AppliedIndex())
		}
	}
	c.CommitIndex, c.LastIndex = e.raft.CommitIndex(), e.raft.LastIndex()
	if first, err := e.log.FirstIndex(); err == nil {
		if last, err := e.log.LastIndex(); err == nil {
			c.LogKnown = true
			c.LogFirstIndex, c.LogLastIndex = first, last
			if first != 0 && last >= first {
				c.LogEntries = last - first + 1
			}
		}
	}
	if f, err := os.Stat(filepath.Join(e.root, "control", "raft.db")); err == nil && f.Size() >= 0 {
		c.LogBytes = uint64(f.Size())
		c.LogBytesKnown = true
	}
	if snapshots, err := e.snapshots.List(); err == nil {
		c.SnapshotKnown = true
		if len(snapshots) > 0 {
			latest := snapshots[0]
			for _, s := range snapshots {
				if s.Index > latest.Index {
					latest = s
				}
			}
			c.SnapshotIndex = latest.Index
			if latest.Size >= 0 {
				c.SnapshotBytes = uint64(latest.Size)
			}
			if parts := strings.Split(latest.ID, "-"); len(parts) == 3 {
				c.SnapshotAt, _ = strconv.ParseUint(parts[2], 10, 64)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return observability.Consensus{}, err
	}
	// The durable FSM may be ahead of the SDK's live commit counter just
	// after reopening. Expose no consensus sample until those counters form
	// a coherent prefix; never synthesize a larger live commit observation.
	if c.AppliedIndex > c.CommitIndex || c.CommitIndex > c.LastIndex {
		return observability.Consensus{}, ErrRecovering
	}
	return c, nil
}

func (e *Engine) ReplicationObservations() []ReplicationObservation {
	e.transport.mu.Lock()
	defer e.transport.mu.Unlock()
	out := make([]ReplicationObservation, 0, len(e.transport.replication))
	for _, v := range e.transport.replication {
		out = append(out, v)
	}
	return out
}

func (t *raftTransport) observeAppend(id raft.ServerID, a *raft.AppendEntriesRequest, r *raft.AppendEntriesResponse, elapsed time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.replication == nil {
		t.replication = map[string]ReplicationObservation{}
	}
	node := string(id)
	v := t.replication[node]
	if v.Term != a.Term {
		v = ReplicationObservation{Node: node, Term: a.Term}
	}
	v.ObservedAt = uint64(time.Now().UnixMilli())
	v.RTTMillis = float64(elapsed) / float64(time.Millisecond)
	v.Reply = err == nil && r.Term == a.Term
	v.Accepted = v.Reply && r.Success
	if v.Reply {
		v.ContactAt = v.ObservedAt
	}
	if v.Accepted {
		matched := a.PrevLogEntry
		if len(a.Entries) > 0 {
			matched = a.Entries[len(a.Entries)-1].Index
		}
		// Response.LastLog is not an ACK of our accepted prefix.
		v.MatchIndex = max(v.MatchIndex, matched)
		v.MatchKnown = true
	}
	t.replication[node] = v
}

func (e *Engine) ContactObservationMaxAge() uint64 { return uint64(e.contactMaxAge / time.Millisecond) }

// PublishedConfiguration returns the already durable FSM configuration. Unlike
// SDK latest configuration, it cannot name an uncommitted membership update.
func (e *Engine) PublishedConfiguration() (InstalledConfiguration, bool) {
	published := e.fsm.readView.Load()
	if published == nil || !published.ready || !published.configurationTracked || published.configurationIndex == 0 || published.configuration == "" {
		return InstalledConfiguration{}, false
	}
	configuration := raft.DecodeConfiguration([]byte(published.configuration))
	return InstalledConfiguration{Configuration: configuration, Index: published.configurationIndex, AppliedIndex: published.index}, true
}

// LeaderContact is when this node last accepted contact from its current
// leader, in Unix milliseconds, or 0 when it has none.
func (e *Engine) LeaderContact() uint64 {
	at := e.raft.LastContact()
	if at.IsZero() {
		return 0
	}
	return uint64(at.UnixMilli())
}

func (e *Engine) CurrentObservedTerm() uint64 { return e.raft.CurrentTerm() }

func (e *Engine) ObservedNodeID() string { return e.id }

func (e *Engine) ObservationStorageError() string {
	e.observations.mu.Lock()
	defer e.observations.mu.Unlock()
	return e.observations.storageError
}

func (t *raftTransport) observeSnapshot(id raft.ServerID, a *raft.InstallSnapshotRequest, r *raft.InstallSnapshotResponse, elapsed time.Duration, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.replication == nil {
		t.replication = map[string]ReplicationObservation{}
	}
	node := string(id)
	v := t.replication[node]
	if v.Term != a.Term {
		v = ReplicationObservation{Node: node, Term: a.Term}
	}
	v.ObservedAt = uint64(time.Now().UnixMilli())
	v.RTTMillis = float64(elapsed) / float64(time.Millisecond)
	v.Reply = err == nil && r.Term == a.Term
	v.Accepted = v.Reply && r.Success
	if v.Reply {
		v.ContactAt = v.ObservedAt
	}
	if v.Accepted {
		v.MatchKnown = true
		v.MatchIndex = max(v.MatchIndex, a.LastLogIndex)
	}
	t.replication[node] = v
}

// maxAppliedScan bounds the log entries one observation inspects. The covered
// prefix is remembered, so a long idle suffix is still reached incrementally.
const maxAppliedScan = 4096

// appliedThrough extends the durable FSM position over later entries that the
// FSM never stores. Read barriers and leader no-ops are committed log entries
// but change no state, so without this the applied position looks frozen while
// commits continue. A command or configuration entry stops the walk until the
// FSM itself publishes it; a missing log entry stops it too.
func (e *Engine) appliedThrough(durable, dispatched uint64) uint64 {
	e.appliedMu.Lock()
	defer e.appliedMu.Unlock()
	if e.appliedDurable != durable || e.appliedCovered < durable {
		e.appliedDurable, e.appliedCovered = durable, durable
	}
	for scanned := 0; e.appliedCovered < dispatched && scanned < maxAppliedScan; scanned++ {
		var entry raft.Log
		if err := e.log.GetLog(e.appliedCovered+1, &entry); err != nil {
			// Compaction removes a prefix only after a snapshot holds it. A
			// snapshot whose FSM position is this durable one proves that no
			// state entry lies between them.
			if covered, ok := e.snapshotCovers(durable); ok && covered > e.appliedCovered {
				e.appliedCovered = min(covered, dispatched)
				continue
			}
			break
		}
		if entry.Type == raft.LogCommand || entry.Type == raft.LogConfiguration {
			break
		}
		e.appliedCovered++
	}
	return e.appliedCovered
}

// snapshotCovers returns the Raft index of the newest snapshot that was taken
// at exactly this durable FSM position.
func (e *Engine) snapshotCovers(durable uint64) (uint64, bool) {
	snapshots, err := e.snapshots.List()
	if err != nil || len(snapshots) == 0 {
		return 0, false
	}
	latest := snapshots[0]
	for _, s := range snapshots {
		if s.Index > latest.Index {
			latest = s
		}
	}
	_, source, err := e.snapshots.Open(latest.ID)
	if err != nil {
		return 0, false
	}
	defer source.Close()
	header := make([]byte, snapshotHeaderSize)
	if _, err = io.ReadFull(source, header); err != nil || string(header[:4]) != "MDS1" {
		return 0, false
	}
	return latest.Index, binary.LittleEndian.Uint64(header[40:48]) == durable
}
