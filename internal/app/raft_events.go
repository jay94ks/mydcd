// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

type raftEventCursor struct {
	Schema      uint8
	At, Dropped uint64
}

const raftEventCursorKey = "diagnostic-source/raft-position"

func (r *Runtime) collectRaftEvents() error {
	if r.events == nil {
		return nil
	}
	position := raftEventCursor{Schema: 1}
	raw, err := r.reports.GetBounded(raftEventCursorKey, 1024)
	if err == nil {
		position, err = schema.Decode[raftEventCursor](raw)
		if err != nil || position.Schema != 1 {
			return eventlog.ErrUnavailable
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	old := position
	rows, dropped := r.Engine().ElectionObservations()
	now := uint64(time.Now().UnixMilli())
	if dropped != position.Dropped {
		_, err = r.events.Append(fmt.Sprintf("raft-dropped/%d", dropped), eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "RAFT_OBSERVER_DROPPED"}}, now)
		if err != nil {
			return err
		}
		position.Dropped = dropped
	}
	for _, row := range rows {
		if row.ObservedAt < position.At {
			continue
		}
		if row.Role == "candidate" || row.Reason == "sdk-observation" && row.Role == "" && row.Leader == "" {
			at := row.ObservedAt
			if at < now && now-at > eventlog.RetentionMillis {
				continue
			}
			_, err = r.events.Append(fmt.Sprintf("raft-risk/%d/%d/%s", row.Term, at, row.Role), eventlog.Event{Kind: "quorum-degraded", Scope: "cluster", At: at, Target: eventlog.Target{Node: r.Engine().ObservedNodeID(), Term: row.Term}, Detail: eventlog.Detail{Code: "NO_STABLE_LEADER_OBSERVED", State: row.Role}}, now)
			if err != nil {
				return err
			}
		}
		position.At = max(position.At, row.ObservedAt)
	}
	if position == old {
		return nil
	}
	raw, err = json.Marshal(position)
	if err != nil {
		return err
	}
	return r.reports.Write(map[string][]byte{raftEventCursorKey: raw})
}
