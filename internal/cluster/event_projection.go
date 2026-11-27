// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

// EventProjection is a pure diagnostic projection of an actual FSM result.
// No clock, network, OS effect or second management transition runs here.
type EventProjection func(state.State, state.State, state.Command, state.Result) ([]eventlog.Event, error)

const projectedEventsKey = "observations/committed-events"
const maxProjectedEvents = 512

type ProjectedEvent struct {
	Sequence, RaftIndex uint64
	Event               eventlog.Event
}
type ProjectedWindow struct {
	Schema                          uint8
	Floor, Next, SnapshotAt, LostAt uint64
	Rows                            []ProjectedEvent
}

func readProjected(db *storage.DB) (ProjectedWindow, error) {
	raw, err := db.GetBounded(projectedEventsKey, 8<<20)
	if errors.Is(err, storage.ErrMissing) {
		return ProjectedWindow{Schema: 1, Floor: 1}, nil
	}
	if err != nil {
		return ProjectedWindow{}, err
	}
	v, err := schema.Decode[ProjectedWindow](raw)
	if err != nil || v.Schema != 1 || v.Floor == 0 || v.Next < v.Floor-1 || v.Next-(v.Floor-1) != uint64(len(v.Rows)) || len(v.Rows) > maxProjectedEvents {
		return ProjectedWindow{}, eventlog.ErrUnavailable
	}
	for i, r := range v.Rows {
		if r.Sequence != v.Floor+uint64(i) || r.RaftIndex == 0 || !r.Event.Valid() || r.Event.Authority == "" {
			return ProjectedWindow{}, eventlog.ErrUnavailable
		}
	}
	return v, nil
}

// The outbox shares the FSM transaction, so a short CD transition cannot be
// overwritten before the observer sees it. It is local diagnostic history,
// not part of the replicated business state or a replacement consensus log.
func (f *fsm) projectWrites(writes map[string][]byte, index uint64) {
	if f.project == nil || len(f.pendingEvents) == 0 && f.pendingEventError == nil && f.projectionRestore == 0 {
		return
	}
	v, err := readProjected(f.db)
	if err != nil {
		// Preserve an unreadable outbox. Telemetry corruption must not change
		// an applied business result or disclose payload bytes in an error.
		writes["observations/committed-events-unavailable"] = []byte("1")
		return
	}
	if f.projectionRestore != 0 {
		v.SnapshotAt = f.projectionRestore
	}
	if f.pendingEventError != nil || len(f.pendingEvents) > 32 {
		v.LostAt = index
	} else {
		for i, event := range f.pendingEvents {
			digest := sha256.Sum256([]byte(fmt.Sprintf("sfc-committed-event-1/%s/%d/%d", f.cluster, index, i)))
			event.Authority = hex.EncodeToString(digest[:])
			if !event.Valid() || v.Next == ^uint64(0) {
				v.LostAt = index
				continue
			}
			v.Next++
			v.Rows = append(v.Rows, ProjectedEvent{Sequence: v.Next, RaftIndex: index, Event: event})
		}
	}
	if len(v.Rows) > maxProjectedEvents {
		v.Rows = slices.Clone(v.Rows[len(v.Rows)-maxProjectedEvents:])
	}
	v.Floor = v.Next - uint64(len(v.Rows)) + 1
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 8<<20 {
		writes["observations/committed-events-unavailable"] = []byte("1")
		return
	}
	writes[projectedEventsKey] = raw
}

// ProjectedEvents returns only validated allowlisted events, never command
// bodies. A consumer persists its source position only after its own append.
func (e *Engine) ProjectedEvents(after uint64) (ProjectedWindow, bool, error) {
	if _, err := e.db.GetBounded("observations/committed-events-unavailable", 8); err == nil {
		return ProjectedWindow{}, false, eventlog.ErrUnavailable
	} else if !errors.Is(err, storage.ErrMissing) {
		return ProjectedWindow{}, false, err
	}
	v, err := readProjected(e.db)
	if err != nil {
		return v, false, err
	}
	gap := after < v.Floor-1 || after > v.Next
	if gap {
		after = v.Floor - 1
	}
	rows := []ProjectedEvent{}
	for _, r := range v.Rows {
		if r.Sequence > after {
			rows = append(rows, r)
			if len(rows) == 64 {
				break
			}
		}
	}
	v.Rows = rows
	return v, gap, nil
}
