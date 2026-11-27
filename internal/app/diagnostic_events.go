// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
)

func (r *Runtime) readEvents(ctx context.Context, view cluster.View, session access.Session, q eventlog.Query) (eventlog.Page, error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed {
		return eventlog.Page{}, eventlog.ErrUnavailable
	}
	r.mu.RLock()
	events, collectErr := r.events, r.eventError
	r.mu.RUnlock()
	allowed, err := r.controlPolicy.EventAccess(view.State, session, time.Now().Unix(), q)
	if err != nil {
		return eventlog.Page{}, err
	}
	if events == nil || collectErr != nil {
		return eventlog.Page{}, eventlog.ErrUnavailable
	}
	if err = ctx.Err(); err != nil {
		return eventlog.Page{}, err
	}
	return events.Page(q, uint64(time.Now().UnixMilli()), allowed)
}
func (r *Runtime) eventReceipt(caller string, input []byte, v cluster.View) (json.RawMessage, error) {
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed {
		return nil, sfcp.ErrAdmission
	}
	key, err := identity.ParseKey(caller)
	if err != nil || r.events == nil {
		return nil, sfcp.ErrAdmission
	}
	q, err := schema.Decode[eventlog.ReceiptQuery](input)
	if err != nil || q.Key != key {
		return nil, sfcp.ErrAdmission
	}
	d, err := r.controlPolicy.Members(v.State)
	if err != nil || !d.MemberKey(key) {
		return nil, sfcp.ErrAdmission
	}
	receipt, err := r.events.Receipt(q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(receipt)
}
func (r *Runtime) storeEventBatch(ctx context.Context, caller sfcp.Identity, raw []byte) error {
	if r.events == nil || len(raw) > 32<<10 {
		return sfcp.ErrAdmission
	}
	b, err := schema.Decode[eventlog.Batch](raw)
	if err != nil || !b.Valid() || b.Key != [32]byte(caller) || b.Cluster != r.controlPolicy.Cluster {
		return sfcp.ErrAdmission
	}
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	d, err := r.controlPolicy.Members(v.State)
	if err != nil {
		return err
	}
	entry, ok := d.Entry(b.Node)
	key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
	if !ok || keyErr != nil || key != b.Key || !d.MemberKey(key) {
		return sfcp.ErrAdmission
	}
	if err := r.events.Receive(b, uint64(time.Now().UnixMilli())); err != nil {
		return err
	}
	// One notice per tenant/app the batch touches, so each reader's filter
	// sees the records it may read.
	seen := map[[2]string]bool{}
	for _, rec := range b.Records {
		k := [2]string{rec.Event.Target.Tenant, rec.Event.Target.App}
		if !seen[k] {
			seen[k] = true
			r.bus.Publish(eventbus.Event{Topic: eventbus.TopicReport, Kind: eventbus.KindDiagnostic, Node: b.Node, Tenant: k[0], App: k[1], Changed: true})
		}
	}
	return nil
}

type eventProjectionCursor struct {
	Schema                       uint8
	Position, SnapshotAt, LostAt uint64
}

const eventProjectionCursorKey = "diagnostic-source/committed-position"

func (r *Runtime) collectCommittedEvents() error {
	if r.events == nil {
		return eventlog.ErrUnavailable
	}
	position := eventProjectionCursor{Schema: 1}
	raw, err := r.reports.GetBounded(eventProjectionCursorKey, 1024)
	if err == nil {
		position, err = schema.Decode[eventProjectionCursor](raw)
		if err != nil || position.Schema != 1 {
			return eventlog.ErrUnavailable
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	window, gap, err := r.Engine().ProjectedEvents(position.Position)
	if err != nil {
		return err
	}
	now := uint64(time.Now().UnixMilli())
	if gap || window.SnapshotAt != position.SnapshotAt || window.LostAt != position.LostAt {
		tag := fmt.Sprintf("committed-gap/%d/%d/%d/%d", window.Floor, window.Next, window.SnapshotAt, window.LostAt)
		_, err = r.events.Append(tag, eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "COMMITTED_EVENT_HISTORY_GAP"}}, now)
		if err != nil {
			return err
		}
		if gap {
			position.Position = window.Floor - 1
		}
	}
	for _, row := range window.Rows {
		if row.Event.At <= now && now-row.Event.At > eventlog.RetentionMillis {
			// An offline consumer cannot present expired history as continuous.
			_, err = r.events.Append(fmt.Sprintf("expired-projection/%d", row.Sequence), eventlog.Event{Kind: "event-source-gap", Scope: "node", At: now, Target: eventlog.Target{Node: r.Engine().ObservedNodeID()}, Detail: eventlog.Detail{Code: "COMMITTED_EVENT_EXPIRED"}}, now)
		} else {
			_, err = r.events.Append("committed/"+row.Event.Authority, row.Event, now)
		}
		if err != nil {
			return err
		}
		position.Position = row.Sequence
	}
	position.SnapshotAt, position.LostAt = window.SnapshotAt, window.LostAt
	raw, err = json.Marshal(position)
	if err != nil {
		return err
	}
	return r.reports.Write(map[string][]byte{eventProjectionCursorKey: raw})
}

// replicateEventPeer sends peer this node's records it does not hold yet and
// returns the newest own sequence the peer now holds: the receipt it gave,
// advanced by every batch it accepted in this call (the last one included).
func (r *Runtime) replicateEventPeer(ctx context.Context, peer sfcp.Peer) (uint64, error) {
	q := r.events.Source()
	raw, _ := json.Marshal(q)
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "event-receipt", Input: raw})
	if err != nil {
		return 0, err
	}
	receipt, err := schema.Decode[eventlog.Receipt](reply.Data)
	if err != nil || receipt.Schema != 1 || receipt.Query != q {
		return 0, sfcp.ErrFrame
	}
	for range 4 {
		batch, err := r.events.Export(receipt.Last, uint64(time.Now().UnixMilli()))
		if err != nil {
			return 0, err
		}
		if len(batch.Records) == 0 && receipt.Last >= batch.Floor-1 {
			// Nothing left to send: anything between is no longer retained.
			return batch.Last, nil
		}
		raw, err = json.Marshal(batch)
		if err != nil {
			return 0, err
		}
		conn, err := r.Mesh.Dial(ctx, peer)
		if err != nil {
			return 0, err
		}
		if err = conn.Report(ctx, sfcp.KindEventBatch, raw); err != nil {
			return 0, err
		}
		if len(batch.Records) == 0 {
			return batch.Last, nil
		}
		receipt.Last = batch.Records[len(batch.Records)-1].Sequence
		if receipt.Last >= batch.Last {
			return receipt.Last, nil
		}
	}
	return receipt.Last, nil
}

// eventPeerRecheck bounds how long this node trusts a peer's last receipt
// while it writes nothing new; a peer that lost its copy is found within it.
const eventPeerRecheck = time.Minute

// eventPeerSynced is the newest own sequence a peer holds for a stream, as
// returned by replicateEventPeer.
type eventPeerSynced struct {
	Stream [16]byte
	Last   uint64
	At     time.Time
}

// eventPeerCurrent reports whether peer already holds every record this node
// wrote, so asking it again would only repeat the same receipt.
func eventPeerCurrent(synced eventPeerSynced, stream [16]byte, own uint64, now time.Time) bool {
	return !synced.At.IsZero() && synced.Stream == stream && synced.Last >= own && now.Sub(synced.At) < eventPeerRecheck
}
func (r *Runtime) managedEventLoop() {
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		err := errors.Join(r.collectCommittedEvents(), r.collectRaftEvents())
		r.mu.Lock()
		r.eventError = err
		r.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.ctx, 4*time.Second)
		view, viewErr := r.Engine().Read(ctx, false)
		if viewErr == nil && r.events != nil {
			members, memberErr := r.controlPolicy.Members(view.State)
			if memberErr == nil && len(members.Entries) > 0 {
				// Bound per-cycle work while making progress through large rosters.
				for range min(8, len(members.Entries)) {
					entry := members.Entries[r.eventPeerCursor%len(members.Entries)]
					r.eventPeerCursor++
					key, keyErr := identity.ParseKey(entry.CurrentPeer().Key)
					if keyErr != nil || key == r.Identity.Public || !members.MemberKey(key) {
						continue
					}
					peer, ok := r.Mesh.Peer(sfcp.Identity(key))
					if !ok {
						continue
					}
					// Only ask a peer when this node has written something it
					// has not confirmed yet (or the receipt is old).
					stream, own := r.events.Source().Stream, r.events.OwnLast()
					if eventPeerCurrent(r.eventPeers[key], stream, own, time.Now()) {
						continue
					}
					call, stop := context.WithTimeout(ctx, time.Second)
					last, err := r.replicateEventPeer(call, peer)
					stop()
					if err == nil {
						if r.eventPeers == nil {
							r.eventPeers = map[[32]byte]eventPeerSynced{}
						}
						r.eventPeers[key] = eventPeerSynced{Stream: stream, Last: last, At: time.Now()}
					} else {
						delete(r.eventPeers, key)
					}
					if ctx.Err() != nil {
						break
					}
				}
			}
		}
		cancel()
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
		}
	}
}
