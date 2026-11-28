// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/eventbus"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// A change watch (purpose ChangeWatch) tells one user session which records
// committed changes touched, as they are applied on this node. It carries
// references only: the reader reads a record through its usual query, which
// keeps the read's own authorization. See devel/design/web-live-updates.md.
//
// Revisions are Raft indexes of this node's applied state. A watcher resumes
// from the last index it saw; when that is older than what this node still
// remembers, it is told to read again (Resync) and continues from now.

// ChangeWatchRequest starts a watch after From (0: from now). Topics adds
// event topics to the committed changes every watch carries:
// eventbus.TopicReport (a node report was accepted), "alarm/<name>" for one
// alarm, or "alarm/" for every alarm.
type ChangeWatchRequest struct {
	Schema uint8
	From   uint64
	Nonce  [32]byte
	Topics []string `json:",omitempty"`
}

func (q ChangeWatchRequest) valid() bool { return q.Schema == 1 && q.Nonce != ([32]byte{}) }

// ChangeWatchReply is one frame of a watch. Code "ok" frames carry Index:
// every change up to and including it was delivered. A frame without Refs
// only advances Index (or keeps the stream alive). Any other Code ends the
// watch: "denied" (session no longer valid), "unavailable".
type ChangeWatchReply struct {
	Schema uint8
	Code   string
	Index  uint64
	// Resync: changes between the requested From and Index are no longer
	// known here. Read again, then use the refs that follow.
	Resync bool               `json:",omitempty"`
	Refs   []control.WatchRef `json:",omitempty"`
	// Events are notices of the requested topics, in publish order. They
	// are not numbered and are not resumed: EventsLost means some were
	// dropped (a slow watcher, or a new watch), so the reader reads what it
	// shows from those topics again.
	Events     []ChangeEvent `json:",omitempty"`
	EventsLost bool          `json:",omitempty"`
}

// ChangeEvent names an item a topic event is about, never its value.
// Tenant empty: a cluster item (ManageCluster to learn of it).
type ChangeEvent struct {
	Topic  string
	Kind   string
	Node   string `json:",omitempty"`
	Source string `json:",omitempty"`
	Tenant string `json:",omitempty"`
	App    string `json:",omitempty"`
	Note   string `json:",omitempty"` // an alarm's short text
	// Container and Reasons name an engine notice (eventbus.TopicEngine).
	Container string   `json:",omitempty"`
	Reasons   []string `json:",omitempty"`
}

const (
	changeFeedBatches   = 4096
	changeWatchKeepWait = 20 * time.Second
	changeWatchMaxRefs  = 512
)

type changeBatch struct {
	index uint64
	refs  []control.WatchRef
}

// ChangeFeed follows the local engine's applied state and remembers the
// references of the last changeFeedBatches applies. One per node.
type ChangeFeed struct {
	Engine *cluster.Engine
	Policy control.Policy

	mu      sync.Mutex
	batches []changeBatch // oldest first
	floor   uint64        // index the feed started from; nothing older is known
	head    uint64
	wake    chan struct{}
}

func (f *ChangeFeed) notify() <-chan struct{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.wake == nil {
		f.wake = make(chan struct{})
	}
	return f.wake
}

func (f *ChangeFeed) append(index uint64, refs []control.WatchRef) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if index <= f.head {
		return
	}
	if f.head == 0 {
		f.floor = index
	} else if len(refs) != 0 {
		f.batches = append(f.batches, changeBatch{index, refs})
		if over := len(f.batches) - changeFeedBatches; over > 0 {
			f.floor = f.batches[over-1].index
			f.batches = append([]changeBatch(nil), f.batches[over:]...)
		}
	}
	f.head = index
	if f.wake != nil {
		close(f.wake)
	}
	f.wake = make(chan struct{})
}

// since returns the refs applied after from, the index they reach, and
// whether from is still known. from 0 means "from now".
func (f *ChangeFeed) since(from uint64) (refs []control.WatchRef, index uint64, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.head == 0 {
		return nil, 0, from == 0
	}
	if from == 0 {
		return nil, f.head, true
	}
	if from < f.floor || from > f.head {
		return nil, f.head, false
	}
	for _, b := range f.batches {
		if b.index > from {
			refs = append(refs, b.refs...)
		}
	}
	return refs, f.head, true
}

// Run follows the engine until ctx ends. Views may skip applies; a skipped
// apply's records are still found, because books are compared to the last
// view seen.
func (f *ChangeFeed) Run(ctx context.Context) {
	records := map[string]control.WatchRecords{}
	roots := map[string]uint64{}
	first := true
	for {
		changed := f.Engine.Changes()
		view, err := f.Engine.Read(ctx, false)
		if err == nil {
			policy, perr := f.Policy.Current(view.State)
			if perr == nil {
				var refs []control.WatchRef
				for _, book := range control.WatchBooks {
					root := control.WatchBookRevision(view.State, book)
					if !first && root == roots[book] {
						continue
					}
					now, err := policy.WatchRecords(view.State, book)
					if err != nil {
						continue
					}
					if !first {
						refs = append(refs, control.WatchDiff(records[book], now)...)
					}
					records[book], roots[book] = now, root
				}
				first = false
				f.append(view.RaftIndex, refs)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

// changeWatchAllowed is whether session may learn that ref changed: the
// same gate as the query that reads that record.
func changeWatchAllowed(c access.Catalog, session access.Session, cluster [32]byte, issuer access.Issuer, now int64, ref control.WatchRef) bool {
	switch ref.Kind {
	case "app", "volume", "network", "ingress", "dns":
		if ref.Tenant == "" {
			return c.AuthorizeSession(session, cluster, issuer, now, "", access.ManageCluster, "") == nil
		}
		return c.AuthorizeSession(session, cluster, issuer, now, ref.Tenant, access.Read, "") == nil
	case "tenant":
		return c.AuthorizeSession(session, cluster, issuer, now, ref.Tenant, access.Read, "") == nil || c.AuthorizeSession(session, cluster, issuer, now, "", access.ManageCluster, "") == nil
	case "registry", "registry-maintenance":
		// The registry list also shows registries to their tenant's
		// ManageRegistry holders.
		return ref.Tenant != "" && (c.AuthorizeSession(session, cluster, issuer, now, ref.Tenant, access.Read, "") == nil || c.AuthorizeSession(session, cluster, issuer, now, ref.Tenant, access.ManageRegistry, "") == nil)
	case "node", "certificate", "domain", "acme-responder":
		return c.AuthorizeSession(session, cluster, issuer, now, "", access.ManageCluster, "") == nil
	}
	return false
}

// changeEventAllowed is whether session may learn of e: the gate of the
// read that shows that item.
// An alarm also needs its sender to have chosen watchers (Scope.Web), and
// one addressed to a user reaches only that user.
func changeEventAllowed(c access.Catalog, session access.Session, cluster [32]byte, issuer access.Issuer, now int64, e ChangeEvent, scope eventbus.Scope) bool {
	if eventbus.IsAlarm(e.Topic) && (!scope.Web || scope.User != "" && scope.User != session.User) {
		return false
	}
	if e.Tenant == "" {
		return c.AuthorizeSession(session, cluster, issuer, now, "", access.ManageCluster, "") == nil
	}
	return c.AuthorizeSession(session, cluster, issuer, now, e.Tenant, access.Read, "") == nil
}

// watchTopics subscribes to the requested topics this node publishes and
// hands their batches to the watch loop. While the loop is busy the
// subscription keeps collecting, and a batch it can no longer hold arrives
// as a loss. Unknown topics are ignored.
func (s Service) watchTopics(ctx context.Context, topics []string) <-chan topicBatch {
	want := map[string]bool{}
	allAlarms := false
	for _, t := range topics {
		switch {
		case t == eventbus.TopicReport, t == eventbus.TopicEngine, eventbus.IsAlarm(t):
			want[t] = true
		case t == eventbus.TopicAlarmPrefix:
			allAlarms = true
		}
	}
	if len(want) == 0 && !allAlarms || s.Events == nil {
		return nil
	}
	out := make(chan topicBatch)
	release := func() {}
	if want[eventbus.TopicReport] && s.WantObservations != nil {
		release = s.WantObservations()
	}
	sub := s.Events.Subscribe(changeWatchMaxRefs, func(e eventbus.Event) bool {
		return want[e.Topic] || allAlarms && eventbus.IsAlarm(e.Topic)
	})
	go func() {
		defer release()
		defer sub.Close()
		for {
			batch, lost, err := sub.Next(ctx)
			if err != nil {
				return
			}
			b := topicBatch{lost: lost}
			// One notice per item: a repeat only adds its reasons.
			type item struct{ topic, kind, node, source, tenant, app, note, container string }
			seen := map[item]int{}
			for _, e := range batch {
				k := item{e.Topic, e.Kind, e.Node, e.Source, e.Tenant, e.App, e.Note, e.Container}
				if at, ok := seen[k]; ok {
					for _, r := range e.Reasons {
						if !slices.Contains(b.events[at].Reasons, r) {
							b.events[at].Reasons = append(b.events[at].Reasons, r)
						}
					}
					continue
				}
				seen[k] = len(b.events)
				b.events = append(b.events, ChangeEvent{Topic: e.Topic, Kind: e.Kind, Node: e.Node, Source: e.Source, Tenant: e.Tenant, App: e.App, Note: e.Note, Container: e.Container, Reasons: slices.Clone(e.Reasons)})
				b.scopes = append(b.scopes, e.Scope)
			}
			select {
			case out <- b:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

type topicBatch struct {
	events []ChangeEvent
	scopes []eventbus.Scope // the sender's reach of each event
	lost   bool
}

func writeChangeWatchReply(stream sfcp.Stream, id uint64, header [32]byte, r ChangeWatchReply) error {
	r.Schema = 1
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := stream.SetDeadline(time.Now().Add(changeWatchKeepWait + 10*time.Second)); err != nil {
		return err
	}
	return sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.ChangeWatch, Kind: 2, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}})
}

// handleChangeWatch serves one watch for a session on this node's own
// connection (Unix or a direct QUIC caller). It is never relayed: every
// node applies the same changes.
func (s Service) handleChangeWatch(base context.Context, conn *sfcp.Session, stream sfcp.Stream, frame sfcp.Frame) error {
	if frame.Kind != 1 {
		return sfcp.ErrFrame
	}
	header := sha256.Sum256(frame.Fields[0].Value)
	if !bytes.Equal(header[:], frame.Fields[1].Value) {
		return sfcp.ErrFrame
	}
	envelope, err := schema.Decode[Envelope](frame.Fields[0].Value)
	if err != nil {
		return sfcp.ErrFrame
	}
	q, decodeErr := schema.Decode[ChangeWatchRequest](envelope.Body)
	if err := streamEOF(stream); err != nil {
		return err
	}
	reply := func(code string) error {
		return writeChangeWatchReply(stream, frame.Request, header, ChangeWatchReply{Code: code})
	}
	if decodeErr != nil || !q.valid() || envelope.Session == nil || envelope.Relay != nil || s.Changes == nil {
		return reply("denied")
	}
	binding, err := s.binding(conn, frame.Kind, envelope)
	if err != nil || binding.key != envelope.Session.Key {
		return reply("denied")
	}
	session := *envelope.Session
	ctx, cancel := context.WithDeadline(base, time.Unix(session.ExpiresAt, 0))
	defer cancel()
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	// Every frame re-reads the catalog: a revoked session, a removed
	// membership or a disabled account stops or narrows the watch at once.
	gate := func() (access.Catalog, control.Policy, bool) {
		view, err := s.Engine.Read(ctx, false)
		if err != nil || s.Enabled != nil && !s.Enabled(view.State) {
			return access.Catalog{}, control.Policy{}, false
		}
		policy, err := s.Policy.Current(view.State)
		if err != nil {
			return access.Catalog{}, policy, false
		}
		c, err := policy.Catalog(view.State)
		if err != nil || c.VerifySession(session, policy.Cluster, policy.Issuer(session.Issuer), time.Now().Unix()) != nil {
			return c, policy, false
		}
		return c, policy, true
	}
	c, policy, ok := gate()
	if !ok || access.VerifyRequest(session, binding.challenge, envelope.Body, envelope.Signature) != nil {
		return reply("denied")
	}
	s.Policy = policy
	if !s.nodeRequestAllowed(mustLocalState(ctx, s), c, Request{Method: "change-watch"}, envelope) {
		return reply("denied")
	}
	from := q.From
	resync := false
	events := s.watchTopics(ctx, q.Topics)
	for {
		wake := s.Changes.notify()
		refs, index, known := s.Changes.since(from)
		if index == 0 {
			// The feed has not seen its first view yet.
			select {
			case <-ctx.Done():
				return nil
			case <-wake:
				continue
			}
		}
		if !known {
			resync, refs = true, nil
		}
		c, policy, ok = gate()
		if !ok {
			return reply("denied")
		}
		now := time.Now().Unix()
		issuer := policy.Issuer(session.Issuer)
		visible := refs[:0:0]
		for _, ref := range refs {
			if changeWatchAllowed(c, session, policy.Cluster, issuer, now, ref) {
				visible = append(visible, ref)
			}
		}
		if len(visible) > changeWatchMaxRefs {
			// Too many to name: the reader reads again instead.
			visible, resync = nil, true
		}
		if resync || len(visible) != 0 || index != from {
			if err := writeChangeWatchReply(stream, frame.Request, header, ChangeWatchReply{Code: "ok", Index: index, Resync: resync, Refs: visible}); err != nil {
				return err
			}
		}
		from, resync = index, false
		timer := time.NewTimer(changeWatchKeepWait)
	wait:
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-wake:
			timer.Stop()
		case b := <-events:
			if c, policy, ok = gate(); !ok {
				timer.Stop()
				return reply("denied")
			}
			now, issuer := time.Now().Unix(), policy.Issuer(session.Issuer)
			shown := b.events[:0:0]
			for i, e := range b.events {
				if changeEventAllowed(c, session, policy.Cluster, issuer, now, e, b.scopes[i]) {
					shown = append(shown, e)
				}
			}
			if len(shown) != 0 || b.lost {
				if err := writeChangeWatchReply(stream, frame.Request, header, ChangeWatchReply{Code: "ok", Index: from, Events: shown, EventsLost: b.lost}); err != nil {
					timer.Stop()
					return err
				}
			}
			goto wait
		case <-timer.C:
			// Keep the stream and its deadline alive while nothing changes.
			if err := writeChangeWatchReply(stream, frame.Request, header, ChangeWatchReply{Code: "ok", Index: from}); err != nil {
				return err
			}
		}
	}
}

func mustLocalState(ctx context.Context, s Service) state.State {
	view, err := s.Engine.Read(ctx, false)
	if err != nil {
		return state.State{}
	}
	return view.State
}

// WatchChanges watches the changes session may see, after from (0: from
// now), with the event topics asked for, calling each for every frame until ctx ends, the session expires or
// the node ends the watch. It returns the last index delivered. The watch
// owns one local connection for its whole life, so concurrent watches use
// their own Mesh, as container streams do.
func (c Client) WatchChanges(base context.Context, peer sfcp.Peer, session access.Session, from uint64, topics []string, each func(ChangeWatchReply) error) (uint64, error) {
	if c.Verify(session) != nil || each == nil || c.Mesh == nil {
		return from, sfcp.ErrAdmission
	}
	q := ChangeWatchRequest{Schema: 1, From: from, Topics: topics}
	if _, err := rand.Read(q.Nonce[:]); err != nil {
		return from, err
	}
	ctx, cancel := context.WithDeadline(base, time.Unix(session.ExpiresAt, 0))
	defer cancel()
	conn, err := c.Mesh.Dial(ctx, peer)
	if err != nil {
		return from, err
	}
	body, _ := json.Marshal(q)
	envelope := Envelope{Session: &session, Body: body, Signature: ed25519.Sign(c.Self.Private, access.RequestBytes(session, conn.PeerChallenge(), body))}
	raw, _ := json.Marshal(envelope)
	header := sha256.Sum256(raw)
	stream, err := conn.OpenChangeWatchStream(ctx)
	if err != nil {
		return from, err
	}
	defer stream.Close()
	defer stream.CancelRead(0)
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(1); stream.CancelWrite(1) })
	defer stop()
	id := c.Mesh.NextRequest()
	if err = sfcp.WriteFrame(stream, sfcp.Frame{Purpose: sfcp.ChangeWatch, Kind: 1, Request: id, Fields: []sfcp.Field{{Tag: 1, Required: true, Value: raw}, {Tag: 2, Required: true, Value: header[:]}}}); err != nil {
		return from, err
	}
	if err = stream.Close(); err != nil {
		return from, err
	}
	last := from
	for {
		if err := stream.SetDeadline(time.Now().Add(changeWatchKeepWait + 20*time.Second)); err != nil {
			return last, err
		}
		f, err := sfcp.ReadFrame(stream, 128<<10)
		if err != nil {
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
			return last, err
		}
		var r ChangeWatchReply
		if f.Purpose != sfcp.ChangeWatch || f.Kind != 2 || f.Request != id || conn.Admit(f, sfcp.ChangeWatch, false) != nil || !bytes.Equal(f.Fields[1].Value, header[:]) || lenient(f.Fields[0].Value, &r) != nil || r.Schema != 1 {
			return last, sfcp.ErrFrame
		}
		if r.Code != "ok" {
			return last, &Error{Code: r.Code, Phase: sfcp.Completed}
		}
		if r.Index < last && !r.Resync {
			return last, sfcp.ErrFrame
		}
		if err := each(r); err != nil {
			return last, err
		}
		last = r.Index
	}
}
