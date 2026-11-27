// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

const metaKey = "diagnostic-events/meta"

type metadata struct {
	Schema                                 uint8
	Cluster, Key                           [32]byte
	Node                                   string
	Epoch                                  [16]byte
	Next, Floor, Own, OwnFloor, Generation uint64
	Incomplete                             bool
	Sources                                map[string]uint64
}
type entry struct {
	Serial uint64
	Record Record
}
type Store struct {
	mu     sync.Mutex
	db     *storage.DB
	self   *identity.Identity
	m      metadata
	failed error
	notify func(Record)
}

// Notify sets f to run after each record this node appends itself (Append,
// AppendRelated), under the store lock; f must not block or call the store.
// Records received from other nodes are announced by the receiver instead.
func (s *Store) Notify(f func(Record)) {
	s.mu.Lock()
	s.notify = f
	s.mu.Unlock()
}

func rowKey(n uint64) string      { return fmt.Sprintf("diagnostic-events/row/%020d", n) }
func seenKey(r Record) string     { return "diagnostic-events/seen/" + r.ID() }
func tagKey(tag string) string    { return "diagnostic-events/tag/" + tag }
func semanticKey(r Record) string { return "diagnostic-events/semantic/" + r.Event.Authority }

// Open borrows the owner's existing private DB/identity. It does not create a
// second daemon/database or retain another private key copy.
func Open(db *storage.DB, cluster [32]byte, node string, self *identity.Identity) (*Store, error) {
	if db == nil || self == nil || len(self.Private) != ed25519.PrivateKeySize || cluster == ([32]byte{}) || !lifecycle.ValidID(node) {
		return nil, ErrInvalid
	}
	s := &Store{db: db, self: self}
	raw, err := db.GetBounded(metaKey, 1<<20)
	if errors.Is(err, storage.ErrMissing) {
		s.m = metadata{Schema: 1, Cluster: cluster, Key: self.Public, Node: node, Floor: 1, OwnFloor: 1, Generation: 1, Sources: map[string]uint64{}}
		if _, err = rand.Read(s.m.Epoch[:]); err != nil {
			return nil, err
		}
		raw, err = json.Marshal(s.m)
		if err != nil {
			return nil, err
		}
		if err = db.Write(map[string][]byte{metaKey: raw}); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		var decodeErr error
		s.m, decodeErr = schema.Decode[metadata](raw)
		if decodeErr != nil {
			return nil, ErrInvalid
		}
	}
	m := s.m
	if m.Schema != 1 || m.Cluster != cluster || m.Key != self.Public || m.Node != node || m.Epoch == ([16]byte{}) || m.Generation == 0 || m.Floor == 0 || m.Next < m.Floor-1 || m.Next-m.Floor+1 > MaxRecords || m.OwnFloor == 0 || m.OwnFloor > m.Own+1 || m.Sources == nil || len(m.Sources) > 4096 {
		return nil, ErrInvalid
	}
	rows, err := db.ScanBounded("diagnostic-events/row/", MaxRecords, MaxRecords*(MaxRecordBytes+256))
	if err != nil || uint64(len(rows)) != m.Next-m.Floor+1 {
		return nil, ErrInvalid
	}
	for n := m.Floor; n <= m.Next; n++ {
		e, err := s.read(n, nil)
		if err != nil || e.Record.Cluster != cluster {
			return nil, ErrInvalid
		}
		if n == ^uint64(0) {
			return nil, ErrInvalid
		}
	}
	return s, nil
}
func (s *Store) read(n uint64, writes map[string][]byte) (entry, error) {
	raw, ok := writes[rowKey(n)]
	var err error
	if !ok {
		raw, err = s.db.GetBounded(rowKey(n), MaxRecordBytes+128)
	}
	e, decodeErr := schema.Decode[entry](raw)
	if err != nil || decodeErr != nil || e.Serial != n || !e.Record.Valid() {
		return e, ErrUnavailable
	}
	return e, nil
}

// indexed reads the in-flight transaction before the durable index. This is
// necessary when several source records in one batch describe one committed
// transition. The entire batch must use the same deduplication view.
func (s *Store) indexed(key string, writes map[string][]byte) (Record, bool, error) {
	raw, ok := writes[key]
	var err error
	if !ok {
		raw, err = s.db.GetBounded(key, 32)
	}
	if errors.Is(err, storage.ErrMissing) || ok && raw == nil {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	var serial uint64
	if json.Unmarshal(raw, &serial) != nil {
		return Record{}, false, ErrUnavailable
	}
	e, err := s.read(serial, writes)
	return e.Record, err == nil, err
}
func own(m metadata) metadata {
	out := m
	out.Sources = make(map[string]uint64, len(m.Sources))
	for k, v := range m.Sources {
		out.Sources[k] = v
	}
	return out
}

func (s *Store) commit(m metadata, writes map[string][]byte, now uint64) error {
	if s.failed != nil {
		return ErrUnavailable
	}
	if writes == nil {
		writes = make(map[string][]byte)
	}
	for m.Floor <= m.Next {
		e, err := s.read(m.Floor, writes)
		if err != nil {
			return err
		}
		if m.Next-m.Floor+1 <= MaxRecords && (e.Record.Event.At > now || now-e.Record.Event.At <= RetentionMillis) {
			break
		}
		writes[rowKey(m.Floor)] = nil
		writes[seenKey(e.Record)] = nil
		if e.Record.Event.Authority != "" {
			writes[semanticKey(e.Record)] = nil
		}
		if e.Record.SourceKey == m.Key {
			writes[tagKey(e.Record.Tag)] = nil
			if e.Record.Stream == m.Epoch {
				m.OwnFloor = e.Record.Sequence + 1
			}
		}
		m.Floor++
	}
	old := s.m
	if len(writes) == 0 && m.Schema == old.Schema && m.Cluster == old.Cluster && m.Key == old.Key && m.Node == old.Node && m.Epoch == old.Epoch && m.Next == old.Next && m.Floor == old.Floor && m.Own == old.Own && m.OwnFloor == old.OwnFloor && m.Generation == old.Generation && m.Incomplete == old.Incomplete && maps.Equal(m.Sources, old.Sources) {
		return nil
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > 1<<20 {
		return ErrUnavailable
	}
	writes[metaKey] = raw
	if err = s.db.Write(writes); err != nil {
		s.failed = err
		return err
	}
	s.m = m
	return nil
}
func appendEntry(m *metadata, writes map[string][]byte, r Record) error {
	if m.Next == ^uint64(0) {
		return ErrUnavailable
	}
	m.Next++
	b, err := json.Marshal(entry{Serial: m.Next, Record: r})
	if err != nil {
		return err
	}
	writes[rowKey(m.Next)] = b
	n, _ := json.Marshal(m.Next)
	writes[seenKey(r)] = n
	if r.Event.Authority != "" {
		writes[semanticKey(r)] = n
	}
	return nil
}

func (s *Store) Append(tag string, event Event, now uint64) (Record, error) {
	return s.AppendRelated(tag, event, now, nil)
}

// AppendRelated atomically saves source cursors/checker summaries together
// with their event. Related data stays in this same observer-owned DB and may
// not overwrite the journal's namespace. No management/FSM writes belong here.
func (s *Store) AppendRelated(tag string, event Event, now uint64, related map[string][]byte) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return Record{}, ErrUnavailable
	}
	for key := range related {
		if strings.HasPrefix(key, "diagnostic-events/") {
			return Record{}, ErrInvalid
		}
	}
	if !event.Valid() || tag == "" || len(tag) > 1024 || now == 0 || event.At > now+30000 || event.At < now && now-event.At > RetentionMillis {
		return Record{}, ErrInvalid
	}
	sum := sha256.Sum256([]byte(tag))
	digest := hex.EncodeToString(sum[:])
	if event.Authority != "" {
		if raw, err := s.db.GetBounded("diagnostic-events/semantic/"+event.Authority, 32); err == nil {
			var serial uint64
			if json.Unmarshal(raw, &serial) != nil {
				return Record{}, ErrUnavailable
			}
			e, err := s.read(serial, nil)
			if err != nil {
				return Record{}, err
			}
			a, _ := json.Marshal(e.Record.Event)
			b, _ := json.Marshal(event)
			if !bytes.Equal(a, b) {
				return Record{}, ErrInvalid
			}
			if len(related) != 0 {
				if err := s.commit(own(s.m), maps.Clone(related), now); err != nil {
					return Record{}, err
				}
			}
			return e.Record, nil
		} else if !errors.Is(err, storage.ErrMissing) {
			return Record{}, err
		}
	}
	if raw, err := s.db.GetBounded(tagKey(digest), 32); err == nil {
		var serial uint64
		if json.Unmarshal(raw, &serial) != nil {
			return Record{}, ErrUnavailable
		}
		e, err := s.read(serial, nil)
		if err == nil && len(related) != 0 {
			err = s.commit(own(s.m), maps.Clone(related), now)
		}
		return e.Record, err
	} else if !errors.Is(err, storage.ErrMissing) {
		return Record{}, err
	}
	m := own(s.m)
	if m.Own == ^uint64(0) {
		return Record{}, ErrUnavailable
	}
	m.Own++
	r := Record{Schema: 1, Cluster: m.Cluster, SourceKey: m.Key, SourceNode: m.Node, Stream: m.Epoch, Sequence: m.Own, Tag: digest, Event: event}
	r.Signature = ed25519.Sign(s.self.Private, SigningBytes(r))
	if !r.Valid() {
		return Record{}, ErrInvalid
	}
	writes := maps.Clone(related)
	if writes == nil {
		writes = map[string][]byte{}
	}
	if err := appendEntry(&m, writes, r); err != nil {
		return Record{}, err
	}
	n, _ := json.Marshal(m.Next)
	writes[tagKey(digest)] = n
	if event.Kind == "event-source-gap" {
		if m.Generation == ^uint64(0) {
			return Record{}, ErrUnavailable
		}
		m.Generation++
		m.Incomplete = true
	}
	if err := s.commit(m, writes, now); err != nil {
		return Record{}, err
	}
	if s.notify != nil {
		s.notify(r)
	}
	return r, nil
}

func (s *Store) UpdateRelated(related map[string][]byte, now uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return ErrUnavailable
	}
	for key := range related {
		if strings.HasPrefix(key, "diagnostic-events/") {
			return ErrInvalid
		}
	}
	return s.commit(own(s.m), maps.Clone(related), now)
}

// Export is source-only. Peer receipt queries let a reconnect resume from the
// receiver's durable prefix rather than resend an entire retained journal.
func (s *Store) Export(after, now uint64) (Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return Batch{}, ErrUnavailable
	}
	if after > s.m.Own {
		return Batch{}, ErrInvalid
	}
	m := own(s.m)
	if err := s.commit(m, map[string][]byte{}, now); err != nil {
		return Batch{}, err
	}
	m = s.m
	b := Batch{Kind: "node-events", Schema: 1, Cluster: m.Cluster, Key: m.Key, Node: m.Node, Stream: m.Epoch, Floor: m.OwnFloor, Last: m.Own, At: now}
	for n := m.Floor; n <= m.Next && len(b.Records) < MaxBatch; n++ {
		e, err := s.read(n, nil)
		if err != nil {
			return Batch{}, err
		}
		r := e.Record
		if r.SourceKey == m.Key && r.Stream == m.Epoch && r.Sequence > after {
			candidate := append(slices.Clone(b.Records), r)
			check := b
			check.Records = candidate
			check.Signature = make([]byte, 64)
			raw, _ := json.Marshal(check)
			if len(raw) > 32<<10 {
				break
			}
			b.Records = candidate
		}
	}
	b.Signature = ed25519.Sign(s.self.Private, BatchBytes(b))
	if !b.Valid() {
		return Batch{}, ErrInvalid
	}
	return b, nil
}

// OwnLast is the sequence of the newest record this node wrote itself.
func (s *Store) OwnLast() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m.Own
}
func (s *Store) Source() ReceiptQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return ReceiptQuery{Key: s.m.Key, Stream: s.m.Epoch}
}
func (s *Store) Receipt(q ReceiptQuery) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return Receipt{}, ErrUnavailable
	}
	if q.Key == ([32]byte{}) || q.Stream == ([16]byte{}) {
		return Receipt{}, ErrInvalid
	}
	key := hex.EncodeToString(q.Key[:]) + "/" + hex.EncodeToString(q.Stream[:])
	return Receipt{Schema: 1, Query: q, Last: s.m.Sources[key]}, nil
}
func (s *Store) Receive(batch Batch, now uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return ErrUnavailable
	}
	if !batch.Valid() || batch.Cluster != s.m.Cluster || batch.Key == s.m.Key || batch.At > now+30000 || batch.At < now && now-batch.At > 30000 {
		return ErrInvalid
	}
	origin := hex.EncodeToString(batch.Key[:]) + "/" + hex.EncodeToString(batch.Stream[:])
	m := own(s.m)
	last, known := m.Sources[origin]
	if !known && len(m.Sources) >= 4096 {
		return ErrUnavailable
	}
	if batch.Last < last {
		return nil
	}
	gap := batch.Floor > last+1
	if gap {
		last = batch.Floor - 1
	}
	writes := map[string][]byte{}
	for _, r := range batch.Records {
		if r.Sequence <= last {
			old, found, err := s.indexed(seenKey(r), writes)
			if err != nil {
				return err
			}
			if found && !EqualRecord(old, r) {
				return ErrInvalid
			}
			continue
		}
		if r.Sequence != last+1 {
			return ErrUnavailable
		}
		duplicate := false
		if r.Event.Authority != "" {
			old, found, err := s.indexed(semanticKey(r), writes)
			if err != nil {
				return err
			}
			if found {
				a, _ := json.Marshal(old.Event)
				b, _ := json.Marshal(r.Event)
				if !bytes.Equal(a, b) {
					return ErrInvalid
				}
				duplicate = true
			}
		}
		if !duplicate {
			if err := appendEntry(&m, writes, r); err != nil {
				return err
			}
		}
		last = r.Sequence
		gap = gap || r.Event.Kind == "event-source-gap"
	}
	if gap {
		if m.Generation == ^uint64(0) {
			return ErrUnavailable
		}
		m.Generation++
		m.Incomplete = true
	}
	m.Sources[origin] = last
	return s.commit(m, writes, now)
}

type cursor struct {
	Schema                   uint8
	Owner                    [32]byte
	Epoch                    [16]byte
	Generation, Position, At uint64
	Tenant, App, Node, Kind  string
}

func encodeCursor(c cursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Current permission matching happens BEFORE limiting/page emission. A cursor
// is only a read position; it never replaces the caller's current authority.
func (s *Store) Page(q Query, now uint64, allowed func(Record) bool) (Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return Page{}, ErrUnavailable
	}
	if !q.Valid() || now == 0 || allowed == nil {
		return Page{}, ErrInvalid
	}
	m := s.m
	c := cursor{Schema: 1, Owner: m.Key, Epoch: m.Epoch, Generation: m.Generation, Position: m.Floor - 1, At: now, Tenant: q.Tenant, App: q.App, Node: q.Node, Kind: q.Kind}
	if q.After != "" {
		raw, err := base64.RawURLEncoding.DecodeString(q.After)
		old, decodeErr := schema.Decode[cursor](raw)
		if err != nil || decodeErr != nil || encodeCursor(old) != q.After || old.Schema != 1 || old.Tenant != q.Tenant || old.App != q.App || old.Node != q.Node || old.Kind != q.Kind || old.At > now+30000 {
			return Page{}, ErrInvalid
		}
		if old.Owner != m.Key || old.Epoch != m.Epoch || old.Generation != m.Generation || old.Position > m.Next || old.Position < m.Floor-1 || old.At < now && now-old.At > RetentionMillis {
			return Page{}, ErrCursorExpired
		}
		c = old
	}
	limit := q.Limit
	if limit == 0 {
		limit = 50
	}
	page := Page{Schema: 1, Incomplete: m.Incomplete}
	size := 0
	for n := c.Position + 1; n <= m.Next; n++ {
		e, err := s.read(n, nil)
		if err != nil {
			return Page{}, err
		}
		r := e.Record
		// Source clocks may lead the receiver by the accepted 30-second skew.
		// Such records are already durable: skipping them while advancing the
		// cursor would lose them permanently for that consumer.
		if (r.Event.At > now || now-r.Event.At <= RetentionMillis) && q.matches(r) && allowed(r) {
			if len(page.Items) >= limit || size+len(SigningBytes(r))+1536 > 64<<10 {
				page.More = true
				break
			}
			c.Position, c.At = n, now
			item := Item{ID: r.PublicID(), Cursor: encodeCursor(c), SourceNode: r.SourceNode, Event: r.Event}
			raw, _ := json.Marshal(item)
			size += len(raw)
			page.Items = append(page.Items, item)
		} else {
			c.Position, c.At = n, now
		}
	}
	page.Cursor = encodeCursor(c)
	return page, nil
}

func (s *Store) History(tenant, app, task string, limit int, now uint64) ([]Item, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, true, ErrUnavailable
	}
	if tenant == "" || app == "" || task == "" || limit < 1 || limit > 100 || now == 0 {
		return nil, true, ErrInvalid
	}
	var rows []Item
	for n := s.m.Next; n >= s.m.Floor && n > 0; n-- {
		e, err := s.read(n, nil)
		if err != nil {
			return nil, true, err
		}
		r := e.Record
		if r.Event.At < now && now-r.Event.At > RetentionMillis {
			continue
		}
		if r.Event.Target.Tenant == tenant && r.Event.Target.App == app && r.Event.Target.Task == task && (r.Event.Kind == "task-exited" || r.Event.Kind == "task-restarted") {
			rows = append(rows, Item{ID: r.PublicID(), SourceNode: r.SourceNode, Event: r.Event})
			if len(rows) == limit {
				break
			}
		}
	}
	return slices.Clone(rows), s.m.Incomplete, nil
}

// EqualRecord is useful when checking a retained source identity in consumers;
// opaque source IDs are ordinary hashes, never a management hash chain.
func EqualRecord(a, b Record) bool {
	return bytes.Equal(SigningBytes(a), SigningBytes(b)) && bytes.Equal(a.Signature, b.Signature)
}
