// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/engine"
	bolt "go.etcd.io/bbolt"
)

const MaxLogBytes = containerops.MaxLogWindowBytes
const LogChunkBytes = 8 << 10
const MaxLogPageBytes = 24 << 10

type LogQuery struct {
	Job      string
	MaxBytes uint32
	Tail     bool `json:",omitempty"`
}

func (q LogQuery) Valid() bool {
	return lifecycle.ValidID(q.Job) && q.MaxBytes > 0 && q.MaxBytes <= MaxLogPageBytes
}

// Unclosed is a durable, unacknowledged stream close, not proof of liveness.
// Cursor offsets address append-only REDACTED bytes, never raw Secret prefixes.
type LogPage struct {
	Schema                              uint8
	Job                                 [32]byte
	Offset, Next, Total                 uint32
	Data                                []byte
	Available, Truncated, Gap, Unclosed bool
}

func (p LogPage) Valid(job [32]byte, offset, maxBytes uint32) bool {
	return p.Schema == 1 && job != ([32]byte{}) && p.Job == job && p.Offset == offset && maxBytes > 0 && maxBytes <= MaxLogPageBytes && p.Total <= MaxLogBytes && p.Offset <= p.Total && uint32(len(p.Data)) == min(maxBytes, p.Total-p.Offset) && p.Next == p.Offset+uint32(len(p.Data)) && p.Next <= p.Total && (!p.Truncated || p.Total == MaxLogBytes) && (p.Available || p.Total == 0 && len(p.Data) == 0 && !p.Truncated && !p.Gap && !p.Unclosed)
}

type nativeLogState struct {
	Schema                   uint8
	Job                      [32]byte
	Bytes                    uint32
	Sessions                 uint64
	Truncated, Gap, Unclosed bool
}

func logStateKey(spec JobSpec) []byte { return append([]byte("logs/"), nativeKey(spec)...) }
func logChunkKey(spec JobSpec, slot uint32) []byte {
	return []byte(fmt.Sprintf("log-data/%s/%08d", nativeKey(spec), slot))
}
func readLogState(b *bolt.Bucket, spec JobSpec) (nativeLogState, bool, error) {
	s := nativeLogState{Schema: 1, Job: spec.Digest()}
	raw := b.Get(logStateKey(spec))
	if raw == nil {
		return s, false, nil
	}
	if len(raw) > 4096 || json.Unmarshal(raw, &s) != nil || s.Schema != 1 || s.Job != spec.Digest() || s.Bytes > MaxLogBytes || s.Sessions == 0 || s.Truncated && s.Bytes != MaxLogBytes {
		return nativeLogState{}, false, ErrStorage
	}
	canonical, _ := json.Marshal(s)
	if !bytes.Equal(raw, canonical) {
		return nativeLogState{}, false, ErrStorage
	}
	return s, true, nil
}
func saveLogState(b *bolt.Bucket, spec JobSpec, s nativeLogState) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return ErrStorage
	}
	return b.Put(logStateKey(spec), raw)
}

type LogWriter struct {
	mu      sync.Mutex
	owner   *NativeJobs
	spec    JobSpec
	session uint64
	pending []byte
	closed  bool
	err     error
}

var _ io.WriteCloser = (*LogWriter)(nil)

// OpenLogWriter precedes Secret filtering/SDK attach. Only redacted bytes may
// be passed to Write. Reopening preserves original bytes and marks a gap; it
// cannot fabricate continuous logs from an unclosed or detached old stream.
func (n *NativeJobs) OpenLogWriter(ctx context.Context, spec JobSpec) (*LogWriter, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return nil, err
	}
	if _, err := n.current(ctx, &r, false); err != nil {
		return nil, err
	}
	job := spec.Digest()
	if r.Completion != nil || r.Cancel {
		return nil, ErrConflict
	}
	if n.logWriters[job] {
		return nil, ErrUsed
	}
	var session uint64
	err = n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		s, exists, err := readLogState(b, spec)
		if err != nil {
			return err
		}
		if s.Sessions == ^uint64(0) {
			return ErrStorage
		}
		s.Gap = s.Gap || exists
		s.Sessions++
		s.Unclosed = true
		session = s.Sessions
		return saveLogState(b, spec, s)
	})
	if err != nil {
		return nil, err
	}
	n.logWriters[job] = true
	n.readers[job]++
	return &LogWriter{owner: n, spec: spec.Own(), session: session, pending: make([]byte, 0, LogChunkBytes)}, nil
}

func (w *LogWriter) append(data []byte, closing bool) error {
	return w.owner.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		s, exists, err := readLogState(b, w.spec)
		if err != nil {
			return err
		}
		if !exists || !s.Unclosed || s.Sessions != w.session {
			return ErrConflict
		}
		if len(data) > MaxLogBytes-int(s.Bytes) {
			s.Truncated = true
		}
		data = data[:min(len(data), MaxLogBytes-int(s.Bytes))]
		for len(data) != 0 {
			slot, at := s.Bytes/LogChunkBytes, s.Bytes%LogChunkBytes
			key := logChunkKey(w.spec, slot)
			prior := b.Get(key)
			if len(prior) != int(at) {
				return ErrStorage
			}
			size := min(len(data), LogChunkBytes-int(at))
			chunk := append(bytes.Clone(prior), data[:size]...)
			if err := b.Put(key, chunk); err != nil {
				return err
			}
			s.Bytes += uint32(size)
			data = data[size:]
		}
		if closing {
			s.Unclosed = false
		}
		return saveLogState(b, w.spec, s)
	})
}
func (w *LogWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(data) != 0 {
		size := min(len(data), LogChunkBytes-len(w.pending))
		w.pending = append(w.pending, data[:size]...)
		written += size
		data = data[size:]
		if len(w.pending) == LogChunkBytes {
			w.err = w.append(w.pending, false)
			clear(w.pending)
			w.pending = w.pending[:0]
			if w.err != nil {
				return written, w.err
			}
		}
	}
	return written, nil
}

// Flush publishes a partial redacted chunk for live polling without ending
// its stream. The same tail chunk is appended transactionally on the next write.
func (w *LogWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return io.ErrClosedPipe
	}
	if w.err == nil && len(w.pending) != 0 {
		w.err = w.append(w.pending, false)
		clear(w.pending)
		w.pending = w.pending[:0]
	}
	return w.err
}
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.err
	}
	w.closed = true
	if w.err == nil {
		w.err = w.append(w.pending, true)
	}
	clear(w.pending)
	w.pending = nil
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	job := w.spec.Digest()
	delete(w.owner.logWriters, job)
	w.owner.readers[job]--
	if w.owner.readers[job] == 0 {
		delete(w.owner.readers, job)
	}
	return w.err
}

// ReadNativeLogs reuses the original DB without initializing an Engine client,
// native job, stream or empty replacement log. Authorization belongs to the
// shared user/owner boundary and is rechecked after this finite DB read.
func ReadNativeLogs(db Transactions, spec JobSpec, offset, maxBytes uint32) (LogPage, error) {
	return readNativeLogs(db, spec, offset, maxBytes, false)
}

// ReadNativeLogsTail selects the final page in the same snapshot that supplies
// Total and the bytes. Next is an ordinary append cursor, not another tail seek.
func ReadNativeLogsTail(db Transactions, spec JobSpec, maxBytes uint32) (LogPage, error) {
	return readNativeLogs(db, spec, 0, maxBytes, true)
}

func readNativeLogs(db Transactions, spec JobSpec, offset, maxBytes uint32, tail bool) (LogPage, error) {
	if db == nil || spec.Validate() != nil || maxBytes == 0 || maxBytes > MaxLogPageBytes || offset > MaxLogBytes {
		return LogPage{}, ErrInvalid
	}
	page := LogPage{Schema: 1, Job: spec.Digest(), Offset: offset, Next: offset}
	err := db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(nativeBucket) == nil {
			return ErrNativeMissing
		}
		if _, err := readNativeRecord(tx, spec, engine.Owner(spec.Cluster, spec.Scope.Root.Key)); err != nil {
			return err
		}
		b := tx.Bucket(nativeBucket)
		s, exists, err := readLogState(b, spec)
		if err != nil {
			return err
		}
		page.Total, page.Available, page.Truncated, page.Gap, page.Unclosed = s.Bytes, exists, s.Truncated, s.Gap, s.Unclosed
		if tail {
			offset = s.Bytes - min(s.Bytes, maxBytes)
			page.Offset, page.Next = offset, offset
		}
		if offset > s.Bytes {
			return ErrConflict
		}
		end := min(s.Bytes, offset+maxBytes)
		for at := offset; at < end; {
			slot, start := at/LogChunkBytes, at%LogChunkBytes
			chunk := b.Get(logChunkKey(spec, slot))
			expected := min(uint32(LogChunkBytes), s.Bytes-slot*LogChunkBytes)
			if len(chunk) != int(expected) {
				return ErrStorage
			}
			size := min(end-at, uint32(len(chunk))-start)
			page.Data = append(page.Data, chunk[start:start+size]...)
			at += size
		}
		page.Next = end
		return nil
	})
	if err != nil {
		return LogPage{}, err
	}
	return page, nil
}

// The Runtime first checks the committed job tombstone and original closure.
// Local deletion is one DB transaction; no SDK call, file removal or native
// journal replacement is used. A live writer/stream must have joined already.
func (n *NativeJobs) PruneLogs(spec JobSpec, closure JobClosure) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	r, err := n.load(spec)
	if err != nil {
		return err
	}
	if r.Completion == nil || n.readers[spec.Digest()] != 0 || n.logging[spec.Digest()] || n.logWriters[spec.Digest()] {
		return ErrUsed
	}
	if !closure.Valid(spec) || !bytes.Equal(JobClosureBytes(*r.Completion), JobClosureBytes(closure)) || !bytes.Equal(r.Completion.Signature, closure.Signature) {
		return ErrConflict
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		prefix := []byte(fmt.Sprintf("log-data/%s/", nativeKey(spec)))
		cursor := b.Cursor()
		for key, _ := cursor.Seek(prefix); bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		return b.Delete(logStateKey(spec))
	})
}

func (n *NativeJobs) MarkLogGap(spec JobSpec) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, err := n.load(spec); err != nil {
		return err
	}
	return n.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(nativeBucket)
		state, exists, err := readLogState(b, spec)
		if err != nil || !exists {
			return err
		}
		if state.Gap {
			return nil
		}
		state.Gap = true
		return saveLogState(b, spec, state)
	})
}
