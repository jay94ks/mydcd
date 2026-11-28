// SPDX-License-Identifier: Apache-2.0

// Package logstore is sfcd's central container log store. The engine keeps
// container output only until sfcd takes it (purpose 33 bulk, 34 ack); this
// store keeps it per container up to a byte cap, oldest first out, until a
// user deletes it. Records keep the engine's numbering (seq), so a dropped
// range shows as a gap. See seafield/docs/additions.md "로그 queue".
package logstore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Record is one stored line (or partial line).
type Record struct {
	Seq     uint64
	Time    time.Time
	Stderr  bool
	Partial bool
	Data    []byte
}

// Meta describes one container's log.
type Meta struct {
	Container string // engine container ID
	Name      string
	Key       string // the container's org.sfc.key (a task key for workloads)
	Tenant    string
	App       string // the app's internal scope (a standalone's too)
	Service   string
	Cap       int64 // bytes kept at most
}

// Info is a container log's current extent.
type Info struct {
	Meta
	First, Last uint64 // 0, 0 when empty
	Size        int64
	Dropped     uint64 // records dropped by the cap or the engine, ever
	// Gone is when sfcd saw the container no longer exists on the engine
	// (zero while it exists). Only logs of gone containers are pruned.
	Gone time.Time
}

const (
	headerSize = 22
	// DefaultCap is the per-container cap when Meta.Cap is 0.
	DefaultCap = 64 << 20
	MinCap     = 1 << 20
	segments   = 8 // a container's log is cut into about Cap/segments pieces
	maxLine    = 1 << 20
)

var (
	ErrNotFound = errors.New("logstore: no log for that container")
	validID     = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

// Store keeps the logs under one root directory.
type Store struct {
	root string

	mu   sync.Mutex
	logs map[string]*clog
}

type clog struct {
	mu      sync.Mutex
	dir     string
	meta    Meta
	segs    []seg // oldest first
	last    uint64
	dropped uint64
	cleared time.Time     // records at or before this were cleared by a user
	gone    time.Time     // the container was seen gone at this time
	notify  chan struct{} // closed and replaced on every append
	removed bool
}

type seg struct {
	first uint64
	last  uint64
	size  int64
}

// Root is the store's directory.
func (s *Store) Root() string { return s.root }

// Open opens (or creates) the store at root.
func Open(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Store{root: root, logs: map[string]*clog{}}, nil
}

func (s *Store) get(id string, create *Meta) (*clog, error) {
	if !validID.MatchString(id) {
		return nil, fmt.Errorf("logstore: bad container id %q", id)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l := s.logs[id]; l != nil {
		return l, nil
	}
	dir := filepath.Join(s.root, id)
	l := &clog{dir: dir, notify: make(chan struct{})}
	raw, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &l.meta); err != nil {
			return nil, err
		}
		if err := l.load(); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist) && create != nil:
		l.meta = *create
		l.meta.Container = id
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := l.saveMeta(); err != nil {
			return nil, err
		}
	case errors.Is(err, os.ErrNotExist):
		return nil, ErrNotFound
	default:
		return nil, err
	}
	if l.meta.Cap <= 0 {
		l.meta.Cap = DefaultCap
	}
	l.meta.Cap = max(l.meta.Cap, MinCap)
	s.logs[id] = l
	return l, nil
}

func (l *clog) saveMeta() error {
	b, _ := json.Marshal(struct {
		Meta
		Dropped uint64
		Cleared time.Time
		Gone    time.Time `json:",omitzero"`
	}{l.meta, l.dropped, l.cleared, l.gone})
	tmp := filepath.Join(l.dir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(l.dir, "meta.json"))
}

func segName(first uint64) string { return fmt.Sprintf("%020d.seg", first) }

func (l *clog) load() error {
	var extra struct {
		Dropped uint64
		Cleared time.Time
		Gone    time.Time
	}
	if raw, err := os.ReadFile(filepath.Join(l.dir, "meta.json")); err == nil {
		_ = json.Unmarshal(raw, &extra)
	}
	l.dropped, l.cleared, l.gone = extra.Dropped, extra.Cleared, extra.Gone
	names, err := filepath.Glob(filepath.Join(l.dir, "*.seg"))
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		first, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(n), ".seg"), 10, 64)
		if err != nil {
			continue
		}
		sg := seg{first: first}
		f, err := os.OpenFile(n, os.O_RDWR, 0)
		if err != nil {
			return err
		}
		good, last, err := scan(f, nil)
		if err == nil && good < sizeOf(f) {
			err = f.Truncate(good) // cut a torn tail
		}
		_ = f.Close()
		if err != nil {
			return err
		}
		if good == 0 {
			_ = os.Remove(n)
			continue
		}
		sg.size, sg.last = good, last
		if k := len(l.segs); k > 0 && sg.last <= l.segs[k-1].last {
			// A TrimBefore rewrite left beside its original by a crash: the
			// original holds the same records and more, and reads skip the
			// cleared ones, so the copy goes.
			_ = os.Remove(n)
			continue
		}
		l.segs = append(l.segs, sg)
		l.last = max(l.last, last)
	}
	return nil
}

func sizeOf(f *os.File) int64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	return st.Size()
}

// scan reads records from r, calling fn (when set) for each; it returns the
// byte length of whole records and the last seq.
func scan(r io.Reader, fn func(Record) bool) (int64, uint64, error) {
	var (
		h    [headerSize]byte
		off  int64
		last uint64
	)
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return off, last, nil
			}
			return off, last, err
		}
		n := binary.BigEndian.Uint32(h[18:22])
		if n > maxLine {
			return off, last, nil
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return off, last, nil
		}
		rec := Record{Seq: binary.BigEndian.Uint64(h[0:8]), Time: time.Unix(0, int64(binary.BigEndian.Uint64(h[8:16]))).UTC(), Stderr: h[16] == 2, Partial: h[17] == 1, Data: data}
		off += int64(headerSize) + int64(n)
		last = rec.Seq
		if fn != nil && !fn(rec) {
			return off, last, nil
		}
	}
}

// Encode appends r in the engine's segment record encoding.
func Encode(b []byte, r Record) []byte {
	var h [headerSize]byte
	binary.BigEndian.PutUint64(h[0:8], r.Seq)
	binary.BigEndian.PutUint64(h[8:16], uint64(r.Time.UnixNano()))
	h[16] = 1
	if r.Stderr {
		h[16] = 2
	}
	if r.Partial {
		h[17] = 1
	}
	binary.BigEndian.PutUint32(h[18:22], uint32(len(r.Data)))
	return append(append(b, h[:]...), r.Data...)
}

// Decode splits a bulk body (the engine's record encoding) into records.
func Decode(body []byte) ([]Record, error) {
	var out []Record
	n, _, err := scan(bytesReader(body), func(r Record) bool { out = append(out, r); return true })
	if err == nil && n != int64(len(body)) {
		err = errors.New("logstore: torn record in bulk body")
	}
	return out, err
}

type byteReader struct{ b []byte }

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }
func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

// Append stores records for container id (taken from the engine, in seq
// order). Records at or below the last stored seq are skipped, so a bulk
// fetched twice is harmless. meta names the container on first use; a later
// non-zero Cap changes the cap. It returns the last stored seq.
func (s *Store) Append(id string, meta Meta, recs []Record) (uint64, error) {
	l, err := s.get(id, &meta)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.removed {
		return 0, ErrNotFound
	}
	if meta.Cap > 0 && max(meta.Cap, MinCap) != l.meta.Cap {
		l.meta.Cap = max(meta.Cap, MinCap)
		_ = l.saveMeta()
	}
	var buf []byte
	first := uint64(0)
	for _, r := range recs {
		if r.Seq <= l.last {
			continue
		}
		if l.last > 0 && r.Seq > l.last+1 {
			l.dropped += r.Seq - l.last - 1 // the engine dropped these (its own cap)
		}
		l.last = r.Seq
		if !r.Time.After(l.cleared) {
			continue // queued before a clear: taken (and acked) but not kept
		}
		if first == 0 {
			first = r.Seq
		}
		buf = Encode(buf, r)
	}
	if len(buf) == 0 {
		return l.last, nil
	}
	pieceCap := l.meta.Cap / segments
	if len(l.segs) == 0 || l.segs[len(l.segs)-1].size >= pieceCap {
		l.segs = append(l.segs, seg{first: first})
	}
	cur := &l.segs[len(l.segs)-1]
	f, err := os.OpenFile(filepath.Join(l.dir, segName(cur.first)), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	_, err = f.Write(buf)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, err
	}
	cur.size += int64(len(buf))
	cur.last = l.last
	l.trim()
	close(l.notify)
	l.notify = make(chan struct{})
	return l.last, nil
}

// trim drops whole oldest pieces while the log is over its cap.
func (l *clog) trim() {
	total := int64(0)
	for _, sg := range l.segs {
		total += sg.size
	}
	changed := false
	for total > l.meta.Cap && len(l.segs) > 1 {
		old := l.segs[0]
		_ = os.Remove(filepath.Join(l.dir, segName(old.first)))
		l.segs = l.segs[1:]
		total -= old.size
		l.dropped += old.last - old.first + 1
		changed = true
	}
	if changed {
		_ = l.saveMeta()
	}
}

// Last returns the last stored seq of id (0 when none).
func (s *Store) Last(id string) uint64 {
	l, err := s.get(id, nil)
	if err != nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last
}

// Info returns id's extent.
func (s *Store) Info(id string) (Info, error) {
	l, err := s.get(id, nil)
	if err != nil {
		return Info{}, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	in := Info{Meta: l.meta, Last: l.last, Dropped: l.dropped, Gone: l.gone}
	for i, sg := range l.segs {
		if i == 0 {
			in.First = sg.first
		}
		in.Size += sg.size
	}
	return in, nil
}

// List returns every stored container log.
func (s *Store) List() ([]Info, error) {
	ents, err := os.ReadDir(s.root)
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, e := range ents {
		if !e.IsDir() || !validID.MatchString(e.Name()) {
			continue
		}
		if in, err := s.Info(e.Name()); err == nil {
			out = append(out, in)
		}
	}
	return out, nil
}

// Delete removes id's whole log (a user's delete). Readers following it end.
func (s *Store) Delete(id string) error {
	l, err := s.get(id, nil)
	if err != nil {
		return err
	}
	l.mu.Lock()
	l.removed = true
	close(l.notify)
	l.notify = make(chan struct{})
	l.mu.Unlock()
	// Remove the files under s.mu so a follower waking on the close above
	// cannot reload the half-removed log through get.
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.logs, id)
	return os.RemoveAll(l.dir)
}

// DeleteWhere removes the logs for which match returns true (for example
// one app's).
func (s *Store) DeleteWhere(match func(Meta) bool) (int, error) {
	all, err := s.List()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, in := range all {
		if match(in.Meta) {
			if err := s.Delete(in.Container); err != nil && !errors.Is(err, ErrNotFound) {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// Read calls fn for each stored record of id with seq > after, oldest
// first, until fn returns false. changed is closed by the next append (or a
// delete); a follower waits on it and reads again from the last seq it saw.
func (s *Store) Read(id string, after uint64, fn func(Record) bool) (changed <-chan struct{}, err error) {
	l, err := s.get(id, nil)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	if l.removed {
		l.mu.Unlock()
		return nil, ErrNotFound
	}
	changed = l.notify
	segs := slices.Clone(l.segs)
	dir, cleared := l.dir, l.cleared
	l.mu.Unlock()
	for _, sg := range segs {
		if sg.last <= after {
			continue
		}
		f, err := os.Open(filepath.Join(dir, segName(sg.first)))
		if errors.Is(err, os.ErrNotExist) {
			continue // trimmed meanwhile
		}
		if err != nil {
			return changed, err
		}
		stop := false
		_, _, err = scan(io.LimitReader(f, sg.size), func(r Record) bool {
			if r.Seq <= after || !r.Time.After(cleared) {
				return true
			}
			if !fn(r) {
				stop = true
				return false
			}
			return true
		})
		_ = f.Close()
		if err != nil {
			return changed, err
		}
		if stop {
			break
		}
	}
	return changed, nil
}

// TrimBefore removes id's records at or before t and remembers t, so lines
// the engine still queues from before t are dropped when they arrive. The
// container is not touched. It returns how many records were removed.
func (s *Store) TrimBefore(id string, t time.Time) (int, error) {
	l, err := s.get(id, nil)
	if err != nil {
		return 0, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.removed {
		return 0, ErrNotFound
	}
	// The clear time is saved first: from then on reads skip those records,
	// so a crash while segments are rewritten below shows nothing cleared.
	if t.After(l.cleared) {
		l.cleared = t
		if err := l.saveMeta(); err != nil {
			return 0, err
		}
	}
	removed := 0
	var kept []seg
	for _, sg := range l.segs {
		name := filepath.Join(l.dir, segName(sg.first))
		f, err := os.Open(name)
		if err != nil {
			return removed, err
		}
		var (
			buf        []byte
			first, end uint64
			drop       int
		)
		_, _, err = scan(f, func(r Record) bool {
			if !r.Time.After(t) {
				drop++
				return true
			}
			if first == 0 {
				first = r.Seq
			}
			end = r.Seq
			buf = Encode(buf, r)
			return true
		})
		_ = f.Close()
		if err != nil {
			return removed, err
		}
		removed += drop
		switch {
		case drop == 0:
			kept = append(kept, sg)
			continue
		case len(buf) == 0:
			if err := os.Remove(name); err != nil {
				return removed, err
			}
			continue
		}
		next := filepath.Join(l.dir, segName(first))
		tmp := next + ".tmp"
		if err := os.WriteFile(tmp, buf, 0o600); err != nil {
			return removed, err
		}
		if err := os.Rename(tmp, next); err != nil {
			return removed, err
		}
		if next != name {
			if err := os.Remove(name); err != nil {
				return removed, err
			}
		}
		kept = append(kept, seg{first: first, last: end, size: int64(len(buf))})
	}
	l.segs = kept
	close(l.notify)
	l.notify = make(chan struct{})
	return removed, nil
}

// TrimWhere runs TrimBefore(t) on every log whose Meta match accepts,
// including logs of containers already gone. It returns how many logs
// matched and how many records were removed.
func (s *Store) TrimWhere(match func(Meta) bool, t time.Time) (logs, removed int, err error) {
	all, err := s.List()
	if err != nil {
		return 0, 0, err
	}
	for _, in := range all {
		if !match(in.Meta) {
			continue
		}
		n, err := s.TrimBefore(in.Container, t)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return logs, removed, err
		}
		logs++
		removed += n
	}
	return logs, removed, nil
}

// MarkGone records that id's container no longer exists on the engine. The
// first time counts; a log already marked keeps its time.
func (s *Store) MarkGone(id string, at time.Time) error {
	l, err := s.get(id, nil)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.removed {
		return ErrNotFound
	}
	if !l.gone.IsZero() {
		return nil
	}
	l.gone = at.UTC()
	return l.saveMeta()
}

// Prune removes logs of gone containers: those gone for keep(log) or
// longer (keep <= 0 keeps that log), then, while the store holds more than maxTotal
// bytes (maxTotal <= 0: no limit), the longest-gone ones first. Logs of
// containers that still exist are never pruned; their own cap bounds them.
// It returns the containers whose logs were removed.
func (s *Store) Prune(now time.Time, keep func(Info) time.Duration, maxTotal int64) ([]string, error) {
	all, err := s.List()
	if err != nil {
		return nil, err
	}
	var total int64
	var gone []Info
	for _, in := range all {
		total += in.Size
		if !in.Gone.IsZero() {
			gone = append(gone, in)
		}
	}
	slices.SortFunc(gone, func(a, b Info) int { return a.Gone.Compare(b.Gone) })
	var removed []string
	for _, in := range gone {
		k := keep(in)
		expired := k > 0 && now.Sub(in.Gone) >= k
		over := maxTotal > 0 && total > maxTotal
		if !expired && !over {
			continue
		}
		if err := s.Delete(in.Container); err != nil && !errors.Is(err, ErrNotFound) {
			return removed, err
		}
		total -= in.Size
		removed = append(removed, in.Container)
	}
	return removed, nil
}
