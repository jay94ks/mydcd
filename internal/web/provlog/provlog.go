// SPDX-License-Identifier: Apache-2.0

// Package provlog keeps mydc-web's diagnostic log of calls to outside
// providers (DNS vendors, ACME certificate authorities). Every HTTP request
// a provider adapter makes is one entry with a short, redacted summary of
// the request and the response, so a run on the real cluster can be handed
// back for diagnosis without live access to the provider.
//
// Entries live in memory (the newest Max) and in JSON-lines files under
// the data folder, so they survive a restart. Nothing secret is written:
// adapters redact before they call Add, and the HTTP transport never logs
// headers other than a short allow-list.
package provlog

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Entry is one log line.
type Entry struct {
	Seq      uint64    `json:"seq"`
	At       time.Time `json:"at"`
	Provider string    `json:"provider"`       // "dns:hostinger", "acme:letsencrypt-staging"
	Conn     string    `json:"conn,omitempty"` // web connection or account ID
	Op       string    `json:"op,omitempty"`   // adapter operation ("GetZone", "NewOrder", …)
	Level    string    `json:"level"`          // "info", "warn", "error"
	Msg      string    `json:"msg,omitempty"`
	HTTP     *HTTP     `json:"http,omitempty"`
	// Kind is the classified error kind when the call failed.
	Kind  string            `json:"kind,omitempty"`
	Error string            `json:"error,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// HTTP is the redacted summary of one request.
type HTTP struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"` // without query values that look secret
	Status     int               `json:"status,omitempty"`
	DurationMS int64             `json:"durationMs"`
	Request    string            `json:"request,omitempty"`  // redacted, truncated body
	Response   string            `json:"response,omitempty"` // redacted, truncated body
	ReqBytes   int               `json:"reqBytes,omitempty"`
	RespBytes  int               `json:"respBytes,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"` // allow-listed response headers
}

// Levels.
const (
	Info  = "info"
	Warn  = "warn"
	Error = "error"
)

// Filter selects entries. Zero fields match everything.
type Filter struct {
	Provider string    // exact, or a prefix ending in ":" ("dns:")
	Conn     string    // exact
	Op       string    // exact
	Level    string    // minimum level
	Since    time.Time // At >= Since
	Text     string    // substring of the JSON line
}

func levelRank(l string) int {
	switch l {
	case Warn:
		return 1
	case Error:
		return 2
	}
	return 0
}

// Match reports whether e passes f.
func (f Filter) Match(e Entry) bool {
	if f.Provider != "" {
		if strings.HasSuffix(f.Provider, ":") {
			if !strings.HasPrefix(e.Provider, f.Provider) {
				return false
			}
		} else if e.Provider != f.Provider {
			return false
		}
	}
	if f.Conn != "" && e.Conn != f.Conn {
		return false
	}
	if f.Op != "" && e.Op != f.Op {
		return false
	}
	if levelRank(e.Level) < levelRank(f.Level) {
		return false
	}
	if !f.Since.IsZero() && e.At.Before(f.Since) {
		return false
	}
	if f.Text != "" {
		raw, _ := json.Marshal(e)
		if !strings.Contains(string(raw), f.Text) {
			return false
		}
	}
	return true
}

// Log is the provider log. A nil *Log drops everything, so code paths
// without a log (tests) need no checks.
type Log struct {
	mu      sync.Mutex
	dir     string
	max     int
	ring    []Entry
	seq     uint64
	file    *os.File
	size    int64
	maxFile int64
	subs    map[chan Entry]struct{}
	now     func() time.Time
	werr    error // last write error
	sess    session
}

// Options configures Open.
type Options struct {
	Max     int   // entries kept in memory (default 5000)
	MaxFile int64 // bytes per file before rotation (default 8 MiB); one old file is kept
	Now     func() time.Time
}

const fileName = "providers.jsonl"

// Open opens (or creates) the log in dir and loads the newest entries of
// its files. An empty dir keeps the log in memory only.
func Open(dir string, o Options) (*Log, error) {
	if o.Max <= 0 {
		o.Max = 5000
	}
	if o.MaxFile <= 0 {
		o.MaxFile = 8 << 20
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	l := &Log{dir: dir, max: o.Max, maxFile: o.MaxFile, now: o.Now, subs: map[chan Entry]struct{}{}, sess: session{reason: "restart"}}
	if dir == "" {
		return l, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, name := range []string{fileName + ".1", fileName} {
		if err := l.load(filepath.Join(dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	f, err := os.OpenFile(filepath.Join(dir, fileName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	l.file, l.size = f, st.Size()
	return l, nil
}

func (l *Log) load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // a torn last line after a crash
		}
		l.push(e)
		l.seq = max(l.seq, e.Seq)
	}
	return sc.Err()
}

func (l *Log) push(e Entry) {
	l.ring = append(l.ring, e)
	if len(l.ring) > l.max {
		l.ring = append(l.ring[:0:0], l.ring[len(l.ring)-l.max:]...)
	}
}

// Close closes the file and ends the subscriptions.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.subs {
		close(c)
		delete(l.subs, c)
	}
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// Add stores e with the next sequence number and the current time (when
// e.At is zero) and returns it. While collection is off (the default) it
// drops e; a stored entry counts as activity.
func (l *Log) Add(e Entry) Entry {
	if l == nil {
		return e
	}
	if e.Level == "" {
		e.Level = Info
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now().UTC()
	l.expireLocked(now)
	if !l.sess.enabled {
		return e
	}
	l.sess.activity = now
	l.seq++
	e.Seq = l.seq
	if e.At.IsZero() {
		e.At = now
	}
	l.push(e)
	l.write(e)
	for c := range l.subs {
		select {
		case c <- e:
		default: // a slow reader misses entries; it can poll for them by seq
		}
	}
	return e
}

func (l *Log) write(e Entry) {
	if l.file == nil {
		return
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	if l.size+int64(len(raw)) > l.maxFile && l.size > 0 {
		l.file.Close()
		cur := filepath.Join(l.dir, fileName)
		_ = os.Rename(cur, cur+".1")
		f, err := os.OpenFile(cur, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			l.file, l.werr = nil, err
			return
		}
		l.file, l.size = f, 0
	}
	n, err := l.file.Write(raw)
	l.size += int64(n)
	l.werr = err
}

// Page is a list result.
type Page struct {
	Entries []Entry `json:"entries"`
	// Next is the seq to pass as after for the following page (the last
	// returned seq, or after itself when nothing matched).
	Next uint64 `json:"next"`
	// Last is the newest seq in the log.
	Last uint64 `json:"last"`
	// Oldest is the oldest seq still kept in memory; entries before it are
	// only in the files.
	Oldest uint64 `json:"oldest"`
	More   bool   `json:"more"`
}

// List returns up to limit entries with seq > after that match f, oldest
// first. limit <= 0 means 500.
func (l *Log) List(f Filter, after uint64, limit int) Page {
	if limit <= 0 {
		limit = 500
	}
	p := Page{Entries: []Entry{}, Next: after}
	if l == nil {
		return p
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p.Last = l.seq
	if len(l.ring) > 0 {
		p.Oldest = l.ring[0].Seq
	}
	for _, e := range l.ring {
		if e.Seq <= after {
			continue
		}
		p.Next = e.Seq
		if !f.Match(e) {
			continue
		}
		if len(p.Entries) == limit {
			p.Next = p.Entries[len(p.Entries)-1].Seq
			p.More = true
			break
		}
		p.Entries = append(p.Entries, e)
	}
	return p
}

// Subscribe returns a channel of new entries. The channel is closed by
// cancel or Close. A reader that falls behind misses entries and should
// catch up with List.
func (l *Log) Subscribe() (<-chan Entry, func()) {
	c := make(chan Entry, 256)
	if l == nil {
		close(c)
		return c, func() {}
	}
	l.mu.Lock()
	l.subs[c] = struct{}{}
	l.mu.Unlock()
	return c, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if _, ok := l.subs[c]; ok {
			delete(l.subs, c)
			close(c)
		}
	}
}

// WriteError returns the last file write error (nil when the last write
// worked).
func (l *Log) WriteError() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.werr
}

// Export writes every stored entry that matches f as JSON lines, oldest
// first: the files when the log has them (they reach further back than
// memory), else memory.
func (l *Log) Export(w io.Writer, f Filter) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	enc := json.NewEncoder(w)
	if l.dir == "" {
		for _, e := range l.ring {
			if f.Match(e) {
				if err := enc.Encode(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, name := range []string{fileName + ".1", fileName} {
		fh, err := os.Open(filepath.Join(l.dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var e Entry
			if json.Unmarshal(sc.Bytes(), &e) != nil || !f.Match(e) {
				continue
			}
			if err := enc.Encode(e); err != nil {
				fh.Close()
				return err
			}
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}
	return nil
}

// Tail returns the newest n entries that match f (oldest first).
func (l *Log) Tail(f Filter, n int) Page {
	if n <= 0 {
		n = 100
	}
	p := Page{Entries: []Entry{}}
	if l == nil {
		return p
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	p.Last, p.Next = l.seq, l.seq
	if len(l.ring) > 0 {
		p.Oldest = l.ring[0].Seq
	}
	for i := len(l.ring) - 1; i >= 0; i-- {
		if f.Match(l.ring[i]) {
			if len(p.Entries) == n {
				p.More = true
				break
			}
			p.Entries = append(p.Entries, l.ring[i])
		}
	}
	slices.Reverse(p.Entries)
	return p
}
