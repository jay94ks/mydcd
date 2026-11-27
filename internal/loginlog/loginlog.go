// SPDX-License-Identifier: Apache-2.0

// Package loginlog is a node's own record of the logins it judged: each
// password, token or private-key login whose ticket this node issued, with
// its outcome. It is node-local (never Raft) and bounded per account, so a
// flood of failed attempts can neither grow the cluster state nor push out
// another user's history. It never holds a secret, a proof or a session key.
package loginlog

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/storage"
)

const (
	// PerUser is how many records one account keeps on one node.
	PerUser = 64
	// Retention is how long a record is kept.
	Retention = 30 * 24 * time.Hour
	// Coalesce joins repeated failures from one source within this window.
	Coalesce = 60 * time.Second
	// MaxPage is the largest page.
	MaxPage = 100

	prefix = "login-records/"
)

var ErrInvalid = errors.New("invalid login record query")

// Client is what the client reports about itself (for sfc-web, the
// browser's user agent and address). It is a hint, not a verified fact.
type Client struct {
	Client  string `json:",omitempty"`
	Address string `json:",omitempty"`
}

// Valid bounds the hint: printable UTF-8, Client at most 256 bytes and
// Address at most 64.
func (c Client) Valid() bool {
	return printable(c.Client, 256) && printable(c.Address, 64)
}

func printable(s string, max int) bool {
	if len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Record is one login attempt (or, with Count > 1, a run of failed attempts
// from the same source).
type Record struct {
	Schema uint8
	ID     string
	Node   string
	// At is the first attempt (Unix ms); LastAt the latest one of a run.
	At, LastAt int64
	Count      uint32
	User       string
	Username   string
	OK         bool
	// Reason of a failure: "denied" or "throttled".
	Reason     string        `json:",omitempty"`
	Method     access.Method `json:",omitempty"`
	Credential string        `json:",omitempty"`
	// Session of a success: its ID, expiry (Unix s) and account revision.
	Session         string `json:",omitempty"`
	ExpiresAt       int64  `json:",omitempty"`
	AccountRevision uint64 `json:",omitempty"`
	// Source is the connection this node saw (a peer address or a local
	// unix-uid). Client is the client's own report.
	Source string `json:",omitempty"`
	Client Client
}

// Valid is the shape every stored and relayed record has.
func (r Record) Valid() bool {
	if r.Schema != 1 || r.ID == "" || len(r.ID) > 32 || r.Node == "" || len(r.Node) > 128 || r.User == "" || len(r.User) > 128 || len(r.Username) > 128 || r.At <= 0 || r.LastAt < r.At || r.Count < 1 || len(r.Credential) > 128 || len(r.Session) > 128 || len(r.Source) > 128 || !r.Client.Valid() {
		return false
	}
	if r.OK {
		return r.Reason == "" && r.Session != "" && r.Count == 1
	}
	return (r.Reason == "denied" || r.Reason == "throttled") && r.Session == "" && r.ExpiresAt == 0
}

// Cursor orders records newest first: by At, then Node, then ID, all
// descending. A page holds the records strictly after its cursor.
type Cursor struct {
	At   int64
	Node string
	ID   string
}

func (c Cursor) String() string {
	return strconv.FormatInt(c.At, 10) + "/" + c.Node + "/" + c.ID
}

// ParseCursor reads Cursor.String; "" is the start.
func ParseCursor(s string) (Cursor, bool, error) {
	if s == "" {
		return Cursor{}, false, nil
	}
	parts := strings.Split(s, "/")
	if len(s) > 512 || len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return Cursor{}, false, ErrInvalid
	}
	at, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || at <= 0 {
		return Cursor{}, false, ErrInvalid
	}
	return Cursor{At: at, Node: parts[1], ID: parts[2]}, true, nil
}

// Of is the cursor of r.
func Of(r Record) Cursor { return Cursor{At: r.At, Node: r.Node, ID: r.ID} }

// Before reports whether a comes after b in newest-first order.
func Before(a, b Cursor) bool {
	if a.At != b.At {
		return a.At < b.At
	}
	if a.Node != b.Node {
		return a.Node < b.Node
	}
	return a.ID < b.ID
}

// Sort puts records newest first.
func Sort(records []Record) {
	slices.SortFunc(records, func(a, b Record) int {
		switch {
		case Before(Of(b), Of(a)):
			return -1
		case Before(Of(a), Of(b)):
			return 1
		}
		return 0
	})
}

// Query selects one account's records.
type Query struct {
	User  string
	After string `json:",omitempty"`
	Limit int
}

func (q Query) Valid() bool {
	_, _, err := ParseCursor(q.After)
	return q.User != "" && len(q.User) <= 128 && q.Limit >= 1 && q.Limit <= MaxPage && err == nil
}

// Page is a newest-first page. Next is empty at the end. Missing names the
// servers whose records could not be read, so the page may lack theirs.
type Page struct {
	Items   []Record
	Next    string   `json:",omitempty"`
	Missing []string `json:",omitempty"`
}

// Store is one node's journal.
type Store struct {
	db   *storage.DB
	node string
	mu   sync.Mutex
}

// Open uses db (the node's own report database) for node.
func Open(db *storage.DB, node string) (*Store, error) {
	if db == nil || node == "" || strings.Contains(node, "/") {
		return nil, ErrInvalid
	}
	return &Store{db: db, node: node}, nil
}

// Node is the node this journal belongs to.
func (s *Store) Node() string { return s.node }

func userPrefix(user string) string {
	return prefix + hex.EncodeToString([]byte(user)) + "/"
}

func recordKey(r Record) string {
	return fmt.Sprintf("%s%016x/%s", userPrefix(r.User), r.At, r.ID)
}

// scan reads one account's records, oldest first.
func (s *Store) scan(user string) ([]string, []Record, error) {
	raw, err := s.db.ScanBounded(userPrefix(user), PerUser+8, (PerUser+8)*4096)
	if err != nil {
		return nil, nil, err
	}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	records := make([]Record, 0, len(keys))
	for _, k := range keys {
		var r Record
		if json.Unmarshal(raw[k], &r) != nil || !r.Valid() {
			r = Record{}
		}
		records = append(records, r)
	}
	return keys, records, nil
}

// Add stores r (its Schema, ID, Node, At, LastAt and Count are filled in).
// A failure that repeats the latest failed record's source, method,
// credential and reason within Coalesce only counts up that record.
func (s *Store) Add(r Record, now time.Time) error {
	r.Schema, r.Node, r.At, r.LastAt, r.Count = 1, s.node, now.UnixMilli(), now.UnixMilli(), 1
	var id [8]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	r.ID = hex.EncodeToString(id[:])
	if !r.Valid() {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, records, err := s.scan(r.User)
	if err != nil {
		return err
	}
	writes := map[string][]byte{}
	if n := len(records); n > 0 && !r.OK {
		last := records[n-1]
		if last.Schema == 1 && !last.OK && last.Source == r.Source && last.Method == r.Method && last.Credential == r.Credential && last.Reason == r.Reason && last.Client == r.Client && r.At-last.LastAt <= Coalesce.Milliseconds() && last.Count < 1<<31 {
			last.LastAt, last.Count = r.At, last.Count+1
			raw, err := json.Marshal(last)
			if err != nil {
				return err
			}
			return s.db.Write(map[string][]byte{keys[n-1]: raw})
		}
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	writes[recordKey(r)] = raw
	// Keep PerUser records (the new one included) and nothing older than
	// Retention; unreadable records go too.
	cut := now.Add(-Retention).UnixMilli()
	excess := len(keys) + 1 - PerUser
	for i, k := range keys {
		if i < excess || records[i].Schema != 1 || records[i].LastAt < cut {
			writes[k] = nil
		}
	}
	return s.db.Write(writes)
}

// Page reads q.User's records on this node, newest first, after q.After.
func (s *Store) Page(q Query, now time.Time) (Page, error) {
	if !q.Valid() {
		return Page{}, ErrInvalid
	}
	after, has, _ := ParseCursor(q.After)
	s.mu.Lock()
	_, records, err := s.scan(q.User)
	s.mu.Unlock()
	if err != nil {
		return Page{}, err
	}
	cut := now.Add(-Retention).UnixMilli()
	out := Page{Items: []Record{}}
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		if r.Schema != 1 || r.LastAt < cut || has && !Before(Of(r), after) {
			continue
		}
		if len(out.Items) == q.Limit {
			out.Next = Of(out.Items[len(out.Items)-1]).String()
			break
		}
		out.Items = append(out.Items, r)
	}
	return out, nil
}

// Merge joins node pages for one query into one newest-first page of at
// most limit records.
func Merge(pages []Page, limit int) Page {
	out := Page{Items: []Record{}}
	more := false
	for _, p := range pages {
		out.Items = append(out.Items, p.Items...)
		out.Missing = append(out.Missing, p.Missing...)
		more = more || p.Next != ""
	}
	Sort(out.Items)
	if len(out.Items) > limit {
		out.Items, more = out.Items[:limit], true
	}
	if more && len(out.Items) > 0 {
		out.Next = Of(out.Items[len(out.Items)-1]).String()
	}
	slices.Sort(out.Missing)
	out.Missing = slices.Compact(out.Missing)
	return out
}
