// SPDX-License-Identifier: Apache-2.0

// Package recovery implements FSM replay and snapshot staging/activation plans.
// Raft decides commitment, membership and snapshot authorization; a real store
// must atomically persist each returned candidate before publishing or ACKing it.
package recovery

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"io"
)

var ErrRecovery = errors.New("invalid recovery position, artifact or log")

const ChunkLimit = 128 << 10
const DefaultReceiveBudget = 8 << 20

type Entry struct {
	Index, Term uint64
	Command     state.Command
}
type Metadata struct {
	Schema                uint8
	Index, Term           uint64
	Size                  int
	Digest, Configuration [32]byte
}
type Node struct {
	Shared      state.State
	AppliedTerm uint64
	Installed   Metadata
	Log         []Entry
	// Never replace these from a shared snapshot.
	CurrentTerm uint64
	Vote        string
	Local       map[string]string
}

func copyNode(n Node) Node {
	n.Log = append([]Entry(nil), n.Log...)
	m := make(map[string]string, len(n.Local))
	for k, v := range n.Local {
		m[k] = v
	}
	n.Local = m
	return n
}
func validMeta(m Metadata) bool {
	return m.Schema == 1 && m.Index > 0 && m.Term > 0 && m.Size > 0 && m.Configuration != [32]byte{} && m.Digest != [32]byte{}
}
func Build(s state.State, term uint64, configuration [32]byte) (Metadata, []byte, error) {
	b, err := state.Encode(s)
	if err != nil {
		return Metadata{}, nil, err
	}
	m := Metadata{Schema: 1, Index: s.Index(), Term: term, Size: len(b), Digest: sha256.Sum256(b), Configuration: configuration}
	if !validMeta(m) {
		return Metadata{}, nil, ErrRecovery
	}
	return m, b, nil
}

type Receiver struct {
	meta Metadata
	data []byte
}

func Begin(m Metadata) (*Receiver, error) {
	if !validMeta(m) || m.Size > DefaultReceiveBudget {
		return nil, ErrRecovery
	}
	return &Receiver{meta: m}, nil
}
func (r *Receiver) Offset() int { return len(r.data) }
func (r *Receiver) Append(offset int, b []byte) error {
	if len(b) == 0 || len(b) > ChunkLimit || offset < 0 || offset > len(r.data) || len(b) > r.meta.Size-offset {
		return ErrRecovery
	}
	if offset < len(r.data) {
		if len(b) > len(r.data)-offset || !bytes.Equal(r.data[offset:offset+len(b)], b) {
			return ErrRecovery
		}
		return nil
	}
	r.data = append(r.data, b...)
	return nil
}

// Prefix is an owned copy for the staging store. Resume revalidates it; partial
// staging is never an active FSM and cannot authorize prefix deletion or ACK.
func (r *Receiver) Prefix() []byte { return append([]byte(nil), r.data...) }
func Resume(m Metadata, prefix []byte) (*Receiver, error) {
	r, err := Begin(m)
	if err != nil || len(prefix) > m.Size {
		return nil, ErrRecovery
	}
	r.data = append([]byte(nil), prefix...)
	return r, nil
}

type Verified struct {
	meta   Metadata
	shared state.State
}

func (r *Receiver) Finish() (Verified, error) {
	return Verify(r.meta, bytes.NewReader(r.data))
}

// Verify shares canonical validation with staged and streamed artifacts. It
// neither activates state nor sends ACK. The reader must end at the artifact.
func Verify(m Metadata, source io.Reader) (Verified, error) {
	if !validMeta(m) {
		return Verified{}, ErrRecovery
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: source, N: int64(m.Size)}
	s, err := state.DecodeFrom(io.TeeReader(limited, hash))
	if err != nil || limited.N != 0 || s.Index() != m.Index || !bytes.Equal(hash.Sum(nil), m.Digest[:]) {
		return Verified{}, ErrRecovery
	}
	var extra [1]byte
	n, err := source.Read(extra[:])
	if n != 0 || err != io.EOF {
		return Verified{}, ErrRecovery
	}
	return Verified{m, s}, nil
}
func (v Verified) State() state.State { return v.shared }

// Install is a candidate transaction, NOT a durable ACK. A matching included
// term retains a contiguous suffix; a mismatch drops the uncommitted tail.
// A snapshot older than an already applied FSM is never installed.
func Install(n Node, v Verified) (Node, error) {
	if !validMeta(v.meta) || v.shared.Index() != v.meta.Index || v.meta.Index < n.Shared.Index() {
		return n, ErrRecovery
	}
	if v.meta.Index == n.Shared.Index() {
		if n.Installed == v.meta {
			return copyNode(n), nil
		}
		return n, ErrRecovery
	}
	if err := validateLog(n); err != nil {
		return n, err
	}
	retain := n.Installed.Index == v.meta.Index && n.Installed.Term == v.meta.Term
	for _, e := range n.Log {
		if e.Index == v.meta.Index {
			retain = e.Term == v.meta.Term
		}
	}
	q := copyNode(n)
	q.Shared = v.shared
	q.AppliedTerm = v.meta.Term
	q.Installed = v.meta
	q.Log = nil
	if retain {
		for _, e := range n.Log {
			if e.Index > v.meta.Index {
				q.Log = append(q.Log, e)
			}
		}
	}
	return q, nil
}
func validateLog(n Node) error {
	if n.Installed.Index == 0 && n.Installed != (Metadata{}) || n.Installed.Index > 0 && !validMeta(n.Installed) || n.Shared.Index() < n.Installed.Index {
		return ErrRecovery
	}
	index, term := n.Installed.Index, n.Installed.Term
	matched := n.Shared.Index() == index && n.AppliedTerm == term
	for _, e := range n.Log {
		if index == ^uint64(0) || e.Index != index+1 || e.Term == 0 || e.Term < term {
			return ErrRecovery
		}
		index = e.Index
		term = e.Term
		if e.Index == n.Shared.Index() {
			matched = e.Term == n.AppliedTerm
		}
	}
	if !matched {
		return ErrRecovery
	}
	return nil
}

// Add accepts the library's retained committed/suffix input without deciding a
// winner. Duplicate bytes are idempotent; divergent entries require the library
// to provide a new authorized suffix, never silent overwrite here.
func Add(n Node, entries []Entry) (Node, error) {
	if validateLog(n) != nil {
		return n, ErrRecovery
	}
	q := copyNode(n)
	for _, e := range entries {
		if e.Index <= q.Installed.Index {
			return n, ErrRecovery
		}
		pos := e.Index - q.Installed.Index - 1
		if pos < uint64(len(q.Log)) {
			if q.Log[pos] != e {
				return n, ErrRecovery
			}
			continue
		}
		if pos != uint64(len(q.Log)) {
			return n, ErrRecovery
		}
		q.Log = append(q.Log, e)
	}
	if validateLog(q) != nil {
		return n, ErrRecovery
	}
	return q, nil
}
func Replay(n Node, committed uint64) (Node, error) {
	if validateLog(n) != nil || committed < n.Shared.Index() {
		return n, ErrRecovery
	}
	q := copyNode(n)
	for _, e := range q.Log {
		if e.Index <= q.Shared.Index() {
			continue
		}
		if e.Index > committed {
			break
		}
		s, _, err := state.Apply(q.Shared, e.Index, e.Command)
		if err != nil {
			return n, err
		}
		q.Shared = s
		q.AppliedTerm = e.Term
	}
	if q.Shared.Index() != committed {
		return n, ErrRecovery
	}
	return q, nil
}

// Checkpoint atomically advances a LOCAL durable snapshot anchor and drops its
// log prefix in the candidate. Physical segment GC must follow store publication.
func Checkpoint(n Node, v Verified) (Node, error) {
	b, err := state.Encode(n.Shared)
	if err != nil || !validMeta(v.meta) || v.meta.Index != n.Shared.Index() || v.meta.Term != n.AppliedTerm || sha256.Sum256(b) != v.meta.Digest || validateLog(n) != nil {
		return n, ErrRecovery
	}
	q := copyNode(n)
	q.Installed = v.meta
	q.Log = nil
	for _, e := range n.Log {
		if e.Index > v.meta.Index {
			q.Log = append(q.Log, e)
		}
	}
	if validateLog(q) != nil {
		return n, ErrRecovery
	}
	return q, nil
}
