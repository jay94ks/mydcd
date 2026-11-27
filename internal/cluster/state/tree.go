// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/binary"

	iradix "github.com/hashicorp/go-immutable-radix"
)

// tree is an immutable sorted map. A State value keeps one root; setting a
// key path-copies only the changed nodes, so older States (published reads,
// a rejected candidate's parent) keep seeing their own version for free.
type tree[V any] struct{ root *iradix.Tree }

func (t tree[V]) get(key string) (V, bool) {
	var zero V
	if t.root == nil {
		return zero, false
	}
	v, ok := t.root.Get([]byte(key))
	if !ok {
		return zero, false
	}
	return v.(V), true
}

func (t *tree[V]) set(key string, value V) {
	if t.root == nil {
		t.root = iradix.New()
	}
	t.root, _, _ = t.root.Insert([]byte(key), value)
}

func (t *tree[V]) del(key string) {
	if t.root != nil {
		t.root, _, _ = t.root.Delete([]byte(key))
	}
}

func (t tree[V]) len() int {
	if t.root == nil {
		return 0
	}
	return t.root.Len()
}

// walk visits keys with prefix in byte order until fn returns false.
func (t tree[V]) walk(prefix string, fn func(string, V) bool) {
	if t.root == nil {
		return
	}
	t.root.Root().WalkPrefix([]byte(prefix), func(k []byte, v interface{}) bool {
		return !fn(string(k), v.(V))
	})
}

// A request key is length-prefixed so one actor's receipts are one prefix and
// no actor/ID pair can collide with another, whatever bytes they contain.
func actorPrefix(actor string) string {
	b := binary.AppendUvarint(nil, uint64(len(actor)))
	return string(append(b, actor...))
}

func (k requestKey) String() string { return actorPrefix(k.actor) + k.id }

func parseRequestKey(s string) (requestKey, bool) {
	n, size := binary.Uvarint([]byte(s))
	if size <= 0 || uint64(len(s)-size) < n {
		return requestKey{}, false
	}
	rest := s[size:]
	return requestKey{actor: rest[:n], id: rest[n:]}, true
}

// touched records which keys one candidate wrote, so the FSM can persist
// only those rows. Values are read from the candidate itself.
type touched struct {
	objects, requests, reports map[string]struct{}
}

func newTouched() *touched {
	return &touched{objects: map[string]struct{}{}, requests: map[string]struct{}{}, reports: map[string]struct{}{}}
}

func (s *State) mark(set func(*touched) map[string]struct{}, key string) {
	if s.touched != nil {
		set(s.touched)[key] = struct{}{}
	}
}

func (s *State) putObject(key string, o Object) {
	s.objects.set(key, o)
	s.mark(func(t *touched) map[string]struct{} { return t.objects }, key)
}

func (s *State) dropObject(key string) {
	s.objects.del(key)
	s.mark(func(t *touched) map[string]struct{} { return t.objects }, key)
}

// restoreObject puts back before's row for key, or removes it if before had none.
func (s *State) restoreObject(before State, key string) {
	if original, exists := before.objects.get(key); exists {
		s.putObject(key, original)
	} else {
		s.dropObject(key)
	}
}

func (s *State) putRequest(k requestKey, r receipt) {
	s.requests.set(k.String(), r)
	s.mark(func(t *touched) map[string]struct{} { return t.requests }, k.String())
}

func (s *State) dropRequest(k requestKey) {
	s.requests.del(k.String())
	s.mark(func(t *touched) map[string]struct{} { return t.requests }, k.String())
}

func (s State) request(k requestKey) (receipt, bool) { return s.requests.get(k.String()) }

func (s *State) putReport(k requestKey, r reportReceipt) {
	s.reportReceipts.set(k.String(), r)
	s.mark(func(t *touched) map[string]struct{} { return t.reports }, k.String())
}

func (s *State) dropReport(k requestKey) {
	s.reportReceipts.del(k.String())
	s.mark(func(t *touched) map[string]struct{} { return t.reports }, k.String())
}

// actorRequests visits one actor's receipts.
func (s State) actorRequests(actor string, fn func(requestKey, receipt) bool) {
	s.requests.walk(actorPrefix(actor), func(k string, r receipt) bool {
		key, _ := parseRequestKey(k)
		if key.actor != actor {
			return true
		}
		return fn(key, r)
	})
}

func (s State) actorReports(actor string, fn func(requestKey, reportReceipt) bool) {
	s.reportReceipts.walk(actorPrefix(actor), func(k string, r reportReceipt) bool {
		key, _ := parseRequestKey(k)
		if key.actor != actor {
			return true
		}
		return fn(key, r)
	})
}

func (s State) requestCount(actor string) int {
	count := 0
	s.actorRequests(actor, func(requestKey, receipt) bool { count++; return true })
	return count
}
