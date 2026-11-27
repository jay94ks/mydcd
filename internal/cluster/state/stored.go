// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
)

// Stored form: the FSM keeps one database row per object, request receipt
// and report receipt, plus one small head row (index, principals, window,
// report floors). An apply rewrites only the rows it touched and the head.
// The Raft snapshot keeps the single canonical stream of snapshot.go.
const (
	StoredPrefix   = "fsm/"
	storedObjects  = StoredPrefix + "o/"
	storedRequests = StoredPrefix + "r/"
	storedReports  = StoredPrefix + "p/"
)

type storedHead struct {
	Schema       uint8
	Index        uint64
	Principals   []principalRow
	Window       *moduleWindow    `json:",omitempty"`
	ReportFloors []reportFloorRow `json:",omitempty"`
}

// Changes is a set of rows to rewrite. The FSM merges the Changes of each
// applied candidate until they are written.
type Changes struct {
	objects, requests, reports map[string]struct{}
}

func NewChanges() *Changes {
	return &Changes{objects: map[string]struct{}{}, requests: map[string]struct{}{}, reports: map[string]struct{}{}}
}

func (c *Changes) Len() int { return len(c.objects) + len(c.requests) + len(c.reports) }

// Add merges the rows the apply that produced s wrote.
func (c *Changes) Add(s State) {
	if s.touched == nil {
		return
	}
	for k := range s.touched.objects {
		c.objects[k] = struct{}{}
	}
	for k := range s.touched.requests {
		c.requests[k] = struct{}{}
	}
	for k := range s.touched.reports {
		c.reports[k] = struct{}{}
	}
}

// AddAll marks every row of s, for a rewrite after a snapshot restore. Rows
// of the old stored state must be added too, so missing ones are deleted.
func (c *Changes) AddAll(s State) {
	s.objects.walk("", func(k string, _ Object) bool { c.objects[k] = struct{}{}; return true })
	s.requests.walk("", func(k string, _ receipt) bool { c.requests[k] = struct{}{}; return true })
	s.reportReceipts.walk("", func(k string, _ reportReceipt) bool { c.reports[k] = struct{}{}; return true })
}

// StoredWrites returns the rows to put (nil = delete) for the changed keys
// of s and its head row. The caller writes them in one transaction with
// its own Raft position.
func StoredWrites(s State, c *Changes, writes map[string][]byte) (head []byte, err error) {
	for k := range c.objects {
		o, ok := s.objects.get(k)
		if !ok {
			writes[storedObjects+k] = nil
			continue
		}
		if writes[storedObjects+k], err = json.Marshal(objectRow{k, o.Revision, o.Generation, []byte(o.Value), o.Present}); err != nil {
			return nil, err
		}
	}
	for k := range c.requests {
		r, ok := s.requests.get(k)
		if !ok {
			writes[storedRequests+k] = nil
			continue
		}
		key, _ := parseRequestKey(k)
		if writes[storedRequests+k], err = json.Marshal(receiptRow{key.actor, key.id, r.digest, r.result}); err != nil {
			return nil, err
		}
	}
	for k := range c.reports {
		r, ok := s.reportReceipts.get(k)
		if !ok {
			writes[storedReports+k] = nil
			continue
		}
		key, _ := parseRequestKey(k)
		if writes[storedReports+k], err = json.Marshal(reportReceiptRow{key.actor, key.id, r.Key, r.Expected}); err != nil {
			return nil, err
		}
	}
	h := storedHead{Schema: 1, Index: s.index, Window: s.window}
	for k, v := range s.principals {
		h.Principals = append(h.Principals, principalRow{k, v})
	}
	sort.Slice(h.Principals, func(i, j int) bool { return h.Principals[i].Actor < h.Principals[j].Actor })
	_, h.ReportFloors = reportRows(s)
	return json.Marshal(h)
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.More() {
		return ErrSnapshot
	}
	return nil
}

// DecodeStored rebuilds and checks a State from its head and every row under
// StoredPrefix. Each row must sit under its own key.
func DecodeStored(head []byte, rows map[string][]byte) (State, error) {
	var h storedHead
	if strictJSON(head, &h) != nil || h.Schema != 1 {
		return State{}, ErrSnapshot
	}
	d := snapshot{Schema: 1, Index: h.Index, Principals: h.Principals, Window: h.Window, ReportFloors: h.ReportFloors}
	for key, raw := range rows {
		switch {
		case strings.HasPrefix(key, storedObjects):
			var r objectRow
			if strictJSON(raw, &r) != nil || storedObjects+r.Key != key {
				return State{}, ErrSnapshot
			}
			d.Objects = append(d.Objects, r)
		case strings.HasPrefix(key, storedRequests):
			var r receiptRow
			if strictJSON(raw, &r) != nil || storedRequests+(requestKey{r.Actor, r.ID}).String() != key {
				return State{}, ErrSnapshot
			}
			d.Receipts = append(d.Receipts, r)
		case strings.HasPrefix(key, storedReports):
			var r reportReceiptRow
			if strictJSON(raw, &r) != nil || storedReports+(requestKey{r.Actor, r.ID}).String() != key {
				return State{}, ErrSnapshot
			}
			d.Reports = append(d.Reports, r)
		default:
			return State{}, ErrSnapshot
		}
	}
	// Floors check against receipts, so receipts load in their canonical order.
	sort.Slice(d.Reports, func(i, j int) bool {
		a, b := d.Reports[i], d.Reports[j]
		return a.Actor < b.Actor || a.Actor == b.Actor && a.ID < b.ID
	})
	return fromRows(d)
}
