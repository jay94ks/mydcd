// SPDX-License-Identifier: Apache-2.0

package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

var ErrSnapshot = errors.New("invalid shared state snapshot")

type objectRow struct {
	Key                  string
	Revision, Generation uint64
	Value                []byte
	Present              bool
}
type principalRow struct {
	Actor     string
	Principal principal
}
type receiptRow struct {
	Actor, ID string
	Digest    [32]byte
	Result    Result
}
type snapshot struct {
	Schema       uint8
	Index        uint64
	Objects      []objectRow
	Principals   []principalRow
	Receipts     []receiptRow
	Window       *moduleWindow      `json:",omitempty"`
	Reports      []reportReceiptRow `json:",omitempty"`
	ReportFloors []reportFloorRow   `json:",omitempty"`
}

// Encode excludes every node-local journal, key and native resource. Sorted rows
// give an unambiguous artifact; this is a snapshot checksum, not a hash chain.
func rows(s State) snapshot {
	d := snapshot{Schema: 1, Index: s.index, Window: s.window}
	d.Reports, d.ReportFloors = reportRows(s)
	for k, v := range s.objects {
		d.Objects = append(d.Objects, objectRow{k, v.Revision, v.Generation, []byte(v.Value), v.Present})
	}
	for k, v := range s.principals {
		d.Principals = append(d.Principals, principalRow{k, v})
	}
	for k, v := range s.requests {
		d.Receipts = append(d.Receipts, receiptRow{k.actor, k.id, v.digest, v.result})
	}
	sort.Slice(d.Objects, func(i, j int) bool { return d.Objects[i].Key < d.Objects[j].Key })
	sort.Slice(d.Principals, func(i, j int) bool { return d.Principals[i].Actor < d.Principals[j].Actor })
	sort.Slice(d.Receipts, func(i, j int) bool {
		a, b := d.Receipts[i], d.Receipts[j]
		return a.Actor < b.Actor || a.Actor == b.Actor && a.ID < b.ID
	})
	return d
}

// EncodeTo streams canonical rows. Wire receive budgets belong to the caller;
// serialization must never impose a hidden limit on committed database state.
func EncodeTo(w io.Writer, s State) error {
	d := rows(s)
	if _, err := fmt.Fprintf(w, `{"Schema":1,"Index":%d,"Objects":`, d.Index); err != nil {
		return err
	}
	if err := writeRows(w, d.Objects); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"Principals":`); err != nil {
		return err
	}
	if err := writeRows(w, d.Principals); err != nil {
		return err
	}
	if _, err := io.WriteString(w, `,"Receipts":`); err != nil {
		return err
	}
	if err := writeRows(w, d.Receipts); err != nil {
		return err
	}
	if d.Window != nil {
		b, err := json.Marshal(d.Window)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(w, `,"Window":`+string(b)); err != nil {
			return err
		}
	}
	if len(d.Reports) != 0 {
		if _, err := io.WriteString(w, `,"Reports":`); err != nil {
			return err
		}
		if err := writeRows(w, d.Reports); err != nil {
			return err
		}
	}
	if len(d.ReportFloors) != 0 {
		if _, err := io.WriteString(w, `,"ReportFloors":`); err != nil {
			return err
		}
		if err := writeRows(w, d.ReportFloors); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, `}`)
	return err
}
func writeRows[T any](w io.Writer, rows []T) error {
	if rows == nil {
		_, err := io.WriteString(w, "null")
		return err
	}
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	for i, row := range rows {
		if i > 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		b, err := json.Marshal(row)
		if err != nil {
			return err
		}
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
	}
	_, err := io.WriteString(w, "]")
	return err
}
func Encode(s State) ([]byte, error) {
	var b bytes.Buffer
	if err := EncodeTo(&b, s); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func Decode(b []byte) (State, error) { return DecodeFrom(bytes.NewReader(b)) }

// DecodeFrom validates the same canonical bytes without keeping a second copy
// of the entire artifact. The caller bounds the source and owns disk/memory I/O.
func DecodeFrom(source io.Reader) (State, error) {
	input := sha256.New()
	source = io.TeeReader(source, input)
	var d snapshot
	decoder := json.NewDecoder(source)
	decoder.DisallowUnknownFields()
	if readDocument(decoder, &d) != nil || decoder.Decode(new(any)) != io.EOF || d.Schema != 1 {
		return State{}, ErrSnapshot
	}
	s := clone(State{})
	s.index = d.Index
	if d.Window != nil {
		w := *d.Window
		if w.Epoch < 2 || !strings.HasPrefix(w.Actor, "user/") || len(w.Actor) > 256 || !utf8.ValidString(w.Actor) || w.ID == "" || len(w.ID) > 256 || !utf8.ValidString(w.ID) || w.Digest == ([32]byte{}) || w.Result.Code != Applied || w.Result.Index == 0 || w.Result.Index > d.Index || w.Result.Revision != w.Result.Index || w.Result.Generation == 0 || w.Result.Generation > w.Result.Index {
			return State{}, ErrSnapshot
		}
		s.window = &w
	}
	admins := 0
	for _, r := range d.Principals {
		if r.Actor == "" || len(r.Actor) > 256 || r.Principal.Epoch == 0 || r.Principal.Revision > d.Index || r.Principal.Rights & ^allRights != 0 {
			return State{}, ErrSnapshot
		}
		if _, ok := s.principals[r.Actor]; ok {
			return State{}, ErrSnapshot
		}
		s.principals[r.Actor] = r.Principal
		if s.window != nil && r.Principal.Rights == 0 && moduleActor(r.Actor) && r.Principal.Epoch != s.ModuleEpoch() {
			return State{}, ErrSnapshot
		}
		if r.Principal.Rights&Admin != 0 {
			admins++
		}
	}
	if admins == 0 {
		return State{}, ErrSnapshot
	}
	for _, r := range d.Objects {
		o := Object{Revision: r.Revision, Generation: r.Generation, Value: string(r.Value), Present: r.Present}
		if r.Key == "" || len(r.Key) > 512 || len(o.Value) > 64*1024 || o.Revision == 0 || o.Revision > d.Index || o.Generation == 0 || o.Generation > o.Revision || !o.Present && o.Value != "" {
			return State{}, ErrSnapshot
		}
		if _, ok := s.objects[r.Key]; ok {
			return State{}, ErrSnapshot
		}
		s.objects[r.Key] = o
	}
	counts := map[string]int{}
	for _, r := range d.Receipts {
		k := requestKey{r.Actor, r.ID}
		_, known := s.principals[r.Actor]
		if !known || r.ID == "" || len(r.ID) > 256 || r.Result.Index == 0 || r.Result.Index > d.Index || !r.Result.ValidReason() || r.Result.Revision > d.Index || r.Result.Generation > d.Index {
			return State{}, ErrSnapshot
		}
		if _, ok := s.requests[k]; ok {
			return State{}, ErrSnapshot
		}
		counts[r.Actor]++
		if counts[r.Actor] > LedgerLimit {
			return State{}, ErrSnapshot
		}
		s.requests[k] = receipt{r.Digest, r.Result}
	}
	if err := restoreReportRows(&s, d.Reports, d.ReportFloors); err != nil {
		return State{}, err
	}
	// Reject duplicate JSON fields, alternate order/number spellings and omitted
	// fields by requiring our one canonical representation.
	canonical := sha256.New()
	if err := EncodeTo(canonical, s); err != nil || !bytes.Equal(input.Sum(nil), canonical.Sum(nil)) {
		return State{}, ErrSnapshot
	}
	return s, nil
}

// Decode rows individually: json.Decoder.Decode on the top-level object would
// buffer the whole snapshot before producing even its first row.
func readDocument(d *json.Decoder, s *snapshot) error {
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return ErrSnapshot
	}
	field := func(name string, target any) error {
		token, err := d.Token()
		if err != nil || token != name {
			return ErrSnapshot
		}
		return d.Decode(target)
	}
	if err = field("Schema", &s.Schema); err != nil {
		return err
	}
	if err = field("Index", &s.Index); err != nil {
		return err
	}
	token, err = d.Token()
	if err != nil || token != "Objects" {
		return ErrSnapshot
	}
	if s.Objects, err = readRows[objectRow](d); err != nil {
		return err
	}
	token, err = d.Token()
	if err != nil || token != "Principals" {
		return ErrSnapshot
	}
	if s.Principals, err = readRows[principalRow](d); err != nil {
		return err
	}
	token, err = d.Token()
	if err != nil || token != "Receipts" {
		return ErrSnapshot
	}
	if s.Receipts, err = readRows[receiptRow](d); err != nil {
		return err
	}
	token, err = d.Token()
	if err == nil && token == "Window" {
		if err = d.Decode(&s.Window); err != nil {
			return err
		}
		token, err = d.Token()
	}
	if err == nil && token == "Reports" {
		if s.Reports, err = readRows[reportReceiptRow](d); err != nil {
			return err
		}
		token, err = d.Token()
	}
	if err == nil && token == "ReportFloors" {
		if s.ReportFloors, err = readRows[reportFloorRow](d); err != nil {
			return err
		}
		token, err = d.Token()
	}
	if err != nil || token != json.Delim('}') {
		return ErrSnapshot
	}
	return nil
}
func readRows[T any](d *json.Decoder) ([]T, error) {
	token, err := d.Token()
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, nil
	}
	if token != json.Delim('[') {
		return nil, ErrSnapshot
	}
	result := make([]T, 0)
	for d.More() {
		var row T
		if err = d.Decode(&row); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	token, err = d.Token()
	if err != nil || token != json.Delim(']') {
		return nil, ErrSnapshot
	}
	return result, nil
}
