// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
)

// DetailPart is a fragment of one already-redacted canonical JSON snapshot.
// It is not a native Inspect blob or an execution/signed management artifact.
type DetailPart struct {
	Snapshot       string
	Offset, Length int
	Digest         [32]byte
	Data           []byte
}

func (p DetailPart) validate(q Query, next string, truncated bool) error {
	if !ValidLogCursor(p.Snapshot+":1") || p.Length <= q.MaxBytes || p.Length > MaxDetailWindowBytes || p.Offset < 0 || p.Offset >= p.Length || p.Offset%q.MaxBytes != 0 || p.Digest == ([32]byte{}) || len(p.Data) != min(q.MaxBytes, p.Length-p.Offset) {
		return ErrQuery
	}
	if q.Cursor == "" {
		if p.Offset != 0 {
			return ErrQuery
		}
	} else if id, offset, ok := parseLogCursor(q.Cursor); !ok || id != p.Snapshot || offset != p.Offset {
		return ErrQuery
	}
	end := p.Offset + len(p.Data)
	if truncated != (end < p.Length) || end == p.Length && next != "" {
		return ErrQuery
	}
	if end < p.Length {
		if id, offset, ok := parseLogCursor(next); !ok || id != p.Snapshot || offset != end {
			return ErrQuery
		}
	}
	return nil
}

// DetailAssembly is the product client core for joining verified fragments.
// Reordering, changing snapshot/target/time/hash/length or mixing a complete
// detail into the middle never becomes a plausible partial success.
type DetailAssembly struct {
	query    Query
	first    Result
	snapshot string
	digest   [32]byte
	length   int
	data     []byte
	next     string
	complete bool
}

func NewDetailAssembly(q Query) (*DetailAssembly, error) {
	if q.Validate() != nil || q.Kind != "inspect" || q.Cursor != "" {
		return nil, ErrQuery
	}
	return &DetailAssembly{query: q}, nil
}

func (a *DetailAssembly) Accept(q Query, page Result) error {
	if a == nil || a.complete || page.Validate(q, page.Target) != nil || page.DetailCode != "" {
		return ErrQuery
	}
	want := a.query
	want.Cursor = a.next
	if q != want {
		return ErrQuery
	}
	if page.Detail != nil {
		if a.first.Schema != 0 || a.next != "" {
			return ErrQuery
		}
		raw, err := json.Marshal(page.Detail)
		var owned ContainerDetail
		if err != nil || json.Unmarshal(raw, &owned) != nil {
			return ErrQuery
		}
		a.first = page
		a.first.Detail = &owned
		a.complete = true
		return nil
	}
	part := page.DetailPart
	if part == nil || part.Offset != len(a.data) {
		return ErrQuery
	}
	if a.first.Schema == 0 {
		a.first = page
		a.first.DetailPart = nil
		a.first.NextCursor = ""
		a.first.Truncated = false
		a.snapshot, a.digest, a.length = part.Snapshot, part.Digest, part.Length
	} else if part.Snapshot != a.snapshot || part.Digest != a.digest || part.Length != a.length || page.Target != a.first.Target || !page.ObservedAt.Equal(a.first.ObservedAt) || page.TTY != a.first.TTY || page.LogDriver != a.first.LogDriver {
		return ErrQuery
	}
	a.data = append(a.data, part.Data...)
	a.next = page.NextCursor
	a.complete = page.NextCursor == ""
	return nil
}

func (a *DetailAssembly) Next() (Query, bool) {
	if a == nil || a.complete || a.first.Schema == 0 || a.next == "" {
		return Query{}, false
	}
	q := a.query
	q.Cursor = a.next
	return q, true
}

func (a *DetailAssembly) Result() (Result, error) {
	if a == nil || !a.complete {
		return Result{}, ErrQuery
	}
	if a.first.Detail != nil {
		raw, err := json.Marshal(a.first)
		var owned Result
		if err != nil || json.Unmarshal(raw, &owned) != nil {
			return Result{}, ErrQuery
		}
		return owned, nil
	}
	if len(a.data) != a.length || sha256.Sum256(a.data) != a.digest {
		return Result{}, ErrQuery
	}
	var detail ContainerDetail
	d := json.NewDecoder(bytes.NewReader(a.data))
	d.DisallowUnknownFields()
	if d.Decode(&detail) != nil {
		return Result{}, ErrQuery
	}
	canonical, err := json.Marshal(detail)
	if err != nil || !bytes.Equal(canonical, a.data) {
		return Result{}, ErrQuery
	}
	result := a.first
	result.Detail = &detail
	if result.ValidateDetailWindow(a.query, result.Target) != nil {
		return Result{}, ErrQuery
	}
	return result, nil
}

func (a *DetailAssembly) Destroy() {
	if a != nil {
		clear(a.data)
		a.data = nil
		a.complete = true
		a.first = Result{}
	}
}
