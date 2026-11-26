// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrRedaction = errors.New("secret redaction material unavailable or exceeds budget")

const MaxRedactionBytes = 8 << 20

// RedactionValue is transient private material loaded from an original Task's
// verified projection. No value, digest or matcher state is a public cursor.
type RedactionValue struct {
	Reference string
	Value     []byte
}

func (RedactionValue) MarshalJSON() ([]byte, error) { return nil, ErrRedaction }
func (RedactionValue) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted log filter value]")
}

type redactionPattern struct {
	value   []byte
	fail    []uint32
	label   []byte
	matched int
}

type redactionSpan struct {
	start, end int
	label      []byte
}

// Redactor is a per-stream KMP matcher. Pending prefixes stay private across
// Docker frames and network chunks. Overlapping matches hide their union;
// output limits are applied AFTER filtering, never to unfiltered fragments.
type Redactor struct {
	destination io.Writer
	patterns    []redactionPattern
	pending     []byte
	spans       []redactionSpan
	head        int
	inMask      bool
	closed      bool
	borrowed    bool
}

func (Redactor) MarshalJSON() ([]byte, error) { return nil, ErrRedaction }
func (Redactor) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted log filter]")
}

func NewRedactor(destination io.Writer, values []RedactionValue) (*Redactor, error) {
	if destination == nil || len(values) > 256 {
		return nil, ErrRedaction
	}
	r := &Redactor{destination: destination}
	total := 0
	for _, v := range values {
		if len(v.Reference) > 512 || !utf8.ValidString(v.Reference) || strings.ContainsAny(v.Reference, "\x00\r\n«»") || len(v.Value) > MaxRedactionBytes-total {
			r.Destroy()
			return nil, ErrRedaction
		}
		total += len(v.Value)
		if len(v.Value) == 0 || slices.ContainsFunc(r.patterns, func(p redactionPattern) bool { return bytes.Equal(p.value, v.Value) }) {
			continue
		}
		label := v.Reference
		if label == "" {
			label = "secret"
		}
		p := redactionPattern{value: bytes.Clone(v.Value), fail: make([]uint32, len(v.Value)), label: []byte("«가림: " + label + "»")}
		for i, j := 1, 0; i < len(p.value); i++ {
			for j > 0 && p.value[i] != p.value[j] {
				j = int(p.fail[j-1])
			}
			if p.value[i] == p.value[j] {
				j++
			}
			p.fail[i] = uint32(j)
		}
		r.patterns = append(r.patterns, p)
	}
	return r, nil
}

// Fork uses the same destination and patterns with independent stream state.
// stdout/stderr must not interrupt each other's partial Secret matches. Each
// fork owns its copies, so destroying either stream cannot erase the other's
// filter. Writes to the shared destination must be serialized by the caller.
func (r *Redactor) Fork() (*Redactor, error) {
	if r == nil || r.closed {
		return nil, ErrRedaction
	}
	child := &Redactor{destination: r.destination, patterns: slices.Clone(r.patterns)}
	for i := range child.patterns {
		p := &child.patterns[i]
		p.value = bytes.Clone(p.value)
		p.fail = slices.Clone(p.fail)
		p.label = bytes.Clone(p.label)
		p.matched = 0
	}
	return child, nil
}

// BorrowStream keeps independent prefix state while borrowing the parent's
// immutable compiled patterns. The caller must serialize destination writes
// and destroy every borrowed stream before destroying the parent. Finite SDK
// sessions use this to avoid copying all Secret bytes for every vertex/stream.
func (r *Redactor) BorrowStream() (*Redactor, error) {
	if r == nil || r.closed {
		return nil, ErrRedaction
	}
	child := &Redactor{destination: r.destination, patterns: slices.Clone(r.patterns), borrowed: true}
	for i := range child.patterns {
		child.patterns[i].matched = 0
	}
	return child, nil
}

func (r *Redactor) Write(raw []byte) (int, error) {
	if r == nil || r.closed {
		return 0, ErrRedaction
	}
	var output []byte
	for _, b := range raw {
		r.pending = append(r.pending, b)
		keep := 0
		for i := range r.patterns {
			p := &r.patterns[i]
			for p.matched > 0 && b != p.value[p.matched] {
				p.matched = int(p.fail[p.matched-1])
			}
			if b == p.value[p.matched] {
				p.matched++
			}
			if p.matched == len(p.value) {
				start := len(r.pending) - len(p.value)
				r.mask(start, len(r.pending), p.label)
				p.matched = int(p.fail[p.matched-1])
			}
			keep = max(keep, p.matched)
		}
		output = r.flush(output, len(r.pending)-keep)
	}
	// Discard flushed plaintext while retaining only a possible secret prefix.
	clear(r.pending[:r.head])
	r.pending = append(r.pending[:0], r.pending[r.head:]...)
	kept := r.spans[:0]
	for _, span := range r.spans {
		if span.end > r.head {
			span.start = max(0, span.start-r.head)
			span.end -= r.head
			kept = append(kept, span)
		}
	}
	r.spans = kept
	r.head = 0
	n, err := r.destination.Write(output)
	clear(output)
	if err != nil || n != len(output) {
		r.closed = true
		if err == nil {
			err = io.ErrShortWrite
		}
		return len(raw), err
	}
	return len(raw), nil
}

func (r *Redactor) mask(start, end int, label []byte) {
	start = max(start, r.head)
	for len(r.spans) > 0 && r.spans[len(r.spans)-1].end >= start {
		old := r.spans[len(r.spans)-1]
		start = min(start, old.start)
		label = old.label
		r.spans = r.spans[:len(r.spans)-1]
	}
	r.spans = append(r.spans, redactionSpan{start, end, label})
}
func (r *Redactor) flush(output []byte, end int) []byte {
	for r.head < end {
		for len(r.spans) > 0 && r.spans[0].end <= r.head {
			r.spans = r.spans[1:]
		}
		if len(r.spans) > 0 && r.spans[0].start <= r.head {
			if !r.inMask {
				output = append(output, r.spans[0].label...)
			}
			r.inMask = true
			r.head = min(end, r.spans[0].end)
		} else {
			stop := end
			if len(r.spans) > 0 {
				stop = min(stop, r.spans[0].start)
			}
			output = append(output, r.pending[r.head:stop]...)
			r.head = stop
			r.inMask = false
		}
	}
	return output
}

// Finish masks a trailing partial secret too. An EOF after a truncated source
// must not disclose a recognizable prefix. Cancellation/errors use Destroy
// directly and never flush private pending bytes.
func (r *Redactor) Finish() error {
	if r == nil || r.closed {
		return ErrRedaction
	}
	if r.head < len(r.pending) {
		label := []byte("«가림: secret»")
		longest := 0
		for _, pattern := range r.patterns {
			if pattern.matched > longest {
				longest, label = pattern.matched, pattern.label
			}
		}
		r.mask(r.head, len(r.pending), label)
	}
	output := r.flush(nil, len(r.pending))
	n, err := r.destination.Write(output)
	if err == nil && n != len(output) {
		err = io.ErrShortWrite
	}
	clear(output)
	r.closed = true
	return err
}

func (r *Redactor) Destroy() {
	if r == nil {
		return
	}
	if !r.borrowed {
		for i := range r.patterns {
			clear(r.patterns[i].value)
			clear(r.patterns[i].fail)
		}
	}
	clear(r.pending)
	r.patterns = nil
	r.pending = nil
	r.spans = nil
	r.closed = true
}

// RedactString reuses this filter's immutable compiled patterns for one
// complete display field. Independent prefix state never crosses fields.
// The parent must remain alive until this synchronous call returns.
func (r *Redactor) RedactString(value string) (string, error) {
	if r == nil || r.closed || len(value) > MaxRedactionBytes {
		return "", ErrRedaction
	}
	var output bytes.Buffer
	child := &Redactor{destination: &output, patterns: slices.Clone(r.patterns), borrowed: true}
	for i := range child.patterns {
		child.patterns[i].matched = 0
	}
	defer child.Destroy()
	if _, err := child.Write([]byte(value)); err != nil {
		return "", err
	}
	if err := child.Finish(); err != nil {
		return "", err
	}
	return output.String(), nil
}
