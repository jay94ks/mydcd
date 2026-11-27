// SPDX-License-Identifier: Apache-2.0

// Package wire is the SFCP frame codec: the 24-byte header, the TLV body and
// the per-purpose/kind field rules a caller supplies. It imports only the
// standard library, so a program outside this module (the Seafield engine)
// can keep a byte-identical copy and speak the same frames.
//
// Header (little endian): "MDG1" | schema u16 = 1 | purpose u8 | kind u8 |
// reserved u32 = 0 | request u64 | body length u32. Body: fields of
// tag u16 | flags u16 (1 = required) | length u32 | value, tags ascending.
// Tags 1..len(Rule.Fields) are the required fields of that kind, in order;
// tags >= 128 are optional extensions; nothing else is accepted.
package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

const HeaderSize = 24
const MaxBody = 256 << 10

var (
	ErrFrame     = errors.New("invalid SFCP frame")
	ErrBudget    = errors.New("SFCP frame budget exceeded")
	ErrTruncated = errors.New("truncated SFCP frame")
)

type Purpose uint8

type Field struct {
	Tag      uint16
	Required bool
	Value    []byte
}

type Frame struct {
	Purpose Purpose
	Kind    uint8
	Request uint64
	Fields  []Field
}

// Rule is what the codec checks for one purpose/kind. Fields holds the exact
// length of each required field, -1 for any non-zero length. Budget is the
// largest body; zero means the purpose/kind is unknown. NoRequest marks a
// datagram purpose whose request ID is always zero (every other purpose's is
// never zero).
type Rule struct {
	Fields    []int
	Budget    int
	NoRequest bool
}

// Rules looks up the rule of a purpose/kind; ok false means unknown.
type Rules func(p Purpose, kind uint8) (r Rule, ok bool)

func (rules Rules) header(h []byte, limit int) (Frame, Rule, int, error) {
	if string(h[:4]) != "MDG1" || binary.LittleEndian.Uint16(h[4:6]) != 1 || binary.LittleEndian.Uint32(h[8:12]) != 0 {
		return Frame{}, Rule{}, 0, ErrFrame
	}
	f := Frame{Purpose: Purpose(h[6]), Kind: h[7], Request: binary.LittleEndian.Uint64(h[12:20])}
	r, ok := rules(f.Purpose, f.Kind)
	n := uint64(binary.LittleEndian.Uint32(h[20:24]))
	if !ok || r.Budget <= 0 || (f.Request == 0) != r.NoRequest {
		return Frame{}, Rule{}, 0, ErrFrame
	}
	if n > uint64(r.Budget) || n > uint64(limit) {
		return Frame{}, Rule{}, 0, ErrBudget
	}
	return f, r, int(n), nil
}

func parseFields(f Frame, rule Rule, b []byte) (Frame, error) {
	rules := rule.Fields
	previous := uint16(0)
	for len(b) > 0 {
		if len(b) < 8 {
			return Frame{}, ErrFrame
		}
		tag, flags := binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])
		n := uint64(binary.LittleEndian.Uint32(b[4:]))
		b = b[8:]
		if tag <= previous || flags > 1 || n > uint64(len(b)) || len(f.Fields) >= 32 {
			return Frame{}, ErrFrame
		}
		previous = tag
		if int(tag) <= len(rules) {
			want := rules[tag-1]
			if flags != 1 || n == 0 || want >= 0 && n != uint64(want) {
				return Frame{}, ErrFrame
			}
		} else if tag < 128 || flags != 0 {
			return Frame{}, ErrFrame
		}
		f.Fields = append(f.Fields, Field{tag, flags == 1, b[:int(n)]})
		b = b[int(n):]
	}
	if len(f.Fields) < len(rules) {
		return Frame{}, ErrFrame
	}
	for i := range rules {
		if f.Fields[i].Tag != uint16(i+1) {
			return Frame{}, ErrFrame
		}
	}
	return f, nil
}

// Encode returns the bytes of f after checking them as a receiver would.
func (rules Rules) Encode(f Frame) ([]byte, error) {
	b := make([]byte, HeaderSize)
	copy(b, "MDG1")
	binary.LittleEndian.PutUint16(b[4:], 1)
	b[6] = byte(f.Purpose)
	b[7] = f.Kind
	binary.LittleEndian.PutUint64(b[12:], f.Request)
	for _, field := range f.Fields {
		if len(field.Value) > MaxBody || len(b)+8+len(field.Value) > HeaderSize+MaxBody {
			return nil, ErrBudget
		}
		b = binary.LittleEndian.AppendUint16(b, field.Tag)
		flags := uint16(0)
		if field.Required {
			flags = 1
		}
		b = binary.LittleEndian.AppendUint16(b, flags)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(field.Value)))
		b = append(b, field.Value...)
	}
	binary.LittleEndian.PutUint32(b[20:], uint32(len(b)-HeaderSize))
	_, rule, _, err := rules.header(b[:HeaderSize], MaxBody)
	if err != nil {
		return nil, err
	}
	if _, err := parseFields(Frame{Purpose: f.Purpose, Kind: f.Kind}, rule, b[HeaderSize:]); err != nil {
		return nil, err
	}
	return b, nil
}

// ReadFrame reads one frame whose body is at most limit bytes.
func (rules Rules) ReadFrame(r io.Reader, limit int) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}
	f, rule, n, err := rules.header(header[:], limit)
	if err != nil {
		return Frame{}, err
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return Frame{}, err
	}
	return parseFields(f, rule, body)
}

// WriteFrame encodes f and writes all of it.
func (rules Rules) WriteFrame(w io.Writer, f Frame) error {
	b, err := rules.Encode(f)
	if err != nil {
		return err
	}
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// Decoder consumes at most one frame per Feed. The owner controls queued item
// count/deadline separately. Bad input poisons the stream; never resynchronize.
type Decoder struct {
	rules          Rules
	header         [HeaderSize]byte
	hn             int
	body           []byte
	bn             int
	frame          Frame
	rule           Rule
	limit          int
	failed, closed bool
}

func (rules Rules) NewDecoder(limit int) (*Decoder, error) {
	if limit <= 0 || limit > MaxBody {
		return nil, ErrBudget
	}
	return &Decoder{rules: rules, limit: limit}, nil
}

func (d *Decoder) Buffered() int { return d.hn + len(d.body) }

func (d *Decoder) Feed(p []byte) (*Frame, int, error) {
	if d.failed || d.closed {
		return nil, 0, ErrFrame
	}
	used := 0
	if d.hn < HeaderSize {
		n := copy(d.header[d.hn:], p)
		d.hn += n
		used += n
		p = p[n:]
		if d.hn < HeaderSize {
			return nil, used, nil
		}
		f, rule, n, err := d.rules.header(d.header[:], d.limit)
		if err != nil {
			d.failed = true
			return nil, used, err
		}
		d.frame, d.rule = f, rule
		d.body = make([]byte, n)
	}
	n := copy(d.body[d.bn:], p)
	d.bn += n
	used += n
	if d.bn < len(d.body) {
		return nil, used, nil
	}
	f, err := parseFields(d.frame, d.rule, d.body)
	if err != nil {
		d.failed = true
		return nil, used, err
	}
	d.hn = 0
	d.bn = 0
	d.body = nil
	return &f, used, nil
}

func (d *Decoder) Close() error {
	d.closed = true
	if d.failed {
		return ErrFrame
	}
	if d.hn != 0 {
		return ErrTruncated
	}
	return nil
}
