// SPDX-License-Identifier: Apache-2.0

package mydcp

import (
	"encoding/binary"
	"errors"
)

const HeaderSize = 24
const MaxBody = 256 << 10

var (
	ErrFrame     = errors.New("invalid MYDCP frame")
	ErrBudget    = errors.New("MYDCP frame budget exceeded")
	ErrTruncated = errors.New("truncated MYDCP frame")
)

type Purpose uint8

const (
	Handshake Purpose = iota + 1
	Management
	Raft
	Snapshot
	Observation
	Packet
	PathControl
	User
	Membership
	SecretInput
	SecretFetch
	VolumeTransfer
	CheckerArtifact
	CheckerProbe
	ContainerSession
	ImageContent
	CertificateMaterial
	VolumeFile Purpose = 18
	NodeShell  Purpose = 19
)

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

// Tags are purpose-specific: 1=identity/command/RPC/snapshot metadata/report/
// packet owner, 2=cluster/digest/chunk offset/network, 3=challenge/data/endpoint
// (Packet kind1) or bilateral route flow token (Packet kind2),
// 4=signature/packet bytes. Snapshot kind 1=metadata, 2=chunk, 3=installed ACK.
// Known required tags must occur once and in ascending order. Extensions >=128
// are optional; their bytes still count against the same body budget.
func fieldRule(p Purpose, kind uint8) ([]int, int) {
	switch p {
	case Handshake:
		if kind == 3 {
			return []int{32}, 4096
		}
		if kind == 4 {
			return []int{32, 32, 32, -1, 64}, 4096
		}
		if kind == 1 {
			return []int{32, 32, 32}, 4096
		}
		if kind == 2 {
			return []int{32, 32, 32, 64}, 4096
		}
	case Management:
		if kind >= 1 && kind <= 4 {
			return []int{-1, 32}, 128 * 1024
		}
	case User:
		if kind >= 1 && kind <= 3 {
			return []int{-1, 32}, 128 * 1024
		}
		if kind == 4 {
			// Authenticated bounded user input: offset, data, signed header digest.
			return []int{8, -1, 32}, (24 << 10) + 64
		}
	case VolumeFile:
		if kind == 1 || kind == 2 || kind == 3 {
			return []int{-1, 32}, 128 << 10
		}
		if kind == 4 {
			return []int{8, -1, 32}, (24 << 10) + 64
		}
	case ImageContent:
		if kind >= 1 && kind <= 3 || kind == 5 {
			return []int{-1, 32}, 128 << 10
		}
		if kind == 4 {
			return []int{8, -1, 32}, (24 << 10) + 64
		}
	case NodeShell:
		if kind == 1 || kind == 2 || kind == 3 || kind == 5 {
			return []int{-1, 32}, 128 << 10
		}
	case ContainerSession:
		// 1=user start, 2=accept/reject/target resolution, 3=member relay,
		// Signed target confirmation is the open body; 5=ordered duplex records.
		if kind >= 1 && kind <= 5 && kind != 4 {
			return []int{-1, 32}, 128 << 10
		}
	case CertificateMaterial:
		if kind == 1 || kind == 2 {
			return []int{-1, 32}, 64 << 10
		}
	case SecretFetch:
		if kind == 1 || kind == 2 {
			return []int{-1, 32}, 128 * 1024
		}
	case CheckerArtifact:
		switch kind {
		case 1:
			return []int{-1, 32}, 32 << 10
		case 2:
			return []int{-1, 32}, 24 << 10
		case 3:
			return []int{8, -1, 32}, (24 << 10) + 64
		case 4, 5, 6, 7:
			return []int{32, 32}, 128
		}
	case CheckerProbe:
		switch kind {
		case 1:
			return []int{-1, 32}, 128 << 10
		case 2, 5:
			return []int{8, -1, 32}, (24 << 10) + 64
		case 4:
			return []int{-1, 32}, 2048
		case 3, 6, 7, 8:
			return []int{32, 32}, 128
		}
	case VolumeTransfer:
		switch kind {
		case 1:
			return []int{-1, 32}, 32 << 10
		case 2:
			return []int{8, -1, 32}, (128 << 10) + 64
		case 3:
			return []int{8, 32}, 64
		case 4, 5:
			return []int{8, 32, 32}, 128
		}
	case SecretInput:
		if kind == 1 || kind == 2 {
			return []int{-1, 32}, 64 * 1024
		}
	case Membership:
		if kind == 1 || kind == 2 {
			return []int{-1, 32}, 128 * 1024
		}
	case Raft:
		if kind == 1 {
			return []int{-1}, MaxBody
		}
	case Snapshot:
		if kind == 1 {
			return []int{-1, 32}, 4096
		}
		if kind == 2 {
			return []int{8, -1}, 128*1024 + 32
		}
		if kind == 3 {
			return []int{8, 8, 32}, 128
		}
	case Observation:
		if kind == 1 {
			return []int{-1}, 65536
		}
		if kind == 2 {
			return []int{32}, 128
		}
	case Packet:
		if kind == 1 || kind == 2 {
			return []int{32, 16, 16, -1}, 65535 + 128
		}
	case PathControl:
		if kind == 1 || kind == 2 {
			return []int{-1, 32}, 4096
		}
	}
	return nil, 0
}
func validateHeader(h []byte, limit int) (Frame, int, error) {
	if string(h[:4]) != "MDG1" || binary.LittleEndian.Uint16(h[4:6]) != 1 || binary.LittleEndian.Uint32(h[8:12]) != 0 {
		return Frame{}, 0, ErrFrame
	}
	f := Frame{Purpose: Purpose(h[6]), Kind: h[7], Request: binary.LittleEndian.Uint64(h[12:20])}
	_, cap := fieldRule(f.Purpose, f.Kind)
	n := uint64(binary.LittleEndian.Uint32(h[20:24]))
	if cap == 0 || f.Request == 0 && f.Purpose != Packet || f.Request != 0 && f.Purpose == Packet {
		return Frame{}, 0, ErrFrame
	}
	if n > uint64(cap) || n > uint64(limit) {
		return Frame{}, 0, ErrBudget
	}
	return f, int(n), nil
}
func parseFields(f Frame, b []byte) (Frame, error) {
	rules, _ := fieldRule(f.Purpose, f.Kind)
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
func Encode(f Frame) ([]byte, error) {
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
	if _, _, err := validateHeader(b[:HeaderSize], MaxBody); err != nil {
		return nil, err
	}
	if _, err := parseFields(Frame{Purpose: f.Purpose, Kind: f.Kind}, b[HeaderSize:]); err != nil {
		return nil, err
	}
	return b, nil
}

// Decoder consumes at most one frame per Feed. The owner controls queued item
// count/deadline separately. Bad input poisons the stream; never resynchronize.
type Decoder struct {
	header         [HeaderSize]byte
	hn             int
	body           []byte
	bn             int
	frame          Frame
	limit          int
	failed, closed bool
}

func NewDecoder(limit int) (*Decoder, error) {
	if limit <= 0 || limit > MaxBody {
		return nil, ErrBudget
	}
	return &Decoder{limit: limit}, nil
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
		f, n, err := validateHeader(d.header[:], d.limit)
		if err != nil {
			d.failed = true
			return nil, used, err
		}
		d.frame = f
		d.body = make([]byte, n)
	}
	n := copy(d.body[d.bn:], p)
	d.bn += n
	used += n
	if d.bn < len(d.body) {
		return nil, used, nil
	}
	f, err := parseFields(d.frame, d.body)
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
