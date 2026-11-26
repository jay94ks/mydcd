// SPDX-License-Identifier: Apache-2.0

// Package wallet owns the CLI-local encrypted wallet format. Codec operations
// are independent of filesystem I/O, passphrase input, KDF, and encryption.
package wallet

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cliprofile"
)

const (
	HeaderSize     = 50
	MaxFileBytes   = 1 << 20
	MaxEntries     = 4096
	MaxRecordBytes = 64 << 10
	MemoryKiB      = 65536
	Iterations     = 2
	Threads        = 1
)

var ErrWallet = errors.New("invalid or unavailable private wallet")

const magic = "MYDCWLT1"

type Header struct {
	Salt         [16]byte
	Nonce        [12]byte
	CipherLength uint32
}

func (h Header) Encode() ([]byte, error) {
	if h.CipherLength < 20 || h.CipherLength > MaxFileBytes-HeaderSize {
		return nil, ErrWallet
	}
	raw := make([]byte, HeaderSize)
	copy(raw, magic)
	raw[8] = 1
	binary.BigEndian.PutUint32(raw[9:13], MemoryKiB)
	binary.BigEndian.PutUint32(raw[13:17], Iterations)
	raw[17] = Threads
	copy(raw[18:34], h.Salt[:])
	copy(raw[34:46], h.Nonce[:])
	binary.BigEndian.PutUint32(raw[46:50], h.CipherLength)
	return raw, nil
}

// DecodeHeader validates cost/size before a caller allocates memory or runs the
// KDF. The full envelope, including its exact ciphertext length, is required.
func DecodeHeader(raw []byte) (Header, error) {
	if len(raw) < HeaderSize+20 || len(raw) > MaxFileBytes || string(raw[:8]) != magic || raw[8] != 1 || binary.BigEndian.Uint32(raw[9:13]) != MemoryKiB || binary.BigEndian.Uint32(raw[13:17]) != Iterations || raw[17] != Threads {
		return Header{}, ErrWallet
	}
	var h Header
	copy(h.Salt[:], raw[18:34])
	copy(h.Nonce[:], raw[34:46])
	h.CipherLength = binary.BigEndian.Uint32(raw[46:50])
	if h.CipherLength < 20 || uint64(h.CipherLength) != uint64(len(raw)-HeaderSize) {
		return Header{}, ErrWallet
	}
	return h, nil
}

type Entry struct {
	Name string
	Seed [32]byte
	// Record is a private credential payload (type2), mutually exclusive with
	// a key seed (type1). The owning authentication package validates its schema.
	Record []byte
}

func (e Entry) Clone() Entry { e.Record = bytes.Clone(e.Record); return e }
func (e Entry) IsKey() bool  { return e.Record == nil }

func (Entry) MarshalJSON() ([]byte, error) { return nil, ErrWallet }
func (Entry) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[redacted wallet entry]") }
func (e Entry) Public() [32]byte {
	if !e.IsKey() {
		return [32]byte{}
	}
	key := ed25519.NewKeyFromSeed(e.Seed[:])
	defer clear(key)
	var public [32]byte
	copy(public[:], key[ed25519.SeedSize:])
	return public
}
func Clear(entries []Entry) {
	for i := range entries {
		clear(entries[i].Seed[:])
		clear(entries[i].Record)
	}
	clear(entries)
}

// EncodePayload canonicalizes names, not key material. Aliases may refer to the
// same actual key; original signer identity is independent of the display name.
func EncodePayload(entries []Entry) ([]byte, error) {
	if len(entries) > MaxEntries {
		return nil, ErrWallet
	}
	length := 4
	for _, e := range entries {
		if !cliprofile.ValidKeyName(e.Name) {
			return nil, ErrWallet
		}
		length += 2 + len(e.Name) + 1
		if e.IsKey() {
			length += 32
		} else {
			if len(e.Record) == 0 || len(e.Record) > MaxRecordBytes || e.Seed != [32]byte{} {
				return nil, ErrWallet
			}
			length += 4 + len(e.Record)
		}
		if length > MaxFileBytes-HeaderSize-16 {
			return nil, ErrWallet
		}
	}
	sorted := make([]Entry, len(entries))
	for i := range entries {
		sorted[i] = entries[i].Clone()
	}
	defer Clear(sorted)
	slices.SortFunc(sorted, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Name == sorted[i].Name {
			return nil, ErrWallet
		}
	}
	raw := make([]byte, length)
	binary.BigEndian.PutUint32(raw, uint32(len(sorted)))
	offset := 4
	for _, e := range sorted {
		binary.BigEndian.PutUint16(raw[offset:], uint16(len(e.Name)))
		offset += 2
		copy(raw[offset:], e.Name)
		offset += len(e.Name)
		if e.IsKey() {
			raw[offset] = 1
			offset++
			copy(raw[offset:], e.Seed[:])
			offset += 32
		} else {
			raw[offset] = 2
			offset++
			binary.BigEndian.PutUint32(raw[offset:], uint32(len(e.Record)))
			offset += 4
			copy(raw[offset:], e.Record)
			offset += len(e.Record)
		}
	}
	return raw, nil
}
func DecodePayload(raw []byte) (entries []Entry, err error) {
	if len(raw) < 4 || len(raw) > MaxFileBytes-HeaderSize-16 {
		return nil, ErrWallet
	}
	count := binary.BigEndian.Uint32(raw)
	if count > MaxEntries || uint64(count)*9 > uint64(len(raw)-4) {
		return nil, ErrWallet
	}
	entries = make([]Entry, 0, count)
	defer func() {
		if err != nil {
			Clear(entries)
			entries = nil
		}
	}()
	offset := 4
	for range count {
		if len(raw)-offset < 2 {
			return entries, ErrWallet
		}
		n := int(binary.BigEndian.Uint16(raw[offset:]))
		offset += 2
		if n < 1 || n > 128 || len(raw)-offset < n+1 {
			return entries, ErrWallet
		}
		name := string(raw[offset : offset+n])
		offset += n
		if !cliprofile.ValidKeyName(name) || len(entries) > 0 && entries[len(entries)-1].Name >= name {
			return entries, ErrWallet
		}
		kind := raw[offset]
		offset++
		entry := Entry{Name: name}
		switch kind {
		case 1:
			if len(raw)-offset < 32 {
				return entries, ErrWallet
			}
			copy(entry.Seed[:], raw[offset:offset+32])
			offset += 32
		case 2:
			if len(raw)-offset < 4 {
				return entries, ErrWallet
			}
			size := uint64(binary.BigEndian.Uint32(raw[offset:]))
			offset += 4
			if size == 0 || size > MaxRecordBytes || size > uint64(len(raw)-offset) {
				return entries, ErrWallet
			}
			entry.Record = bytes.Clone(raw[offset : offset+int(size)])
			offset += int(size)
		default:
			return entries, ErrWallet
		}
		entries = append(entries, entry)
		clear(entry.Seed[:])
	}
	if offset != len(raw) {
		return entries, ErrWallet
	}
	return entries, nil
}
