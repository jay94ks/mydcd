// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// NewID returns a new request ID: 16 lower-case hex characters starting
// with a letter, so it is also a valid server operation ID. The CLI
// makes one per change and saves it before sending, so a lost reply is
// settled with the same ID (sfcli op show/resume), never a new one.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	b[0] = (0xa+(b[0]>>4)%6)<<4 | b[0]&0x0f // first hex digit a..f
	return hex.EncodeToString(b[:])
}

// ValidID reports whether s can name an operation. It is the server's
// operation ID grammar: 1..63 characters of a-z, 0-9 and '-', starting with
// a letter. Scripts may choose their own ID with --id.
func ValidID(s string) bool {
	if s == "" || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// IDFlag is the --id option. Get returns the given ID or a new one.
type IDFlag struct{ v string }

func (f *IDFlag) String() string { return f.v }
func (f *IDFlag) Set(s string) error {
	if !ValidID(s) {
		return errors.New("id must be 1-63 characters of a-z, 0-9 and '-', starting with a letter")
	}
	f.v = s
	return nil
}

// Get returns the ID chosen with --id, or a new one.
func (f *IDFlag) Get() string {
	if f.v == "" {
		return NewID()
	}
	return f.v
}

// RevisionFlag is the --if-revision option. Without it the command reads
// the current revision just before sending; with it the change applies only
// if the record is still at that revision.
type RevisionFlag struct {
	v   uint64
	set bool
}

func (f *RevisionFlag) String() string {
	if !f.set {
		return ""
	}
	return strconv.FormatUint(f.v, 10)
}

func (f *RevisionFlag) Set(s string) error {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return errors.New("revision must be a whole number")
	}
	f.v, f.set = v, true
	return nil
}

// Resolve returns the explicit revision, or calls current.
func (f *RevisionFlag) Resolve(current func() (uint64, error)) (uint64, error) {
	if f.set {
		return f.v, nil
	}
	return current()
}

// Size is a byte count written as 512, 64KiB, 10MiB, 2GiB or 1TiB
// (KB/MB/GB/TB are accepted as the same powers of 1024).
type Size uint64

var sizeUnits = []struct {
	suffix string
	shift  uint
}{
	{"TiB", 40}, {"GiB", 30}, {"MiB", 20}, {"KiB", 10},
	{"TB", 40}, {"GB", 30}, {"MB", 20}, {"KB", 10},
	{"T", 40}, {"G", 30}, {"M", 20}, {"K", 10}, {"B", 0},
}

// ParseSize reads a Size.
func ParseSize(s string) (Size, error) {
	text := strings.TrimSpace(s)
	shift := uint(0)
	for _, u := range sizeUnits {
		if strings.HasSuffix(strings.ToUpper(text), strings.ToUpper(u.suffix)) {
			text, shift = strings.TrimSpace(text[:len(text)-len(u.suffix)]), u.shift
			break
		}
	}
	if text == "" {
		return 0, fmt.Errorf("size %q needs a number, such as 2GiB", s)
	}
	if n, err := strconv.ParseUint(text, 10, 64); err == nil {
		if shift > 0 && n > math.MaxUint64>>shift {
			return 0, fmt.Errorf("size %q is too large", s)
		}
		return Size(n << shift), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || f < 0 || math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("size %q must look like 512, 64KiB or 2GiB", s)
	}
	v := f * float64(uint64(1)<<shift)
	if v >= math.MaxUint64 {
		return 0, fmt.Errorf("size %q is too large", s)
	}
	return Size(v), nil
}

// String prints the largest exact binary unit, such as 2GiB or 1536KiB.
func (s Size) String() string {
	for _, u := range sizeUnits[:4] {
		if s != 0 && uint64(s)%(1<<u.shift) == 0 {
			return strconv.FormatUint(uint64(s)>>u.shift, 10) + u.suffix
		}
	}
	return strconv.FormatUint(uint64(s), 10) + "B"
}

// Set makes *Size an option value.
func (s *Size) Set(text string) error {
	v, err := ParseSize(text)
	if err != nil {
		return err
	}
	*s = v
	return nil
}
