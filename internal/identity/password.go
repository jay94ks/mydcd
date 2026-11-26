// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var ErrCredential = errors.New("invalid protected credential or input")

type PasswordCost struct {
	Memory, Iterations uint32
	Threads            uint8
}

// PasswordVerifier is private provider material, never a Shared record. Cost
// is bounded before KDF allocation, including when read from protected storage.
type PasswordVerifier struct {
	cost      PasswordCost
	salt, key []byte
}

func DefaultPasswordCost() PasswordCost {
	return PasswordCost{Memory: 64 * 1024, Iterations: 2, Threads: 1}
}
func validPasswordCost(c PasswordCost) bool {
	return c.Memory >= 8*1024 && c.Memory <= 64*1024 && c.Iterations >= 1 && c.Iterations <= 3 && c.Threads >= 1 && c.Threads <= 2
}
func PasswordHash(password, salt []byte, cost PasswordCost) (PasswordVerifier, error) {
	if len(password) == 0 || len(password) > 1024 || len(salt) < 16 || len(salt) > 32 || !validPasswordCost(cost) {
		return PasswordVerifier{}, ErrCredential
	}
	salt = slices.Clone(salt)
	key := argon2.IDKey(password, salt, cost.Iterations, cost.Memory, cost.Threads, 32)
	return PasswordVerifier{cost, salt, key}, nil
}
func (v PasswordVerifier) Verify(password []byte) bool {
	if len(v.key) != 32 || len(v.salt) < 16 || len(v.salt) > 32 || !validPasswordCost(v.cost) || len(password) == 0 || len(password) > 1024 {
		return false
	}
	key := argon2.IDKey(password, v.salt, v.cost.Iterations, v.cost.Memory, v.cost.Threads, 32)
	ok := subtle.ConstantTimeCompare(key, v.key) == 1
	clear(key)
	return ok
}
func (PasswordVerifier) MarshalJSON() ([]byte, error) { return nil, ErrCredential }
func (PasswordVerifier) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted password verifier]")
}

// ProtectedBytes is only for the private verifier provider, never the public
// credential record. Its independent format and Argon version are explicit.
func (v PasswordVerifier) ProtectedBytes() ([]byte, error) {
	if !validPasswordCost(v.cost) || len(v.key) != 32 || len(v.salt) < 16 || len(v.salt) > 32 {
		return nil, ErrCredential
	}
	raw := []byte("MDPV")
	for _, n := range []uint32{1, argon2.Version, v.cost.Memory, v.cost.Iterations} {
		raw = binary.LittleEndian.AppendUint32(raw, n)
	}
	raw = append(raw, v.cost.Threads, byte(len(v.salt)))
	raw = append(raw, v.salt...)
	raw = append(raw, v.key...)
	return raw, nil
}
func RestorePasswordVerifier(raw []byte) (PasswordVerifier, error) {
	if len(raw) < 70 || len(raw) > 86 || string(raw[:4]) != "MDPV" || binary.LittleEndian.Uint32(raw[4:]) != 1 || binary.LittleEndian.Uint32(raw[8:]) != argon2.Version {
		return PasswordVerifier{}, ErrCredential
	}
	c := PasswordCost{Memory: binary.LittleEndian.Uint32(raw[12:]), Iterations: binary.LittleEndian.Uint32(raw[16:]), Threads: raw[20]}
	n := int(raw[21])
	if n < 16 || n > 32 || len(raw) != 22+n+32 || !validPasswordCost(c) {
		return PasswordVerifier{}, ErrCredential
	}
	return PasswordVerifier{c, slices.Clone(raw[22 : 22+n]), slices.Clone(raw[22+n:])}, nil
}

// ReadPassword uses the maintained terminal implementation. No echoed stdin
// fallback, argv or environment password is accepted by this input boundary.
func ReadPassword(fd int) ([]byte, error) {
	if !term.IsTerminal(fd) {
		return nil, ErrCredential
	}
	value, err := term.ReadPassword(fd)
	if err != nil || len(value) == 0 || len(value) > 1024 {
		clear(value)
		return nil, ErrCredential
	}
	return value, nil
}
