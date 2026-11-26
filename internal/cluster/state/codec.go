// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/binary"
	"errors"
)

var ErrCommand = errors.New("invalid management command encoding")

const MaxCommand = 66 << 10

// EncodeCommand is schema-1 canonical LE encoding, not a Go memory dump. The
// authenticated adapter must match Actor to the connection/caller proof.
func EncodeCommand(c Command) ([]byte, error) {
	if c.Kind > ModuleAppDown || c.Rights & ^allRights != 0 {
		return nil, ErrCommand
	}
	b := []byte{1, byte(c.Kind), byte(c.Rights), 0}
	if c.Delete {
		b[3] = 1
	}
	b = binary.LittleEndian.AppendUint64(b, c.Epoch)
	b = binary.LittleEndian.AppendUint64(b, c.Expected)
	for i, s := range []string{c.Actor, c.RequestID, c.Key, c.Value, c.Target} {
		cap := 256
		if i == 2 {
			cap = 512
		}
		if i == 3 {
			cap = 64 * 1024
		}
		if len(s) > cap {
			return nil, ErrCommand
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(len(s)))
		b = append(b, s...)
	}
	return b, nil
}
func DecodeCommand(b []byte) (Command, error) {
	if len(b) < 20 || len(b) > MaxCommand || b[0] != 1 || b[1] > byte(ModuleAppDown) || Rights(b[2]) & ^allRights != 0 || b[3] > 1 {
		return Command{}, ErrCommand
	}
	c := Command{Kind: CommandKind(b[1]), Rights: Rights(b[2]), Delete: b[3] == 1, Epoch: binary.LittleEndian.Uint64(b[4:]), Expected: binary.LittleEndian.Uint64(b[12:])}
	b = b[20:]
	fields := []*string{&c.Actor, &c.RequestID, &c.Key, &c.Value, &c.Target}
	for i, f := range fields {
		if len(b) < 4 {
			return Command{}, ErrCommand
		}
		n := uint64(binary.LittleEndian.Uint32(b))
		b = b[4:]
		cap := uint64(256)
		if i == 2 {
			cap = 512
		}
		if i == 3 {
			cap = 64 * 1024
		}
		if n > cap || n > uint64(len(b)) {
			return Command{}, ErrCommand
		}
		*f = string(b[:int(n)])
		b = b[int(n):]
	}
	if len(b) != 0 {
		return Command{}, ErrCommand
	}
	return c, nil
}
