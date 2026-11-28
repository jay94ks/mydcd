// SPDX-License-Identifier: Apache-2.0

package state

import (
	"encoding/binary"
	"errors"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

var ErrCommand = errors.New("invalid management command encoding")

const MaxCommand = 66 << 10

// MaxCommandFeatures bounds the features one entry may use.
const MaxCommandFeatures = 16

// EncodeCommand is schema-1 canonical LE encoding, not a Go memory dump. The
// authenticated adapter must match Actor to the connection/caller proof.
//
// An entry that uses features ends with a feature block: a count byte (1 to
// MaxCommandFeatures) and that many 32-bit feature codes, little endian, in
// ascending order (buildinfo.Feature.Code, mainline only). An entry without
// features has no block, so it encodes exactly as before. A build that
// predates the block refuses the trailing bytes and halts its FSM instead of
// applying an entry it does not understand.
func EncodeCommand(c Command) ([]byte, error) {
	if c.Kind > ModuleAppDown || c.Rights & ^allRights != 0 || c.Renew && (c.Delete || c.Kind != Mutate) {
		return nil, ErrCommand
	}
	b := []byte{1, byte(c.Kind), byte(c.Rights), 0}
	if c.Delete {
		b[3] = 1
	}
	if c.Renew {
		b[3] = 2
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
	if !c.Features.Empty() {
		list := c.Features.List()
		if len(list) > MaxCommandFeatures {
			return nil, ErrCommand
		}
		b = append(b, byte(len(list)))
		for _, f := range list {
			if !f.Stable() {
				return nil, ErrCommand
			}
			b = binary.LittleEndian.AppendUint32(b, f.Code())
		}
	}
	return b, nil
}
func DecodeCommand(b []byte) (Command, error) {
	if len(b) < 20 || len(b) > MaxCommand || b[0] != 1 || b[1] > byte(ModuleAppDown) || Rights(b[2]) & ^allRights != 0 || b[3] > 2 || b[3] == 2 && CommandKind(b[1]) != Mutate {
		return Command{}, ErrCommand
	}
	c := Command{Kind: CommandKind(b[1]), Rights: Rights(b[2]), Delete: b[3] == 1, Renew: b[3] == 2, Epoch: binary.LittleEndian.Uint64(b[4:]), Expected: binary.LittleEndian.Uint64(b[12:])}
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
		n := int(b[0])
		if n == 0 || n > MaxCommandFeatures || len(b) != 1+4*n {
			return Command{}, ErrCommand
		}
		list := make([]buildinfo.Feature, n)
		for i := range list {
			code := binary.LittleEndian.Uint32(b[1+4*i:])
			if i > 0 && code <= list[i-1].Code() {
				return Command{}, ErrCommand
			}
			list[i] = buildinfo.FeatureOf(code, "")
		}
		features, ok := buildinfo.NewFeatures(list...)
		if !ok {
			return Command{}, ErrCommand
		}
		c.Features = features
	}
	return c, nil
}
