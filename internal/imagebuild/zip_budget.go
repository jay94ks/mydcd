// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"bytes"
	"encoding/binary"
	"io"
)

const maxZIPDirectoryBytes = 16 << 20

// checkZIPBudget checks only allocation/directory bounds before archive/zip
// parses anything. The standard reader preallocates from an untrusted record
// count and otherwise enumerates every central record before callers can cap
// len(File). This bounded header walk prevents a 500 MB metadata-only ZIP from
// causing millions of allocations. archive/zip remains the actual decoder.
func checkZIPBudget(reader io.ReaderAt, length int64) error {
	if length < 22 {
		return ErrInvalid
	}
	tail := make([]byte, min(length, 22+65535))
	if n, err := reader.ReadAt(tail, length-int64(len(tail))); err != nil || n != len(tail) {
		return ErrInvalid
	}
	end := -1
	for index := len(tail) - 22; index >= 0; index-- {
		if bytes.Equal(tail[index:index+4], []byte{'P', 'K', 5, 6}) && index+22+int(binary.LittleEndian.Uint16(tail[index+20:])) == len(tail) {
			end = index
			break
		}
	}
	if end < 0 {
		return ErrInvalid
	}
	header := tail[end:]
	if binary.LittleEndian.Uint16(header[4:]) != 0 || binary.LittleEndian.Uint16(header[6:]) != 0 || binary.LittleEndian.Uint16(header[8:]) != binary.LittleEndian.Uint16(header[10:]) {
		return ErrInvalid
	}
	count := uint64(binary.LittleEndian.Uint16(header[10:]))
	size := uint64(binary.LittleEndian.Uint32(header[12:]))
	offset := uint64(binary.LittleEndian.Uint32(header[16:]))
	directoryEnd := uint64(length - int64(len(tail)) + int64(end))
	if count == 0xffff || size == 0xffffffff || offset == 0xffffffff {
		if directoryEnd < 20 {
			return ErrInvalid
		}
		var locator [20]byte
		if n, err := reader.ReadAt(locator[:], int64(directoryEnd)-20); err != nil || n != len(locator) || binary.LittleEndian.Uint32(locator[:]) != 0x07064b50 || binary.LittleEndian.Uint32(locator[4:]) != 0 || binary.LittleEndian.Uint32(locator[16:]) != 1 {
			return ErrInvalid
		}
		zip64Offset := binary.LittleEndian.Uint64(locator[8:])
		if zip64Offset > directoryEnd-20 || directoryEnd-20-zip64Offset < 56 {
			return ErrInvalid
		}
		var extended [56]byte
		if n, err := reader.ReadAt(extended[:], int64(zip64Offset)); err != nil || n != len(extended) || binary.LittleEndian.Uint32(extended[:]) != 0x06064b50 {
			return ErrInvalid
		}
		recordSize := binary.LittleEndian.Uint64(extended[4:])
		if recordSize < 44 || recordSize > maxZIPDirectoryBytes || zip64Offset+12+recordSize != directoryEnd-20 || binary.LittleEndian.Uint32(extended[16:]) != 0 || binary.LittleEndian.Uint32(extended[20:]) != 0 || binary.LittleEndian.Uint64(extended[24:]) != binary.LittleEndian.Uint64(extended[32:]) {
			return ErrInvalid
		}
		count, size, offset = binary.LittleEndian.Uint64(extended[32:]), binary.LittleEndian.Uint64(extended[40:]), binary.LittleEndian.Uint64(extended[48:])
		directoryEnd = zip64Offset
	}
	if count == 0 || count > MaxTreeEntries || size > maxZIPDirectoryBytes || size < count*46 || offset > directoryEnd || size != directoryEnd-offset {
		return ErrInvalid
	}
	position := offset
	var entry [46]byte
	for range count {
		if directoryEnd-position < 46 {
			return ErrInvalid
		}
		if n, err := reader.ReadAt(entry[:], int64(position)); err != nil || n != len(entry) || binary.LittleEndian.Uint32(entry[:]) != 0x02014b50 || binary.LittleEndian.Uint16(entry[34:]) != 0 {
			return ErrInvalid
		}
		name := uint64(binary.LittleEndian.Uint16(entry[28:]))
		extra := uint64(binary.LittleEndian.Uint16(entry[30:]))
		comment := uint64(binary.LittleEndian.Uint16(entry[32:]))
		step := 46 + name + extra + comment
		if name == 0 || name > 1025 || step > directoryEnd-position {
			return ErrInvalid
		}
		position += step
	}
	if position != directoryEnd {
		return ErrInvalid
	}
	return nil
}
