// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"unicode/utf16"
)

// GPT is a fresh partition table with one Linux filesystem partition that
// spans the disk, aligned to 1 MiB (devel/proposals/node-disk-management.md).
// Primary goes at offset 0 (protective MBR, header, entries); Backup (entries,
// header) at BackupOffset. Start/End are the partition's first and last
// sector.
type GPT struct {
	Primary, Backup []byte
	BackupOffset    int64
	Start, End      uint64
}

const (
	gptEntries   = 128
	gptEntrySize = 128
	gptAlign     = 1 << 20
)

// linuxFilesystemType is 0FC63DAF-8483-4772-8E79-3D69D8477DE4 on disk.
var linuxFilesystemType = [16]byte{0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4}

var ErrDiskTooSmall = errors.New("disk too small for a partition table")

// BuildGPT lays out the table for a disk of the given logical sector size
// and count. diskGUID and partGUID are the on-disk (mixed-endian) bytes.
func BuildGPT(sector int, sectors uint64, diskGUID, partGUID [16]byte, name string) (GPT, error) {
	if sector != 512 && sector != 4096 {
		return GPT{}, errors.New("unsupported sector size")
	}
	ss := uint64(sector)
	tableSectors := uint64(gptEntries*gptEntrySize) / ss
	align := uint64(gptAlign) / ss
	firstUsable, lastUsable := 2+tableSectors, sectors-2-tableSectors
	if sectors < 2*align+2*tableSectors+4 {
		return GPT{}, ErrDiskTooSmall
	}
	start := (firstUsable + align - 1) / align * align
	end := (lastUsable+1)/align*align - 1
	if end <= start {
		return GPT{}, ErrDiskTooSmall
	}
	entries := make([]byte, gptEntries*gptEntrySize)
	copy(entries[0:16], linuxFilesystemType[:])
	copy(entries[16:32], partGUID[:])
	binary.LittleEndian.PutUint64(entries[32:], start)
	binary.LittleEndian.PutUint64(entries[40:], end)
	for i, u := range utf16.Encode([]rune(name)) {
		if i == 36 {
			break
		}
		binary.LittleEndian.PutUint16(entries[56+2*i:], u)
	}
	entriesCRC := crc32.ChecksumIEEE(entries)
	header := func(my, alternate, entryLBA uint64) []byte {
		h := make([]byte, sector)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], my)
		binary.LittleEndian.PutUint64(h[32:], alternate)
		binary.LittleEndian.PutUint64(h[40:], firstUsable)
		binary.LittleEndian.PutUint64(h[48:], lastUsable)
		copy(h[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(h[72:], entryLBA)
		binary.LittleEndian.PutUint32(h[80:], gptEntries)
		binary.LittleEndian.PutUint32(h[84:], gptEntrySize)
		binary.LittleEndian.PutUint32(h[88:], entriesCRC)
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
		return h
	}
	mbr := make([]byte, sector)
	e := mbr[446:462]
	e[1], e[2], e[3] = 0x00, 0x02, 0x00
	e[4] = 0xEE
	e[5], e[6], e[7] = 0xFF, 0xFF, 0xFF
	binary.LittleEndian.PutUint32(e[8:], 1)
	binary.LittleEndian.PutUint32(e[12:], uint32(min(sectors-1, 0xFFFFFFFF)))
	mbr[510], mbr[511] = 0x55, 0xAA
	primary := append(append(mbr, header(1, sectors-1, 2)...), entries...)
	backupEntries := sectors - 1 - tableSectors
	backup := append(append([]byte{}, entries...), header(sectors-1, 1, backupEntries)...)
	return GPT{Primary: primary, Backup: backup, BackupOffset: int64(backupEntries * ss), Start: start, End: end}, nil
}
