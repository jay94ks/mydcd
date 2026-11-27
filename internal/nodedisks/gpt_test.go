// SPDX-License-Identifier: Apache-2.0

package nodedisks

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/jay94ks/seafield/internal/observability"
)

func TestBuildGPTOnePartitionAlignedWithValidChecksums(t *testing.T) {
	for _, sector := range []int{512, 4096} {
		sectors := uint64(8<<30) / uint64(sector)
		disk := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		g, err := BuildGPT(sector, sectors, disk, [16]byte{9}, "seafield")
		if err != nil {
			t.Fatal(err)
		}
		if kind, id := observability.ProbeTable(g.Primary, sector); kind != "gpt" || id != "04030201-0605-0807-090a-0b0c0d0e0f10" {
			t.Fatal("primary not read back", sector, kind, id)
		}
		align := uint64(1<<20) / uint64(sector)
		if g.Start%align != 0 || (g.End+1)%align != 0 || g.End >= sectors-1 || g.Start < 2 {
			t.Fatal("alignment", sector, g.Start, g.End)
		}
		check := func(h, entries []byte, my uint64) {
			copyH := append([]byte{}, h[:92]...)
			binary.LittleEndian.PutUint32(copyH[16:], 0)
			if crc32.ChecksumIEEE(copyH) != binary.LittleEndian.Uint32(h[16:]) || crc32.ChecksumIEEE(entries) != binary.LittleEndian.Uint32(h[88:]) || binary.LittleEndian.Uint64(h[24:]) != my {
				t.Fatal("header checksum", sector, my)
			}
		}
		check(g.Primary[sector:2*sector], g.Primary[2*sector:], 1)
		table := gptEntries * gptEntrySize
		check(g.Backup[table:], g.Backup[:table], sectors-1)
		if g.BackupOffset+int64(len(g.Backup)) != int64(sectors)*int64(sector) {
			t.Fatal("backup does not end at the last sector", sector)
		}
	}
	if _, err := BuildGPT(512, 1000, [16]byte{}, [16]byte{}, ""); err != ErrDiskTooSmall {
		t.Fatal("tiny disk", err)
	}
}
