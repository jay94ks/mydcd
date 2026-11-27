// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Devices is one server's block device inventory: every disk the kernel
// lists, its partitions, the filesystem signature on each, where it is
// mounted and what holds it (devel/proposals/node-disk-management.md). It
// is a measurement only. It never authorizes a format or a mount: those
// re-read the device right before they act.
type Devices struct {
	Disks []BlockDisk `json:",omitempty"`
	// Truncated: more disks exist than one report holds.
	Truncated bool `json:",omitempty"`
	// Recorded are the mounts sfcd made and mounts again at start, with
	// why one is not mounted now (Reason empty = mounted).
	Recorded []RecordedMount `json:",omitempty"`
}

// RecordedMount is one entry of sfcd's local mount record.
type RecordedMount struct {
	UUID, Path, Disk, Part string
	Reason                 string `json:",omitempty"`
}

// RecordedReasons say why a recorded disk is not mounted.
var RecordedReasons = []string{"disk-not-found", "device-identity-changed", "not-an-additional-ext4-disk", "mounted-elsewhere", "mount-point-not-empty", "mount-failed", "pending"}

func (m RecordedMount) valid() bool {
	return deviceText(m.UUID, 64) && m.UUID != "" && strings.HasPrefix(m.Path, "/") && deviceText(m.Path, maxDeviceMount) && deviceName(m.Disk) && deviceName(m.Part) && (m.Reason == "" || slices.Contains(RecordedReasons, m.Reason))
}

// DeviceClasses: system holds "/"; additional has a mounted filesystem or
// active swap; unused has neither.
var DeviceClasses = []string{"system", "additional", "unused"}

const (
	MaxDevicesBytes = 32 << 10
	maxBlockDisks   = 32
	maxBlockParts   = 32
	maxBlockMounts  = 8
	maxBlockHolders = 8
	maxDeviceText   = 128
	maxDeviceMount  = 4096
)

type BlockDisk struct {
	Name, Class string
	Size        uint64
	Model       string `json:",omitempty"`
	Serial      string `json:",omitempty"`
	WWN         string `json:",omitempty"`
	Rotational  bool   `json:",omitempty"`
	ReadOnly    bool   `json:",omitempty"`
	Removable   bool   `json:",omitempty"`
	// Table is "gpt" or "dos"; TableID is the GPT disk GUID or the DOS
	// disk signature. Empty when the disk has no partition table.
	Table   string `json:",omitempty"`
	TableID string `json:",omitempty"`
	// Parts are the partitions. A filesystem written on the whole disk is
	// one part with Number 0 and the disk's own Name.
	Parts []BlockPart `json:",omitempty"`
}

// BlockPart is one partition (or the whole disk). Filesystem/UUID/Label are
// from its own signature probe, never from a path the caller chose.
type BlockPart struct {
	Name       string
	Number     uint32 `json:",omitempty"`
	Size       uint64
	Filesystem string        `json:",omitempty"`
	UUID       string        `json:",omitempty"`
	Label      string        `json:",omitempty"`
	Mounts     []string      `json:",omitempty"`
	Swap       bool          `json:",omitempty"`
	Holders    []BlockHolder `json:",omitempty"`
	Space      *BlockSpace   `json:",omitempty"`
}

// BlockHolder is a device built on the part (LVM, dm-crypt, RAID). It is
// only shown: its mounts make the part busy.
type BlockHolder struct {
	Name, Kind string
	Mapper     string      `json:",omitempty"`
	Filesystem string      `json:",omitempty"`
	Mounts     []string    `json:",omitempty"`
	Swap       bool        `json:",omitempty"`
	Space      *BlockSpace `json:",omitempty"`
}

// BlockSpace is statfs of the first mount point.
type BlockSpace struct{ Total, Used, Available uint64 }

var holderKinds = []string{"lvm", "crypt", "raid", "dm"}

func deviceText(s string, limit int) bool {
	if len(s) > limit {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func deviceName(s string) bool {
	if s == "" || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func validMounts(mounts []string) bool {
	if len(mounts) > maxBlockMounts || !slices.IsSorted(mounts) {
		return false
	}
	for i, m := range mounts {
		if !strings.HasPrefix(m, "/") || len(m) > maxDeviceMount || strings.ContainsAny(m, "\x00\r\n") || i > 0 && mounts[i-1] == m {
			return false
		}
	}
	return true
}

func (s *BlockSpace) valid() bool {
	return s == nil || s.Total > 0 && s.Used <= s.Total && s.Available <= s.Total-s.Used
}

func (h BlockHolder) valid() bool {
	return deviceName(h.Name) && slices.Contains(holderKinds, h.Kind) && deviceText(h.Mapper, maxDeviceText) && deviceText(h.Filesystem, 32) && validMounts(h.Mounts) && h.Space.valid() && (h.Space == nil || len(h.Mounts) > 0)
}

func (p BlockPart) valid(disk string) bool {
	ok := deviceName(p.Name) && (p.Number == 0) == (p.Name == disk) && deviceText(p.Filesystem, 32) && deviceText(p.UUID, 64) && deviceText(p.Label, maxDeviceText) && validMounts(p.Mounts) && len(p.Holders) <= maxBlockHolders && p.Space.valid() && (p.Space == nil || len(p.Mounts) > 0)
	for i, h := range p.Holders {
		ok = ok && h.valid() && (i == 0 || p.Holders[i-1].Name < h.Name)
	}
	return ok
}

func (d BlockDisk) valid() bool {
	ok := deviceName(d.Name) && slices.Contains(DeviceClasses, d.Class) && deviceText(d.Model, maxDeviceText) && deviceText(d.Serial, maxDeviceText) && deviceText(d.WWN, maxDeviceText) && (d.Table == "" || d.Table == "gpt" || d.Table == "dos") && (d.Table == "") == (d.TableID == "") && deviceText(d.TableID, 64) && len(d.Parts) <= maxBlockParts
	whole := false
	for i, p := range d.Parts {
		whole = whole || p.Number == 0
		ok = ok && p.valid(d.Name) && (i == 0 || d.Parts[i-1].Number < p.Number)
	}
	// A whole-disk filesystem has no partition table and is the only part.
	return ok && (!whole || len(d.Parts) == 1 && d.Table == "") && d.Class == classOf(d)
}

func (v Devices) valid() bool {
	if len(v.Disks) > maxBlockDisks || len(v.Recorded) > maxBlockDisks {
		return false
	}
	for i, m := range v.Recorded {
		if !m.valid() || i > 0 && v.Recorded[i-1].Path >= m.Path {
			return false
		}
	}
	for i, d := range v.Disks {
		if !d.valid() || i > 0 && v.Disks[i-1].Name >= d.Name {
			return false
		}
	}
	raw, err := json.Marshal(v)
	return err == nil && len(raw) <= MaxDevicesBytes
}

// Busy: the part has a mount, active swap or a holder. Such a part is never
// formatted or mounted by sfcd.
func (p BlockPart) Busy() bool { return len(p.Mounts) > 0 || p.Swap || len(p.Holders) > 0 }

// Mounted lists every mount point on the part and on its holders.
func (p BlockPart) Mounted() []string {
	out := slices.Clone(p.Mounts)
	for _, h := range p.Holders {
		out = append(out, h.Mounts...)
	}
	return out
}

func classOf(d BlockDisk) string {
	class := "unused"
	for _, p := range d.Parts {
		if slices.Contains(p.Mounted(), "/") {
			return "system"
		}
		swap := p.Swap
		for _, h := range p.Holders {
			swap = swap || h.Swap
		}
		if len(p.Mounted()) > 0 || swap {
			class = "additional"
		}
	}
	return class
}

// Probe results. Every probe reads only the given bytes.

type Signature struct{ Filesystem, UUID, Label string }

func cString(b []byte) string {
	if i := slices.Index(b, 0); i >= 0 {
		b = b[:i]
	}
	s := strings.TrimSpace(string(b))
	if !deviceText(s, maxDeviceText) {
		return ""
	}
	return s
}

func uuidString(b []byte) string {
	if len(b) != 16 || slices.Equal(b, make([]byte, 16)) {
		return ""
	}
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// guidString is a GPT GUID: the first three fields are little-endian.
func guidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	c := slices.Clone(b)
	slices.Reverse(c[0:4])
	slices.Reverse(c[4:6])
	slices.Reverse(c[6:8])
	return uuidString(c)
}

// ProbeSignature finds a filesystem or volume signature at the start of a
// device. It needs the first 0x11000 bytes (less for a smaller device).
func ProbeSignature(b []byte) (Signature, bool) {
	at := func(off int, magic string) bool {
		return len(b) >= off+len(magic) && string(b[off:off+len(magic)]) == magic
	}
	switch {
	case at(0, "LUKS\xba\xbe"):
		return Signature{Filesystem: "crypto_LUKS", UUID: cStringAt(b, 168, 40)}, true
	case at(512+24, "LVM2 001") && at(512, "LABELONE"):
		return Signature{Filesystem: "LVM2_member"}, true
	case at(0, "XFSB") && len(b) >= 120:
		return Signature{Filesystem: "xfs", UUID: uuidString(b[32:48]), Label: cString(b[108:120])}, true
	case len(b) >= 1024+0x88 && binary.LittleEndian.Uint16(b[1024+0x38:]) == 0xEF53:
		sb := b[1024:]
		kind := "ext2"
		compat, incompat := binary.LittleEndian.Uint32(sb[0x5C:]), binary.LittleEndian.Uint32(sb[0x60:])
		if compat&0x4 != 0 {
			kind = "ext3"
		}
		// extents, 64bit, flex_bg are ext4-only incompatible features.
		if incompat&(0x40|0x80|0x200) != 0 {
			kind = "ext4"
		}
		return Signature{Filesystem: kind, UUID: uuidString(sb[0x68:0x78]), Label: cString(sb[0x78:0x88])}, true
	case at(0x10040, "_BHRfS_M") && len(b) >= 0x1012B+256:
		return Signature{Filesystem: "btrfs", UUID: uuidString(b[0x10020:0x10030]), Label: cString(b[0x1012B : 0x1012B+256])}, true
	case at(4096-10, "SWAPSPACE2") || at(4096-10, "SWAP-SPACE"):
		return Signature{Filesystem: "swap", UUID: uuidString(b[1024+12 : 1024+28]), Label: cString(b[1024+28 : 1024+44])}, true
	case at(3, "NTFS    ") && len(b) >= 0x50:
		serial := slices.Clone(b[0x48:0x50])
		slices.Reverse(serial)
		return Signature{Filesystem: "ntfs", UUID: strings.ToUpper(hex.EncodeToString(serial))}, true
	case len(b) >= 512 && b[510] == 0x55 && b[511] == 0xAA && at(82, "FAT32   "):
		return Signature{Filesystem: "vfat", UUID: fatSerial(b[67:71]), Label: cString(b[71:82])}, true
	case len(b) >= 512 && b[510] == 0x55 && b[511] == 0xAA && (at(54, "FAT16   ") || at(54, "FAT12   ")):
		return Signature{Filesystem: "vfat", UUID: fatSerial(b[39:43]), Label: cString(b[43:54])}, true
	}
	return Signature{}, false
}

func cStringAt(b []byte, off, n int) string {
	if len(b) < off+n {
		return ""
	}
	return cString(b[off : off+n])
}

func fatSerial(b []byte) string {
	return fmt.Sprintf("%02X%02X-%02X%02X", b[3], b[2], b[1], b[0])
}

// ProbeTable finds a GPT or DOS partition table. sector is the logical
// sector size; b must hold at least the first two sectors.
func ProbeTable(b []byte, sector int) (string, string) {
	if sector < 512 || len(b) < 2*sector {
		return "", ""
	}
	if string(b[sector:sector+8]) == "EFI PART" {
		return "gpt", guidString(b[sector+56 : sector+72])
	}
	if b[510] != 0x55 || b[511] != 0xAA {
		return "", ""
	}
	if _, fs := ProbeSignature(b); fs {
		return "", "" // a FAT/NTFS boot sector, not a partition table
	}
	entries := 0
	for i := 0; i < 4; i++ {
		e := b[446+16*i : 446+16*(i+1)]
		if e[0] != 0 && e[0] != 0x80 {
			return "", ""
		}
		if e[4] != 0 {
			entries++
		}
	}
	if entries == 0 {
		return "", ""
	}
	return "dos", fmt.Sprintf("%08x", binary.LittleEndian.Uint32(b[440:444]))
}
