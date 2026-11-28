// SPDX-License-Identifier: Apache-2.0

// Package sfcimg is the chunk image format of fuse disk bundles
// (devel/design/node-disk-bundles.md §2-5). One chunk file
// holds a piece of a bundle's virtual disk on an existing filesystem. It
// borrows the idea of VHDX (a header and a block map) but is its own small
// format; compatibility with other programs is not a goal.
//
// Layout: two 4 KiB headers at 0 and 4 KiB (the newer valid one wins), then
// for a grow chunk the region map (8 bytes per 1 MiB region), then data
// from DataOffset. A reserve chunk has its data contiguous and allocated
// up front; a grow chunk appends each region on its first write and only
// then points the map at it, so a crash never maps garbage.
package sfcimg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	Magic      = "SFCIMG01"
	headerSize = 4096
	// RegionSize is the grow allocation and map unit.
	RegionSize = 1 << 20
	// MaxChunk bounds one chunk file.
	MaxChunk = 64 << 30
)

var (
	ErrFormat  = errors.New("sfcimg: not a valid chunk image")
	ErrRange   = errors.New("sfcimg: offset outside the chunk")
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
)

// Header describes one chunk.
type Header struct {
	Bundle     [16]byte // bundle ID
	Mode       uint8    // 0 linear, 1 mirror
	Grow       bool     // allocation: grow (true) or reserve
	Copy       uint8    // mirror copy number (1…), 0 for linear
	Index      uint32   // chunk number inside its copy
	Start      uint64   // virtual offset of the chunk's first byte
	Length     uint64   // bytes of virtual disk the chunk holds
	Generation uint64
}

func (h Header) regions() uint64 { return (h.Length + RegionSize - 1) / RegionSize }

// DataOffset is where data (reserve) or the first region (grow) starts.
func (h Header) DataOffset() int64 {
	off := int64(2 * headerSize)
	if h.Grow {
		off += int64(h.regions() * 8)
	}
	return (off + RegionSize - 1) / RegionSize * RegionSize
}

func (h Header) encode() []byte {
	b := make([]byte, headerSize)
	copy(b, Magic)
	binary.LittleEndian.PutUint16(b[8:], 1) // format version
	copy(b[16:32], h.Bundle[:])
	b[32] = h.Mode
	if h.Grow {
		b[33] = 1
	}
	b[34] = h.Copy
	binary.LittleEndian.PutUint32(b[36:], h.Index)
	binary.LittleEndian.PutUint64(b[40:], h.Start)
	binary.LittleEndian.PutUint64(b[48:], h.Length)
	binary.LittleEndian.PutUint64(b[56:], h.Generation)
	binary.LittleEndian.PutUint32(b[headerSize-4:], crc32.Checksum(b[:headerSize-4], castagnoli))
	return b
}

func decodeHeader(b []byte) (Header, bool) {
	if len(b) != headerSize || string(b[:8]) != Magic || binary.LittleEndian.Uint16(b[8:]) != 1 || binary.LittleEndian.Uint32(b[headerSize-4:]) != crc32.Checksum(b[:headerSize-4], castagnoli) {
		return Header{}, false
	}
	var h Header
	copy(h.Bundle[:], b[16:32])
	h.Mode, h.Grow, h.Copy = b[32], b[33] == 1, b[34]
	h.Index = binary.LittleEndian.Uint32(b[36:])
	h.Start = binary.LittleEndian.Uint64(b[40:])
	h.Length = binary.LittleEndian.Uint64(b[48:])
	h.Generation = binary.LittleEndian.Uint64(b[56:])
	if h.Length == 0 || h.Length > MaxChunk || h.Mode > 1 {
		return Header{}, false
	}
	return h, true
}

// Image is one open chunk.
type Image struct {
	mu     sync.Mutex
	f      *os.File
	h      Header
	regmap []uint64 // grow: file offset of each region, 0 = never written
	end    int64    // grow: where the next region goes
}

// Create makes a new chunk file at path. A reserve chunk allocates all of
// its space now (fallocate), so it fails at once when the filesystem is
// short; a grow chunk takes only its header and map.
func Create(path string, h Header) (*Image, error) {
	if h.Length == 0 || h.Length > MaxChunk {
		return nil, ErrRange
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Image, error) {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	size := h.DataOffset()
	if !h.Grow {
		size += int64(h.Length)
		if err := unix.Fallocate(int(f.Fd()), 0, 0, size); err != nil {
			return fail(err)
		}
	} else if err := f.Truncate(size); err != nil {
		return fail(err)
	}
	enc := h.encode()
	if _, err := f.WriteAt(enc, 0); err != nil {
		return fail(err)
	}
	if _, err := f.WriteAt(enc, headerSize); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	img := &Image{f: f, h: h, end: size}
	if h.Grow {
		img.regmap = make([]uint64, h.regions())
	}
	return img, nil
}

// Open opens an existing chunk.
func Open(path string) (*Image, error) {
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	img, err := load(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return img, nil
}

func load(f *os.File) (*Image, error) {
	buf := make([]byte, 2*headerSize)
	if _, err := f.ReadAt(buf, 0); err != nil {
		return nil, ErrFormat
	}
	a, okA := decodeHeader(buf[:headerSize])
	b, okB := decodeHeader(buf[headerSize:])
	var h Header
	switch {
	case okA && (!okB || a.Generation >= b.Generation):
		h = a
	case okB:
		h = b
	default:
		return nil, ErrFormat
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	img := &Image{f: f, h: h, end: st.Size()}
	if !h.Grow {
		if st.Size() < h.DataOffset()+int64(h.Length) {
			return nil, ErrFormat
		}
		return img, nil
	}
	raw := make([]byte, h.regions()*8)
	if _, err := f.ReadAt(raw, 2*headerSize); err != nil {
		return nil, ErrFormat
	}
	img.regmap = make([]uint64, h.regions())
	for i := range img.regmap {
		off := binary.LittleEndian.Uint64(raw[i*8:])
		if off != 0 && (int64(off) < h.DataOffset() || int64(off)+RegionSize > st.Size() || (int64(off)-h.DataOffset())%RegionSize != 0) {
			off = 0 // a region whose append did not finish is unwritten
		}
		img.regmap[i] = off
	}
	if end := (st.Size() - h.DataOffset() + RegionSize - 1) / RegionSize * RegionSize; end > 0 {
		img.end = h.DataOffset() + end
	} else {
		img.end = h.DataOffset()
	}
	return img, nil
}

func (m *Image) Header() Header { return m.h }

// Allocated is the bytes of virtual disk this chunk has stored.
func (m *Image) Allocated() uint64 {
	if !m.h.Grow {
		return m.h.Length
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := uint64(0)
	for _, off := range m.regmap {
		if off != 0 {
			n += RegionSize
		}
	}
	return min(n, m.h.Length)
}

// Written reports whether the region holding off was ever written (always
// true for reserve).
func (m *Image) Written(off uint64) bool {
	if !m.h.Grow {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	i := off / RegionSize
	return i < uint64(len(m.regmap)) && m.regmap[i] != 0
}

// ReadAt reads chunk-relative bytes; never-written regions read as zero.
func (m *Image) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || uint64(off)+uint64(len(p)) > m.h.Length {
		return 0, ErrRange
	}
	if !m.h.Grow {
		return m.f.ReadAt(p, m.h.DataOffset()+off)
	}
	done := 0
	for done < len(p) {
		cur := uint64(off) + uint64(done)
		i, in := cur/RegionSize, cur%RegionSize
		n := min(uint64(len(p)-done), RegionSize-in)
		m.mu.Lock()
		base := m.regmap[i]
		m.mu.Unlock()
		if base == 0 {
			clear(p[done : done+int(n)])
		} else if _, err := m.f.ReadAt(p[done:done+int(n)], int64(base+in)); err != nil && !errors.Is(err, io.EOF) {
			return done, err
		}
		done += int(n)
	}
	return done, nil
}

// WriteAt writes chunk-relative bytes. A grow chunk appends a region on its
// first write: data first (synced), then the 8-byte map entry.
func (m *Image) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || uint64(off)+uint64(len(p)) > m.h.Length {
		return 0, ErrRange
	}
	if !m.h.Grow {
		return m.f.WriteAt(p, m.h.DataOffset()+off)
	}
	done := 0
	for done < len(p) {
		cur := uint64(off) + uint64(done)
		i, in := cur/RegionSize, cur%RegionSize
		n := min(uint64(len(p)-done), RegionSize-in)
		base, err := m.region(i, in == 0 && n == RegionSize)
		if err != nil {
			return done, err
		}
		if _, err := m.f.WriteAt(p[done:done+int(n)], int64(base+in)); err != nil {
			return done, err
		}
		done += int(n)
	}
	return done, nil
}

// region returns region i's file offset, appending it when new. whole says
// the caller overwrites all of it, so the zero fill is skipped.
func (m *Image) region(i uint64, whole bool) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.regmap[i] != 0 {
		return m.regmap[i], nil
	}
	base := m.end
	if err := unix.Fallocate(int(m.f.Fd()), 0, base, RegionSize); err != nil {
		return 0, err
	}
	if !whole {
		// fallocate gives zeroed space on ext4/xfs; a reused file range
		// is cleared explicitly so stale bytes never show.
		if err := unix.Fallocate(int(m.f.Fd()), unix.FALLOC_FL_ZERO_RANGE, base, RegionSize); err != nil && !errors.Is(err, unix.EOPNOTSUPP) {
			return 0, err
		}
	}
	if err := unix.Fdatasync(int(m.f.Fd())); err != nil {
		return 0, err
	}
	var entry [8]byte
	binary.LittleEndian.PutUint64(entry[:], uint64(base))
	if _, err := m.f.WriteAt(entry[:], int64(2*headerSize+i*8)); err != nil {
		return 0, err
	}
	if err := unix.Fdatasync(int(m.f.Fd())); err != nil {
		return 0, err
	}
	m.regmap[i], m.end = uint64(base), base+RegionSize
	return uint64(base), nil
}

// Sync flushes data to the filesystem below.
func (m *Image) Sync() error { return unix.Fdatasync(int(m.f.Fd())) }

func (m *Image) Close() error { return m.f.Close() }

// Check reads a chunk file's header and map and reports problems; the
// sfcimg tool and tests use it.
func Check(path string) (Header, uint64, error) {
	img, err := Open(path)
	if err != nil {
		return Header{}, 0, err
	}
	defer img.Close()
	buf := make([]byte, 2*headerSize)
	if _, err := img.f.ReadAt(buf, 0); err != nil {
		return img.h, 0, err
	}
	if !bytes.Equal(buf[:headerSize], buf[headerSize:]) {
		return img.h, img.Allocated(), errors.New("sfcimg: the two headers differ")
	}
	return img.h, img.Allocated(), nil
}
