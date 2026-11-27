// SPDX-License-Identifier: Apache-2.0

// Package fuse is sfc's own user-mode FUSE driver. It speaks the Linux
// /dev/fuse protocol directly (no libfuse, no fusermount) and serves one
// FileSystem per mount. Only the operations a shared Volume needs are
// implemented; everything else is answered with ENOSYS.
//
// The serving process must not open regular files on its own mount with
// os.Open/os.ReadFile/os.WriteFile: the Go runtime registers every opened
// file with its netpoller through a raw epoll_ctl that stays "running" to
// the scheduler, the kernel turns that into a FUSE_POLL for this server,
// and a concurrent GC stop-the-world then waits for a thread that waits for
// a server goroutine that cannot run. Use golang.org/x/sys/unix calls (or
// O_PATH) for any access sfcd itself makes inside a mount.
package fuse

import (
	"encoding/binary"
	"errors"
	"syscall"
)

// Kernel protocol version this driver speaks. Kernels with a newer minor
// accept it; kernels older than minMinor are refused.
const (
	protoMajor = 7
	protoMinor = 31
	minMinor   = 23
)

// RootID is the node ID of the mount root.
const RootID uint64 = 1

type opcode uint32

const (
	opLookup      opcode = 1
	opForget      opcode = 2
	opGetattr     opcode = 3
	opSetattr     opcode = 4
	opReadlink    opcode = 5
	opSymlink     opcode = 6
	opMkdir       opcode = 9
	opUnlink      opcode = 10
	opRmdir       opcode = 11
	opRename      opcode = 12
	opLink        opcode = 13
	opOpen        opcode = 14
	opRead        opcode = 15
	opWrite       opcode = 16
	opStatfs      opcode = 17
	opRelease     opcode = 18
	opFsync       opcode = 20
	opFlush       opcode = 25
	opInit        opcode = 26
	opOpendir     opcode = 27
	opReaddir     opcode = 28
	opReleasedir  opcode = 29
	opFsyncdir    opcode = 30
	opGetlk       opcode = 31
	opSetlk       opcode = 32
	opSetlkw      opcode = 33
	opCreate      opcode = 35
	opInterrupt   opcode = 36
	opDestroy     opcode = 38
	opBatchForget opcode = 42
	opRename2     opcode = 45
)

// INIT flags (fuse_init_in/out.flags).
const (
	initAsyncRead     = 1 << 0
	initPosixLocks    = 1 << 1
	initAtomicOTrunc  = 1 << 3
	initBigWrites     = 1 << 5
	initFlockLocks    = 1 << 10
	initParallelDirop = 1 << 18
	initMaxPages      = 1 << 22
)

// Open reply flags (fuse_open_out.open_flags).
const (
	OpenDirectIO  = 1 << 0
	OpenKeepCache = 1 << 1
)

// SETATTR valid bits.
const (
	SetMode      = 1 << 0
	SetUID       = 1 << 1
	SetGID       = 1 << 2
	SetSize      = 1 << 3
	SetAtime     = 1 << 4
	SetMtime     = 1 << 5
	SetFH        = 1 << 6
	SetAtimeNow  = 1 << 7
	SetMtimeNow  = 1 << 8
	SetLockOwner = 1 << 9
	SetCtime     = 1 << 10
)

const (
	lkFlock       = 1 << 0
	getattrFH     = 1 << 0
	fsyncDatasync = 1 << 0
)

const (
	inHeaderSize  = 40
	outHeaderSize = 16
	attrSize      = 88
	entryOutSize  = 40 + attrSize
	attrOutSize   = 16 + attrSize
	openOutSize   = 16
	kstatfsSize   = 80
	fileLockSize  = 24
	initOutSize   = 64
	initOutCompat = 24
	direntBase    = 24
)

var ne = binary.NativeEndian

var errShort = errors.New("fuse: short request")

// inHeader is struct fuse_in_header.
type inHeader struct {
	Len    uint32
	Opcode opcode
	Unique uint64
	Node   uint64
	UID    uint32
	GID    uint32
	PID    uint32
}

func parseHeader(b []byte) (inHeader, error) {
	if len(b) < inHeaderSize {
		return inHeader{}, errShort
	}
	h := inHeader{
		Len:    ne.Uint32(b[0:]),
		Opcode: opcode(ne.Uint32(b[4:])),
		Unique: ne.Uint64(b[8:]),
		Node:   ne.Uint64(b[16:]),
		UID:    ne.Uint32(b[24:]),
		GID:    ne.Uint32(b[28:]),
		PID:    ne.Uint32(b[32:]),
	}
	if int(h.Len) != len(b) {
		return h, errShort
	}
	return h, nil
}

// reader walks a request body.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errShort
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u32() uint32 { return ne.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return ne.Uint64(r.take(8)) }

// name reads one NUL-terminated name.
func (r *reader) name() string {
	if r.err != nil {
		return ""
	}
	for i, c := range r.b {
		if c == 0 {
			s := string(r.b[:i])
			r.b = r.b[i+1:]
			if s == "" {
				r.err = syscall.EINVAL
			}
			return s
		}
	}
	r.err = errShort
	return ""
}

// writer builds a reply body.
type writer struct{ b []byte }

func (w *writer) u16(v uint16) { w.b = ne.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = ne.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = ne.AppendUint64(w.b, v) }
func (w *writer) pad(n int)    { w.b = append(w.b, make([]byte, n)...) }

func (w *writer) attr(a Attr) {
	w.u64(a.Ino)
	w.u64(a.Size)
	w.u64(a.Blocks)
	as, an := split(a.Atime)
	ms, mn := split(a.Mtime)
	cs, cn := split(a.Ctime)
	w.u64(as)
	w.u64(ms)
	w.u64(cs)
	w.u32(an)
	w.u32(mn)
	w.u32(cn)
	w.u32(a.Mode)
	w.u32(a.Nlink)
	w.u32(a.UID)
	w.u32(a.GID)
	w.u32(a.Rdev)
	w.u32(a.Blksize)
	w.u32(0) // flags
}

func (w *writer) entry(e Entry) {
	w.u64(e.Node)
	w.u64(e.Generation)
	es, en := seconds(e.EntryValid)
	as, an := seconds(e.AttrValid)
	w.u64(es)
	w.u64(as)
	w.u32(en)
	w.u32(an)
	w.attr(e.Attr)
}

func (w *writer) attrOut(a AttrReply) {
	s, n := seconds(a.Valid)
	w.u64(s)
	w.u32(n)
	w.u32(0)
	w.attr(a.Attr)
}

func (w *writer) open(fh uint64, flags uint32) {
	w.u64(fh)
	w.u32(flags)
	w.u32(0)
}

func (w *writer) lock(l Lock) {
	w.u64(l.Start)
	w.u64(l.End)
	w.u32(l.Type)
	w.u32(l.PID)
}

func (r *reader) lock() Lock {
	return Lock{Start: r.u64(), End: r.u64(), Type: r.u32(), PID: r.u32()}
}

// dirent appends one struct fuse_dirent padded to 8 bytes. It reports
// false when the entry does not fit in limit.
func (w *writer) dirent(d DirEntry, limit int) bool {
	size := direntBase + len(d.Name)
	padded := (size + 7) &^ 7
	if len(w.b)+padded > limit {
		return false
	}
	w.u64(d.Ino)
	w.u64(d.Off)
	w.u32(uint32(len(d.Name)))
	w.u32(d.Type)
	w.b = append(w.b, d.Name...)
	w.pad(padded - size)
	return true
}
