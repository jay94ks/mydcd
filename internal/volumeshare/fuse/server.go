// SPDX-License-Identifier: Apache-2.0

package fuse

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

// MaxWrite is the largest WRITE (and READ) the driver accepts.
const MaxWrite = 128 << 10

const (
	maxBackground = 64
	readBuffer    = MaxWrite + 4096
	pollInterval  = 500 // milliseconds
)

// Session is the negotiated state of one mount. Persist it with the device
// FD to resume serving after a restart without a new INIT.
type Session struct {
	Minor    uint32
	Flags    uint32
	MaxWrite uint32
}

// Device is an open /dev/fuse connection bound to one mount. It uses the
// raw FD with level-triggered poll(2) rather than the Go poller: the
// edge-triggered netpoller misses /dev/fuse wake-ups.
type Device struct {
	fd     int
	closed atomic.Bool
}

// NewDevice wraps an already-mounted /dev/fuse FD, for example one handed
// back by the service manager after a restart. The Device owns fd.
func NewDevice(fd int) (*Device, error) {
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("fuse: %w", err)
	}
	return &Device{fd: fd}, nil
}

// FD returns the /dev/fuse descriptor (for an FD store hand-off).
func (d *Device) FD() int { return d.fd }

// Close closes the connection. The kernel then fails pending and future
// requests with ENOTCONN until the mount is unmounted.
func (d *Device) Close() error {
	if d.closed.Swap(true) {
		return nil
	}
	return unix.Close(d.fd)
}

// read returns one whole request. It wakes at least every pollInterval to
// notice ctx.
func (d *Device) read(ctx context.Context, b []byte) (int, error) {
	for {
		if d.closed.Load() {
			return 0, os.ErrClosed
		}
		n, err := unix.Read(d.fd, b)
		if err == nil {
			return n, nil
		}
		if err != unix.EAGAIN {
			return 0, err
		}
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		_, err = unix.Poll([]unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}, pollInterval)
		if err != nil && err != unix.EINTR {
			return 0, err
		}
	}
}

func (d *Device) write(b []byte) error {
	for {
		_, err := unix.Write(d.fd, b)
		if err != unix.EINTR {
			return err
		}
	}
}

// ServeOptions tunes one Serve call.
type ServeOptions struct {
	// Resume skips INIT: the kernel already negotiated this session with an
	// earlier server on the same FD.
	Resume *Session
	// OnInit is called once INIT is answered (not called on Resume).
	OnInit func(Session)
}

type server struct {
	dev  *Device
	fs   FileSystem
	sess Session

	mu       sync.Mutex
	inflight map[uint64]context.CancelFunc

	pool sync.Pool
	sem  chan struct{}
	wg   sync.WaitGroup
}

// Serve answers kernel requests until the mount goes away (nil), ctx ends
// (ctx.Err()), or the device fails. It does not unmount.
func Serve(ctx context.Context, dev *Device, fs FileSystem, o ServeOptions) error {
	s := &server{dev: dev, fs: fs, inflight: map[uint64]context.CancelFunc{}, sem: make(chan struct{}, maxBackground)}
	s.pool.New = func() any { b := make([]byte, readBuffer); return &b }
	defer s.wg.Wait()
	if o.Resume != nil {
		s.sess = *o.Resume
	} else {
		if err := s.init(); err != nil {
			return err
		}
		if o.OnInit != nil {
			o.OnInit(s.sess)
		}
	}
	for {
		bp := s.pool.Get().(*[]byte)
		n, err := dev.read(ctx, *bp)
		if err != nil {
			s.pool.Put(bp)
			switch {
			case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.EINTR), errors.Is(err, syscall.EAGAIN):
				continue // request aborted before we read it
			case errors.Is(err, syscall.ENODEV), errors.Is(err, io.EOF):
				return nil // unmounted
			case ctx.Err() != nil && errors.Is(err, ctx.Err()):
				return ctx.Err()
			}
			return fmt.Errorf("fuse: read: %w", err)
		}
		req := (*bp)[:n]
		h, err := parseHeader(req)
		if err != nil {
			s.pool.Put(bp)
			return fmt.Errorf("fuse: bad request header: %w", err)
		}
		switch h.Opcode {
		case opForget:
			r := reader{b: req[inHeaderSize:]}
			if c := r.u64(); r.err == nil {
				fs.Forget(h.Node, c)
			}
			s.pool.Put(bp)
			continue
		case opBatchForget:
			s.batchForget(req[inHeaderSize:])
			s.pool.Put(bp)
			continue
		case opInterrupt:
			r := reader{b: req[inHeaderSize:]}
			if u := r.u64(); r.err == nil {
				s.interrupt(u)
			}
			s.pool.Put(bp)
			continue
		case opDestroy:
			s.pool.Put(bp)
			s.reply(h.Unique, 0, nil)
			return nil
		}
		rctx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.inflight[h.Unique] = cancel
		s.mu.Unlock()
		s.sem <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			defer s.pool.Put(bp)
			s.handle(rctx, h, req[inHeaderSize:])
			s.mu.Lock()
			delete(s.inflight, h.Unique)
			s.mu.Unlock()
			cancel()
		}()
	}
}

func (s *server) init() error {
	bp := s.pool.Get().(*[]byte)
	defer s.pool.Put(bp)
	for {
		n, err := s.dev.read(context.Background(), *bp)
		if errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) {
			continue
		}
		if err != nil {
			return fmt.Errorf("fuse: read INIT: %w", err)
		}
		h, err := parseHeader((*bp)[:n])
		if err != nil || h.Opcode != opInit {
			return fmt.Errorf("fuse: expected INIT, got opcode %d", h.Opcode)
		}
		r := reader{b: (*bp)[inHeaderSize:n]}
		major, minor, readahead, flags := r.u32(), r.u32(), r.u32(), r.u32()
		if r.err != nil {
			return fmt.Errorf("fuse: short INIT")
		}
		if major < protoMajor || major == protoMajor && minor < minMinor {
			s.reply(h.Unique, syscall.EPROTO, nil)
			return fmt.Errorf("fuse: kernel protocol %d.%d is older than 7.%d", major, minor, minMinor)
		}
		if major > protoMajor {
			// Kernel will retry INIT with our major.
			w := writer{}
			w.u32(protoMajor)
			w.u32(protoMinor)
			w.pad(initOutSize - 8)
			s.reply(h.Unique, 0, w.b)
			continue
		}
		want := uint32(initAsyncRead | initPosixLocks | initAtomicOTrunc | initBigWrites | initFlockLocks | initParallelDirop | initMaxPages)
		s.sess = Session{Minor: min(minor, protoMinor), Flags: flags & want, MaxWrite: MaxWrite}
		w := writer{}
		w.u32(protoMajor)
		w.u32(s.sess.Minor)
		w.u32(readahead)
		w.u32(s.sess.Flags)
		w.u16(maxBackground)
		w.u16(maxBackground * 3 / 4)
		w.u32(MaxWrite)
		w.u32(1)               // time_gran: nanoseconds
		w.u16(MaxWrite / 4096) // max_pages
		w.u16(0)               // map_alignment
		w.pad(initOutSize - len(w.b))
		s.reply(h.Unique, 0, w.b)
		return nil
	}
}

func (s *server) interrupt(unique uint64) {
	s.mu.Lock()
	cancel := s.inflight[unique]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *server) batchForget(b []byte) {
	r := reader{b: b}
	count := r.u32()
	r.u32()
	for i := uint32(0); i < count && r.err == nil; i++ {
		node, n := r.u64(), r.u64()
		if r.err == nil {
			s.fs.Forget(node, n)
		}
	}
}

// reply writes one whole answer in a single write(2).
func (s *server) reply(unique uint64, errno syscall.Errno, body []byte) {
	if errno != 0 {
		body = nil
	}
	w := writer{b: make([]byte, 0, outHeaderSize+len(body))}
	w.u32(uint32(outHeaderSize + len(body)))
	w.u32(uint32(-int32(errno)))
	w.u64(unique)
	w.b = append(w.b, body...)
	// ENOENT here means the request was interrupted and is gone.
	_ = s.dev.write(w.b)
}

func errnoOf(ctx context.Context, err error) syscall.Errno {
	if err == nil {
		return 0
	}
	var e syscall.Errno
	if errors.As(err, &e) && e != 0 {
		return e
	}
	if ctx.Err() != nil {
		return syscall.EINTR
	}
	return syscall.EIO
}

func (s *server) handle(ctx context.Context, h inHeader, body []byte) {
	c := Caller{UID: h.UID, GID: h.GID, PID: h.PID}
	r := &reader{b: body}
	var out writer
	var err error
	fs := s.fs
	switch h.Opcode {
	case opLookup:
		name := r.name()
		if err = r.err; err == nil {
			var e Entry
			if e, err = fs.Lookup(ctx, c, h.Node, name); err == nil {
				out.entry(e)
			}
		}
	case opGetattr:
		flags := r.u32()
		r.u32()
		fh := r.u64()
		if err = r.err; err == nil {
			var a AttrReply
			if a, err = fs.GetAttr(ctx, c, h.Node, fh, flags&getattrFH != 0); err == nil {
				out.attrOut(a)
			}
		}
	case opSetattr:
		in := SetAttrIn{Valid: r.u32()}
		r.u32()
		in.FH, in.Size, in.LockOwner = r.u64(), r.u64(), r.u64()
		as, ms, cs := r.u64(), r.u64(), r.u64()
		an, mn, cn := r.u32(), r.u32(), r.u32()
		in.Mode = r.u32()
		r.u32()
		in.UID, in.GID = r.u32(), r.u32()
		in.Atime, in.Mtime, in.Ctime = unixTime(as, an), unixTime(ms, mn), unixTime(cs, cn)
		if err = r.err; err == nil {
			var a AttrReply
			if a, err = fs.SetAttr(ctx, c, h.Node, in); err == nil {
				out.attrOut(a)
			}
		}
	case opReadlink:
		var t string
		if t, err = fs.Readlink(ctx, c, h.Node); err == nil {
			out.b = append(out.b, t...)
		}
	case opSymlink:
		name, target := r.name(), r.name()
		if err = r.err; err == nil {
			var e Entry
			if e, err = fs.Symlink(ctx, c, h.Node, name, target); err == nil {
				out.entry(e)
			}
		}
	case opMkdir:
		mode, umask := r.u32(), r.u32()
		name := r.name()
		if err = r.err; err == nil {
			var e Entry
			if e, err = fs.Mkdir(ctx, c, h.Node, name, mode, umask); err == nil {
				out.entry(e)
			}
		}
	case opUnlink, opRmdir:
		name := r.name()
		if err = r.err; err == nil {
			if h.Opcode == opUnlink {
				err = fs.Unlink(ctx, c, h.Node, name)
			} else {
				err = fs.Rmdir(ctx, c, h.Node, name)
			}
		}
	case opRename, opRename2:
		newDir := r.u64()
		var flags uint32
		if h.Opcode == opRename2 {
			flags = r.u32()
			r.u32()
		}
		oldName, newName := r.name(), r.name()
		if err = r.err; err == nil {
			err = fs.Rename(ctx, c, h.Node, oldName, newDir, newName, flags)
		}
	case opLink:
		old := r.u64()
		name := r.name()
		if err = r.err; err == nil {
			var e Entry
			if e, err = fs.Link(ctx, c, old, h.Node, name); err == nil {
				out.entry(e)
			}
		}
	case opOpen, opOpendir:
		flags := r.u32()
		r.u32()
		if err = r.err; err == nil {
			var o OpenReply
			if h.Opcode == opOpen {
				o, err = fs.Open(ctx, c, h.Node, flags)
			} else {
				o, err = fs.OpenDir(ctx, c, h.Node, flags)
			}
			if err == nil {
				out.open(o.FH, o.Flags)
			}
		}
	case opCreate:
		flags, mode, umask := r.u32(), r.u32(), r.u32()
		r.u32()
		name := r.name()
		if err = r.err; err == nil {
			var e Entry
			var o OpenReply
			if e, o, err = fs.Create(ctx, c, h.Node, name, flags, mode, umask); err == nil {
				out.entry(e)
				out.open(o.FH, o.Flags)
			}
		}
	case opRead:
		fh, off, size := r.u64(), r.u64(), r.u32()
		if err = r.err; err == nil {
			if size > s.sess.MaxWrite {
				size = s.sess.MaxWrite
			}
			var data []byte
			if data, err = fs.Read(ctx, c, h.Node, fh, off, size); err == nil {
				if uint32(len(data)) > size {
					data = data[:size]
				}
				out.b = data
			}
		}
	case opWrite:
		fh, off, size := r.u64(), r.u64(), r.u32()
		r.u32() // write_flags
		r.u64() // lock_owner
		r.u32() // flags
		r.u32()
		data := r.take(int(size))
		if err = r.err; err == nil {
			var n uint32
			if n, err = fs.Write(ctx, c, h.Node, fh, off, data); err == nil {
				out.u32(n)
				out.u32(0)
			}
		}
	case opStatfs:
		var st StatFs
		if st, err = fs.StatFs(ctx, c, h.Node); err == nil {
			out.u64(st.Blocks)
			out.u64(st.Bfree)
			out.u64(st.Bavail)
			out.u64(st.Files)
			out.u64(st.Ffree)
			out.u32(st.Bsize)
			out.u32(st.Namelen)
			out.u32(st.Frsize)
			out.pad(kstatfsSize - len(out.b))
		}
	case opRelease:
		fh, flags, rflags, owner := r.u64(), r.u32(), r.u32(), r.u64()
		if err = r.err; err == nil {
			fs.Release(h.Node, fh, flags, owner, rflags&(1<<1) != 0)
		}
	case opReleasedir:
		fh := r.u64()
		if err = r.err; err == nil {
			fs.ReleaseDir(h.Node, fh)
		}
	case opFlush:
		fh := r.u64()
		r.u32()
		r.u32()
		owner := r.u64()
		if err = r.err; err == nil {
			err = fs.Flush(ctx, c, h.Node, fh, owner)
		}
	case opFsync, opFsyncdir:
		fh, flags := r.u64(), r.u32()
		if err = r.err; err == nil {
			if h.Opcode == opFsync {
				err = fs.Fsync(ctx, c, h.Node, fh, flags&fsyncDatasync != 0)
			} else {
				err = fs.FsyncDir(ctx, c, h.Node, fh, flags&fsyncDatasync != 0)
			}
		}
	case opReaddir:
		fh, off, size := r.u64(), r.u64(), r.u32()
		if err = r.err; err == nil {
			var ents []DirEntry
			if ents, err = fs.ReadDir(ctx, c, h.Node, fh, off); err == nil {
				for _, d := range ents {
					if !out.dirent(d, int(size)) {
						break
					}
				}
			}
		}
	case opGetlk, opSetlk, opSetlkw:
		fh, owner := r.u64(), r.u64()
		l := r.lock()
		lkFlags := r.u32()
		if err = r.err; err == nil {
			flock := lkFlags&lkFlock != 0
			if h.Opcode == opGetlk {
				var got Lock
				if got, err = fs.GetLk(ctx, c, h.Node, fh, owner, l, flock); err == nil {
					out.lock(got)
				}
			} else {
				err = fs.SetLk(ctx, c, h.Node, fh, owner, l, h.Opcode == opSetlkw, flock)
			}
		}
	default:
		err = syscall.ENOSYS
	}
	if errors.Is(err, errShort) {
		err = syscall.EINVAL
	}
	s.reply(h.Unique, errnoOf(ctx, err), out.b)
}
