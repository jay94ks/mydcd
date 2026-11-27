// SPDX-License-Identifier: Apache-2.0

package volumeshare

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"syscall"
	"time"
)

// Authorize says whether peer may use volume now and returns the Volume's
// Ops: the full Ops for a peer holding a writable pin, ReadOnly(Ops) for a
// reader. It must return the same value while the answer is the same. The
// home calls it when a server mounts, every Recheck while the mount is
// used, and before every change, so a write never relies on a time window:
// once the writer's pin is gone from the committed state, the next change
// is refused.
type Authorize func(ctx context.Context, peer [32]byte, volume string) (Ops, error)

// ServerOptions tunes the home side.
type ServerOptions struct {
	// Lease is how long a mount survives without any operation; the
	// client pings well within it. Then its files and locks are released.
	Lease time.Duration
	// Recheck is how often a used mount is authorized again.
	Recheck time.Duration
	Now     func() time.Time
}

// Server answers VolumeFS operations on the home.
type Server struct {
	auth Authorize
	o    ServerOptions

	mu       sync.Mutex
	sessions map[uint64]*session
}

type session struct {
	peer    [32]byte
	volume  string
	ops     Ops
	files   map[FileID]bool
	last    time.Time
	checked time.Time
}

// NewServer serves through auth.
func NewServer(auth Authorize, o ServerOptions) *Server {
	if o.Lease <= 0 {
		o.Lease = 15 * time.Second
	}
	if o.Recheck <= 0 {
		o.Recheck = 5 * time.Second
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Server{auth: auth, o: o, sessions: map[uint64]*session{}}
}

// Expire releases mounts idle past the lease. Run it about once a second.
func (s *Server) Expire() {
	now := s.o.Now()
	var gone []*session
	var ids []uint64
	s.mu.Lock()
	for id, x := range s.sessions {
		if now.Sub(x.last) > s.o.Lease {
			gone, ids = append(gone, x), append(ids, id)
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
	for i, x := range gone {
		x.ops.Release(ids[i])
	}
}

// Mounts reports how many mounts are open (for status).
func (s *Server) Mounts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func errnoOf(err error) uint32 {
	if err == nil {
		return 0
	}
	var e syscall.Errno
	if errors.As(err, &e) && e != 0 {
		return uint32(e)
	}
	return uint32(syscall.EIO)
}

// Handle answers one operation from peer. A returned error refuses the
// frame (no reply); file system failures are answered with an errno.
func (s *Server) Handle(ctx context.Context, peer [32]byte, header, data []byte) ([]byte, []byte, error) {
	var q wireRequest
	if err := json.Unmarshal(header, &q); err != nil || q.Schema != 1 {
		return nil, nil, errors.New("volumeshare: bad request")
	}
	reply, out := s.handle(ctx, peer, q, data)
	reply.Schema = 1
	raw, err := json.Marshal(reply)
	return raw, out, err
}

func (s *Server) handle(ctx context.Context, peer [32]byte, q wireRequest, data []byte) (wireReply, []byte) {
	fail := func(err error) (wireReply, []byte) { return wireReply{Errno: errnoOf(err)}, nil }
	if q.Op == opMount {
		ops, err := s.auth(ctx, peer, q.Volume)
		if err != nil || ops == nil {
			return wireReply{Errno: uint32(syscall.EACCES)}, nil
		}
		var b [8]byte
		if _, err = rand.Read(b[:]); err != nil {
			return fail(err)
		}
		id := binary.LittleEndian.Uint64(b[:]) | 1
		now := s.o.Now()
		s.mu.Lock()
		s.sessions[id] = &session{peer: peer, volume: q.Volume, ops: ops, files: map[FileID]bool{}, last: now, checked: now}
		s.mu.Unlock()
		return wireReply{Session: id, Root: ops.Root()}, nil
	}
	x, err := s.session(ctx, peer, q.Session, mutating(q))
	if err != nil {
		return fail(err)
	}
	ops := x.ops
	owns := func(f FileID) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !x.files[f] {
			return syscall.EBADF
		}
		return nil
	}
	switch q.Op {
	case opPing:
		return wireReply{}, nil
	case opUnmount:
		s.mu.Lock()
		delete(s.sessions, q.Session)
		s.mu.Unlock()
		ops.Release(q.Session)
		return wireReply{}, nil
	case opLookup:
		e, err := ops.Lookup(ctx, q.Dir, q.Name)
		if err != nil {
			return fail(err)
		}
		return wireReply{Entry: &e}, nil
	case opGetAttr:
		a, err := ops.GetAttr(ctx, q.Handle)
		if err != nil {
			return fail(err)
		}
		return wireReply{Attr: &a}, nil
	case opSetAttr:
		if q.Set == nil {
			return fail(syscall.EINVAL)
		}
		if q.Set.File != 0 {
			if err := owns(q.Set.File); err != nil {
				return fail(err)
			}
		}
		a, err := ops.SetAttr(ctx, q.Caller, q.Handle, *q.Set)
		if err != nil {
			return fail(err)
		}
		return wireReply{Attr: &a}, nil
	case opReadlink:
		t, err := ops.Readlink(ctx, q.Handle)
		if err != nil {
			return fail(err)
		}
		return wireReply{Target: t}, nil
	case opSymlink, opMkdir, opLink:
		var e Entry
		switch q.Op {
		case opSymlink:
			e, err = ops.Symlink(ctx, q.Caller, q.Dir, q.Name, q.Target)
		case opMkdir:
			e, err = ops.Mkdir(ctx, q.Caller, q.Dir, q.Name, q.Mode)
		default:
			e, err = ops.Link(ctx, q.Handle, q.Dir, q.Name)
		}
		if err != nil {
			return fail(err)
		}
		return wireReply{Entry: &e}, nil
	case opUnlink:
		return fail(ops.Unlink(ctx, q.Dir, q.Name))
	case opRmdir:
		return fail(ops.Rmdir(ctx, q.Dir, q.Name))
	case opRename:
		return fail(ops.Rename(ctx, q.Dir, q.Name, q.NewDir, q.NewName, q.Flags))
	case opReadDir:
		max := q.Max
		if max <= 0 || max > 512 {
			max = 512
		}
		rows, err := ops.ReadDir(ctx, q.Dir, q.Cookie, max)
		if err != nil {
			return fail(err)
		}
		return wireReply{Rows: rows}, nil
	case opStatFs:
		st, err := ops.StatFs(ctx)
		if err != nil {
			return fail(err)
		}
		return wireReply{StatFs: &st}, nil
	case opOpen, opCreate:
		var e Entry
		var f FileID
		if q.Op == opOpen {
			f, err = ops.Open(ctx, q.Session, q.Handle, q.Flags)
		} else {
			e, f, err = ops.Create(ctx, q.Session, q.Caller, q.Dir, q.Name, q.Flags, q.Mode)
		}
		if err != nil {
			return fail(err)
		}
		s.mu.Lock()
		x.files[f] = true
		s.mu.Unlock()
		if q.Op == opOpen {
			return wireReply{File: f}, nil
		}
		return wireReply{Entry: &e, File: f}, nil
	}
	if err := owns(q.File); err != nil {
		return fail(err)
	}
	switch q.Op {
	case opRead:
		if q.Size > maxData {
			q.Size = maxData
		}
		b, err := ops.Read(ctx, q.File, q.Off, q.Size)
		if err != nil {
			return fail(err)
		}
		return wireReply{}, b
	case opWrite:
		n, err := ops.Write(ctx, q.File, q.Off, data)
		if err != nil {
			return fail(err)
		}
		return wireReply{N: n}, nil
	case opFsync:
		return fail(ops.Fsync(ctx, q.File, q.Datasync))
	case opClose:
		s.mu.Lock()
		delete(x.files, q.File)
		s.mu.Unlock()
		return fail(ops.Close(q.File))
	case opGetLk, opSetLk:
		if q.Lock == nil {
			return fail(syscall.EINVAL)
		}
		if q.Op == opGetLk {
			l, err := ops.GetLk(ctx, q.File, q.Owner, *q.Lock, q.Flock)
			if err != nil {
				return fail(err)
			}
			return wireReply{Lock: &l}, nil
		}
		// The home never blocks a stream on a lock: the client polls.
		return fail(ops.SetLk(ctx, q.File, q.Owner, *q.Lock, false, q.Flock))
	case opRelOwner:
		return fail(ops.ReleaseOwner(q.File, q.Owner))
	}
	return fail(syscall.ENOSYS)
}

// maxData bounds one read reply (the SFCP VolumeFS data extension).
const maxData = 128 << 10

// session finds peer's mount and authorizes it again when due.
// mutating reports whether q may change the Volume.
func mutating(q wireRequest) bool {
	switch q.Op {
	case opSetAttr, opSymlink, opMkdir, opLink, opUnlink, opRmdir, opRename, opCreate, opWrite:
		return true
	case opOpen:
		return q.Flags&(syscall.O_WRONLY|syscall.O_RDWR|syscall.O_TRUNC|syscall.O_APPEND|syscall.O_CREAT) != 0
	case opSetLk:
		return q.Lock != nil && q.Lock.Type == syscall.F_WRLCK
	}
	return false
}

func (s *Server) session(ctx context.Context, peer [32]byte, id uint64, change bool) (*session, error) {
	now := s.o.Now()
	s.mu.Lock()
	x := s.sessions[id]
	if x == nil || x.peer != peer {
		s.mu.Unlock()
		return nil, syscall.ESTALE
	}
	x.last = now
	due := change || now.Sub(x.checked) >= s.o.Recheck
	s.mu.Unlock()
	if !due {
		return x, nil
	}
	if ops, err := s.auth(ctx, peer, x.volume); err != nil || ops != x.ops {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		x.ops.Release(id)
		return nil, syscall.EACCES
	}
	s.mu.Lock()
	x.checked = now
	s.mu.Unlock()
	return x, nil
}
