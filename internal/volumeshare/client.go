// SPDX-License-Identifier: Apache-2.0

package volumeshare

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"syscall"
	"time"
)

// Call sends one VolumeFS operation to the home and returns its reply. The
// SFCP side is sfcp.Session.CallVolumeFS on a session to the home,
// found again for every call so a reconnect is picked up.
type Call func(ctx context.Context, header, data []byte) (reply, replyData []byte, err error)

// ClientOptions tunes the consuming side.
type ClientOptions struct {
	Volume string
	// Sent reports whether a failed call may have reached the home
	// (sfcp.CallSent). Without it every failure counts as sent.
	Sent func(error) bool
	// Ping keeps the mount's lease; keep it well under the home's Lease.
	Ping time.Duration
	// Retry is how long a call that never left is tried again while the
	// home is unreachable. Then the operation fails with EIO.
	Retry time.Duration
	// Timeout bounds calls made without a caller context (close, release).
	Timeout time.Duration
}

// Client is a Volume served by another server: Ops over VolumeFS.
//
// When the home forgets the mount (it restarted, or the lease ran out while
// the network was down) the client mounts again. Handles stay valid; open
// files and locks of the old mount are gone and report EBADF.
type Client struct {
	call Call
	o    ClientOptions

	mu      sync.Mutex
	session uint64
	root    Handle
	appends map[FileID]bool // O_APPEND files: a resent write would append twice
}

// Dial mounts volume through call.
func Dial(ctx context.Context, call Call, o ClientOptions) (*Client, error) {
	if o.Sent == nil {
		o.Sent = func(error) bool { return true }
	}
	if o.Ping <= 0 {
		o.Ping = 5 * time.Second
	}
	if o.Retry <= 0 {
		o.Retry = 30 * time.Second
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	c := &Client{call: call, o: o, appends: map[FileID]bool{}}
	if _, err := c.mount(ctx, 0); err != nil {
		return nil, err
	}
	return c, nil
}

// Session is the mount on the home; open files and locks belong to it.
func (c *Client) Session() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.session
}

// Run keeps the lease until ctx ends, then unmounts.
func (c *Client) Run(ctx context.Context) {
	t := time.NewTicker(c.o.Ping)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Release(0)
			return
		case <-t.C:
			_, _, _ = c.do(ctx, wireRequest{Op: opPing}, nil)
		}
	}
}

// mount replaces session old with a new one (or keeps a newer one another
// call already made).
func (c *Client) mount(ctx context.Context, old uint64) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session != old {
		return c.session, nil
	}
	r, _, err := c.send(ctx, wireRequest{Op: opMount, Volume: c.o.Volume}, nil)
	if err != nil {
		return 0, err
	}
	if r.Session == 0 || len(r.Root) == 0 {
		return 0, syscall.EIO
	}
	c.session, c.root = r.Session, r.Root
	return c.session, nil
}

// do runs one operation on the current mount, mounting again once when
// the home no longer knows it.
func (c *Client) do(ctx context.Context, q wireRequest, data []byte) (wireReply, []byte, error) {
	session := c.Session()
	for again := true; ; again = false {
		q.Session = session
		r, out, err := c.send(ctx, q, data)
		if err == syscall.ESTALE && again {
			if session, err = c.mount(ctx, session); err != nil {
				return wireReply{}, nil, err
			}
			continue
		}
		return r, out, err
	}
}

// send delivers q once, trying again while it did not leave (and, for
// retry-safe operations, while its outcome is unknown). A home errno comes
// back as a syscall.Errno.
func (c *Client) send(ctx context.Context, q wireRequest, data []byte) (wireReply, []byte, error) {
	q.Schema = 1
	header, err := json.Marshal(q)
	if err != nil {
		return wireReply{}, nil, err
	}
	deadline := time.Now().Add(c.o.Retry)
	wait := 50 * time.Millisecond
	for {
		raw, out, err := c.call(ctx, header, data)
		if err == nil {
			var r wireReply
			if json.Unmarshal(raw, &r) != nil || r.Schema != 1 {
				return wireReply{}, nil, syscall.EIO
			}
			if r.Errno != 0 {
				return r, nil, syscall.Errno(r.Errno)
			}
			return r, out, nil
		}
		if ctx.Err() != nil {
			return wireReply{}, nil, syscall.EINTR
		}
		if c.o.Sent(err) && !c.retrySafe(q) || time.Now().After(deadline) {
			return wireReply{}, nil, syscall.EIO
		}
		if !sleep(ctx, wait) {
			return wireReply{}, nil, syscall.EINTR
		}
		wait = min(2*wait, time.Second)
	}
}

func (c *Client) retrySafe(q wireRequest) bool {
	if q.Op == opWrite {
		c.mu.Lock()
		defer c.mu.Unlock()
		return !c.appends[q.File]
	}
	return retrySafe[q.Op]
}

func (c *Client) opened(f FileID, flags uint32, err error) {
	if err == nil && flags&syscall.O_APPEND != 0 {
		c.mu.Lock()
		c.appends[f] = true
		c.mu.Unlock()
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (c *Client) background() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.o.Timeout)
}

func (c *Client) Root() Handle {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.root
}

func entry(r wireReply, _ []byte, err error) (Entry, error) {
	if err != nil {
		return Entry{}, err
	}
	if r.Entry == nil {
		return Entry{}, syscall.EIO
	}
	return *r.Entry, nil
}

func attr(r wireReply, err error) (Attr, error) {
	if err != nil {
		return Attr{}, err
	}
	if r.Attr == nil {
		return Attr{}, syscall.EIO
	}
	return *r.Attr, nil
}

func (c *Client) Lookup(ctx context.Context, dir Handle, name string) (Entry, error) {
	return entry(c.do(ctx, wireRequest{Op: opLookup, Dir: dir, Name: name}, nil))
}

func (c *Client) GetAttr(ctx context.Context, h Handle) (Attr, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opGetAttr, Handle: h}, nil)
	return attr(r, err)
}

func (c *Client) SetAttr(ctx context.Context, who Caller, h Handle, in SetAttr) (Attr, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opSetAttr, Caller: who, Handle: h, Set: &in}, nil)
	return attr(r, err)
}

func (c *Client) Readlink(ctx context.Context, h Handle) (string, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opReadlink, Handle: h}, nil)
	return r.Target, err
}

func (c *Client) Symlink(ctx context.Context, who Caller, dir Handle, name, target string) (Entry, error) {
	return entry(c.do(ctx, wireRequest{Op: opSymlink, Caller: who, Dir: dir, Name: name, Target: target}, nil))
}

func (c *Client) Mkdir(ctx context.Context, who Caller, dir Handle, name string, mode uint32) (Entry, error) {
	return entry(c.do(ctx, wireRequest{Op: opMkdir, Caller: who, Dir: dir, Name: name, Mode: mode}, nil))
}

func (c *Client) Unlink(ctx context.Context, dir Handle, name string) error {
	_, _, err := c.do(ctx, wireRequest{Op: opUnlink, Dir: dir, Name: name}, nil)
	return err
}

func (c *Client) Rmdir(ctx context.Context, dir Handle, name string) error {
	_, _, err := c.do(ctx, wireRequest{Op: opRmdir, Dir: dir, Name: name}, nil)
	return err
}

func (c *Client) Rename(ctx context.Context, dir Handle, name string, newDir Handle, newName string, flags uint32) error {
	_, _, err := c.do(ctx, wireRequest{Op: opRename, Dir: dir, Name: name, NewDir: newDir, NewName: newName, Flags: flags}, nil)
	return err
}

func (c *Client) Link(ctx context.Context, h, dir Handle, name string) (Entry, error) {
	return entry(c.do(ctx, wireRequest{Op: opLink, Handle: h, Dir: dir, Name: name}, nil))
}

func (c *Client) ReadDir(ctx context.Context, dir Handle, cookie uint64, max int) ([]DirEntry, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opReadDir, Dir: dir, Cookie: cookie, Max: max}, nil)
	return r.Rows, err
}

func (c *Client) StatFs(ctx context.Context) (StatFs, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opStatFs}, nil)
	if err != nil {
		return StatFs{}, err
	}
	if r.StatFs == nil {
		return StatFs{}, syscall.EIO
	}
	return *r.StatFs, nil
}

// Open ignores session: files belong to the client's own mount.
func (c *Client) Open(ctx context.Context, _ uint64, h Handle, flags uint32) (FileID, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opOpen, Handle: h, Flags: flags}, nil)
	c.opened(r.File, flags, err)
	return r.File, err
}

func (c *Client) Create(ctx context.Context, _ uint64, who Caller, dir Handle, name string, flags, mode uint32) (Entry, FileID, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opCreate, Caller: who, Dir: dir, Name: name, Flags: flags, Mode: mode}, nil)
	e, err := entry(r, nil, err)
	c.opened(r.File, flags, err)
	return e, r.File, err
}

func (c *Client) Read(ctx context.Context, f FileID, off uint64, size uint32) ([]byte, error) {
	if size > maxData {
		size = maxData
	}
	_, out, err := c.do(ctx, wireRequest{Op: opRead, File: f, Off: off, Size: size}, nil)
	return out, err
}

func (c *Client) Write(ctx context.Context, f FileID, off uint64, data []byte) (uint32, error) {
	if len(data) > maxData {
		data = data[:maxData]
	}
	r, _, err := c.do(ctx, wireRequest{Op: opWrite, File: f, Off: off}, data)
	return r.N, err
}

func (c *Client) Fsync(ctx context.Context, f FileID, datasync bool) error {
	_, _, err := c.do(ctx, wireRequest{Op: opFsync, File: f, Datasync: datasync}, nil)
	return err
}

func (c *Client) Close(f FileID) error {
	ctx, cancel := c.background()
	defer cancel()
	_, _, err := c.do(ctx, wireRequest{Op: opClose, File: f}, nil)
	c.mu.Lock()
	delete(c.appends, f)
	c.mu.Unlock()
	return err
}

func (c *Client) GetLk(ctx context.Context, f FileID, owner uint64, l Lock, flock bool) (Lock, error) {
	r, _, err := c.do(ctx, wireRequest{Op: opGetLk, File: f, Owner: owner, Lock: &l, Flock: flock}, nil)
	if err != nil {
		return Lock{}, err
	}
	if r.Lock == nil {
		return Lock{}, syscall.EIO
	}
	return *r.Lock, nil
}

// SetLk never blocks the home: a waiting lock is asked for again until it
// is granted or ctx ends.
func (c *Client) SetLk(ctx context.Context, f FileID, owner uint64, l Lock, wait, flock bool) error {
	pause := 5 * time.Millisecond
	for {
		_, _, err := c.do(ctx, wireRequest{Op: opSetLk, File: f, Owner: owner, Lock: &l, Flock: flock}, nil)
		if !wait || !errors.Is(err, syscall.EAGAIN) {
			return err
		}
		if !sleep(ctx, pause) {
			return syscall.EINTR
		}
		pause = min(2*pause, 200*time.Millisecond)
	}
}

func (c *Client) ReleaseOwner(f FileID, owner uint64) error {
	ctx, cancel := c.background()
	defer cancel()
	_, _, err := c.do(ctx, wireRequest{Op: opRelOwner, File: f, Owner: owner}, nil)
	return err
}

// Release unmounts; the home drops the mount's files and locks.
func (c *Client) Release(uint64) {
	ctx, cancel := c.background()
	defer cancel()
	c.mu.Lock()
	session := c.session
	c.mu.Unlock()
	if session != 0 {
		_, _, _ = c.send(ctx, wireRequest{Op: opUnmount, Session: session}, nil)
	}
}

var _ Ops = (*Client)(nil)
