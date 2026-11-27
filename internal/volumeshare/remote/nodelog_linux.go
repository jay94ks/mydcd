// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/jay94ks/seafield/internal/fdstore"
	"github.com/jay94ks/seafield/internal/volumeshare/front/mount"
	"github.com/jay94ks/seafield/internal/volumeshare/fuse"
	"golang.org/x/sys/unix"
)

// nodeLog keeps one mount's FUSE session and node table in a memfd that
// lives in the service manager's FD store next to the /dev/fuse fd, so a
// restarted sfcd can answer the kernel's existing node IDs. It is an
// append log, rewritten into a new memfd (next generation) when it grows.
type nodeLog struct {
	mu      sync.Mutex
	base    string // fdstore name prefix (the engine volume name)
	fd      int
	off     int64
	gen     uint64
	session fuse.Session
	live    map[uint64]mount.Node
	stored  bool
	failed  bool
}

const (
	recSession = 'S'
	recPut     = 'P'
	recDrop    = 'D'
	compactAt  = 1 << 20
)

func devName(base string) string { return base + ".dev" }
func logName(base string, gen uint64) string {
	return base + ".n" + strconv.FormatUint(gen, 10)
}

func newMemfd(base string, gen uint64) (int, error) {
	return unix.MemfdCreate(logName(base, gen), unix.MFD_CLOEXEC)
}

// openNodeLog starts an empty log for a fresh mount.
func openNodeLog(base string, s fuse.Session) (*nodeLog, error) {
	l := &nodeLog{base: base, gen: 1, session: s, live: map[uint64]mount.Node{}}
	fd, err := newMemfd(base, l.gen)
	if err != nil {
		return nil, err
	}
	l.fd = fd
	if err = l.writeImage(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	l.store()
	return l, nil
}

func (l *nodeLog) store() {
	if !fdstore.Available() {
		return
	}
	if err := fdstore.Store(logName(l.base, l.gen), l.fd); err != nil {
		log.Printf("shared volume %s: node log not kept across restarts: %v", l.base, err)
		return
	}
	l.stored = true
}

func encodeNode(n mount.Node) []byte {
	b := make([]byte, 1+24+2+len(n.Handle))
	b[0] = recPut
	binary.LittleEndian.PutUint64(b[1:], n.ID)
	binary.LittleEndian.PutUint64(b[9:], n.Ino)
	binary.LittleEndian.PutUint64(b[17:], n.Refs)
	binary.LittleEndian.PutUint16(b[25:], uint16(len(n.Handle)))
	copy(b[27:], n.Handle)
	return b
}

func encodeSession(s fuse.Session) []byte {
	b := make([]byte, 13)
	b[0] = recSession
	binary.LittleEndian.PutUint32(b[1:], s.Minor)
	binary.LittleEndian.PutUint32(b[5:], s.Flags)
	binary.LittleEndian.PutUint32(b[9:], s.MaxWrite)
	return b
}

// writeImage writes the whole state at offset 0 of l.fd.
func (l *nodeLog) writeImage() error {
	img := encodeSession(l.session)
	ids := make([]uint64, 0, len(l.live))
	for id := range l.live {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		img = append(img, encodeNode(l.live[id])...)
	}
	if err := unix.Ftruncate(l.fd, 0); err != nil {
		return err
	}
	if _, err := unix.Pwrite(l.fd, img, 0); err != nil {
		return err
	}
	l.off = int64(len(img))
	return nil
}

func (l *nodeLog) appendRecord(b []byte) {
	if l.failed {
		return
	}
	if _, err := unix.Pwrite(l.fd, b, l.off); err != nil {
		l.failed = true
		log.Printf("shared volume %s: node log stopped (resume after restart lost): %v", l.base, err)
		return
	}
	l.off += int64(len(b))
	if l.off > compactAt && l.off > int64(8*(len(l.live)+1)*64) {
		l.compact()
	}
}

// compact moves the state to a new memfd of the next generation: stored
// first, the old one removed after, so a crash between keeps a full one.
func (l *nodeLog) compact() {
	fd, err := newMemfd(l.base, l.gen+1)
	if err != nil {
		return
	}
	old, oldGen, wasStored := l.fd, l.gen, l.stored
	l.fd, l.gen, l.stored = fd, l.gen+1, false
	if err = l.writeImage(); err != nil {
		unix.Close(fd)
		l.fd, l.gen, l.stored = old, oldGen, wasStored
		return
	}
	l.store()
	if wasStored {
		_ = fdstore.Remove(logName(l.base, oldGen))
	}
	unix.Close(old)
}

func (l *nodeLog) Put(n mount.Node) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n.Handle = append([]byte(nil), n.Handle...)
	l.live[n.ID] = n
	l.appendRecord(encodeNode(n))
}

func (l *nodeLog) Drop(id uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.live, id)
	b := make([]byte, 9)
	b[0] = recDrop
	binary.LittleEndian.PutUint64(b[1:], id)
	l.appendRecord(b)
}

// nodes is the restored table for mount.Options.Restore.
func (l *nodeLog) nodes() []mount.Node {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]mount.Node, 0, len(l.live))
	for _, n := range l.live {
		out = append(out, n)
	}
	return out
}

// setSession records the session INIT negotiated (fuse OnInit).
func (l *nodeLog) setSession(s fuse.Session) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.session = s
	if _, err := unix.Pwrite(l.fd, encodeSession(s), 0); err != nil {
		l.failed = true
	}
}

// release closes our copy only; the stored log stays for another try.
func (l *nodeLog) release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	unix.Close(l.fd)
	l.failed = true
}

// close forgets the log and removes it from the store (the mount ended).
func (l *nodeLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stored {
		_ = fdstore.Remove(logName(l.base, l.gen))
	}
	unix.Close(l.fd)
	l.failed = true
}

// parseNodeLog reads a log back. A torn last record is dropped.
func parseNodeLog(base string, gen uint64, f *os.File) (*nodeLog, error) {
	raw, err := io.ReadAll(io.NewSectionReader(f, 0, 1<<40))
	if err != nil {
		return nil, err
	}
	l := &nodeLog{base: base, gen: gen, live: map[uint64]mount.Node{}, stored: true}
	if len(raw) < 13 || raw[0] != recSession {
		return nil, errors.New("shared volume: node log without a session")
	}
	l.session = fuse.Session{Minor: binary.LittleEndian.Uint32(raw[1:]), Flags: binary.LittleEndian.Uint32(raw[5:]), MaxWrite: binary.LittleEndian.Uint32(raw[9:])}
	at := 13 // end of the last whole record
	for at < len(raw) {
		p := raw[at:]
		switch {
		case p[0] == recPut && len(p) >= 27 && len(p) >= 27+int(binary.LittleEndian.Uint16(p[25:])):
			h := int(binary.LittleEndian.Uint16(p[25:]))
			n := mount.Node{ID: binary.LittleEndian.Uint64(p[1:]), Ino: binary.LittleEndian.Uint64(p[9:]), Refs: binary.LittleEndian.Uint64(p[17:]), Handle: append([]byte(nil), p[27:27+h]...)}
			l.live[n.ID] = n
			at += 27 + h
		case p[0] == recDrop && len(p) >= 9:
			delete(l.live, binary.LittleEndian.Uint64(p[1:]))
			at += 9
		case p[0] == recPut || p[0] == recDrop:
			at = len(raw) + 1 // torn tail: stop here
		default:
			return nil, errors.New("shared volume: bad node log record")
		}
	}
	// Keep writing to a private copy: the stored fd stays as it is until
	// this log replaces it (the next compaction writes generation+1).
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	l.fd = fd
	l.off = int64(len(raw))
	if at > len(raw) {
		// A torn tail: write a clean image so the next record follows a
		// whole one.
		if err = l.writeImage(); err != nil {
			unix.Close(fd)
			return nil, err
		}
	}
	return l, nil
}

// inheritedLog picks the newest stored log generation of base and drops
// older ones from the store.
func inheritedLog(base string) (*nodeLog, error) {
	prefix := base + ".n"
	var best uint64
	for _, name := range fdstore.Names() {
		if g, err := strconv.ParseUint(strings.TrimPrefix(name, prefix), 10, 64); strings.HasPrefix(name, prefix) && err == nil && g > best {
			best = g
		}
	}
	if best == 0 {
		return nil, nil
	}
	var l *nodeLog
	var err error
	for _, name := range fdstore.Names() {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		g, _ := strconv.ParseUint(strings.TrimPrefix(name, prefix), 10, 64)
		for _, f := range fdstore.Take(name) {
			if g == best && l == nil && err == nil {
				l, err = parseNodeLog(base, g, f)
			}
			_ = f.Close()
		}
		if g != best {
			_ = fdstore.Remove(name)
		}
	}
	return l, err
}
