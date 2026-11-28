// SPDX-License-Identifier: Apache-2.0

// Package diskfs is the fuse disk bundle (devel/proposals/
// devel/design/node-disk-bundles.md §2-5): sfcimg chunk files on existing
// partitions joined into one virtual disk, served as a single FUSE file
// that sfcd attaches to a loop device and formats ext4. It runs in its own
// process (sfcd diskfs serve), so an sfcd restart never drops the mount.
package diskfs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/jay94ks/seafield/internal/observability"
	"github.com/jay94ks/seafield/internal/sfcimg"
)

// RunDir holds one directory per bundle: the FUSE mount (file "disk") and
// status.json.
const RunDir = observability.FuseBundleRun

// Spec is what sfcd hands the diskfs process.
type Spec struct {
	Schema uint8
	Bundle string
	ID     [16]byte
	Mode   string // linear | mirror
	// Copies: linear has one; a mirror one per copy. Each lists its chunks
	// in virtual order.
	Copies [][]ChunkSpec
}

// ChunkSpec is one chunk file: Dir is the bundle directory on the member
// partition (<mount>/.sfc-disks/<bundle>), File the chunk's name in it.
type ChunkSpec struct {
	Dir, File     string
	Start, Length uint64
	// Disk and Part name the member for status (as recorded).
	Disk, Part string
}

func (s Spec) Valid() bool {
	if s.Schema != 1 || s.Bundle == "" || (s.Mode != "linear" && s.Mode != "mirror") || len(s.Copies) == 0 || s.Mode == "linear" && len(s.Copies) != 1 || s.Mode == "mirror" && len(s.Copies) < 2 {
		return false
	}
	for _, chunks := range s.Copies {
		next := uint64(0)
		for _, c := range chunks {
			if c.Start != next || c.Length == 0 || c.Length > sfcimg.MaxChunk || !filepath.IsAbs(c.Dir) || filepath.Base(c.File) != c.File {
				return false
			}
			next += c.Length
		}
		if next == 0 {
			return false
		}
	}
	return true
}

type chunk struct {
	spec ChunkSpec
	img  *sfcimg.Image
}

type copyState struct {
	chunks []chunk
	size   uint64
	ok     bool
	// dirty marks regions this copy missed (mirror), persisted as
	// sync-<n> in every healthy copy's directories.
	dirty   map[uint64]bool
	syncing bool
}

// Disk is the virtual disk.
type Disk struct {
	mu     sync.RWMutex
	spec   Spec
	size   uint64
	copies []*copyState
	// status changes are pushed here (non-blocking).
	changed chan struct{}
}

// Open opens every chunk. A linear bundle needs all of them; a mirror needs
// at least one whole copy, and a copy with a chunk missing runs degraded.
func Open(spec Spec) (*Disk, error) {
	if !spec.Valid() {
		return nil, errors.New("diskfs: invalid spec")
	}
	d := &Disk{spec: spec, changed: make(chan struct{}, 1)}
	for _, chunks := range spec.Copies {
		c := &copyState{ok: true, dirty: map[uint64]bool{}}
		for _, cs := range chunks {
			img, err := sfcimg.Open(filepath.Join(cs.Dir, cs.File))
			if err == nil && (img.Header().Start != cs.Start || img.Header().Length != cs.Length || img.Header().Bundle != spec.ID) {
				img.Close()
				err = fmt.Errorf("chunk %s does not belong here", cs.File)
			}
			if err != nil {
				c.ok = false
			}
			c.chunks = append(c.chunks, chunk{spec: cs, img: img})
			c.size += cs.Length
		}
		if !c.ok && spec.Mode == "linear" {
			d.Close()
			return nil, fmt.Errorf("diskfs: a chunk of linear bundle %s is missing", spec.Bundle)
		}
		d.copies = append(d.copies, c)
	}
	d.size = d.copies[0].size
	for _, c := range d.copies {
		d.size = min(d.size, c.size)
	}
	healthy := 0
	for _, c := range d.copies {
		if c.ok {
			healthy++
		}
	}
	if healthy == 0 {
		d.Close()
		return nil, fmt.Errorf("diskfs: no whole copy of bundle %s", spec.Bundle)
	}
	d.loadDirty()
	return d, nil
}

func (d *Disk) Size() uint64 { return d.size }

func (d *Disk) Close() error {
	var errs []error
	for _, c := range d.copies {
		for _, ch := range c.chunks {
			if ch.img != nil {
				errs = append(errs, ch.img.Close())
			}
		}
	}
	return errors.Join(errs...)
}

// span calls fn for each chunk piece of [off, off+n) in copy c.
func (c *copyState) span(off, n uint64, fn func(ch chunk, chunkOff, bufOff, length uint64) error) error {
	end := off + n
	for _, ch := range c.chunks {
		s, e := ch.spec.Start, ch.spec.Start+ch.spec.Length
		if e <= off || s >= end {
			continue
		}
		from, to := max(off, s), min(end, e)
		if err := fn(ch, from-s, from-off, to-from); err != nil {
			return err
		}
	}
	return nil
}

// ReadAt reads from the first healthy copy that is not still being
// filled; a copy that fails is taken out (mirror) and the next one tried.
func (d *Disk) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || uint64(off)+uint64(len(p)) > d.size {
		return 0, sfcimg.ErrRange
	}
	for {
		d.mu.RLock()
		var c *copyState
		for _, x := range d.copies {
			if x.ok && !x.dirtyIn(uint64(off), uint64(len(p))) {
				c = x
				break
			}
		}
		if c == nil {
			d.mu.RUnlock()
			return 0, errors.New("diskfs: no healthy copy")
		}
		err := c.span(uint64(off), uint64(len(p)), func(ch chunk, co, bo, n uint64) error {
			_, err := ch.img.ReadAt(p[bo:bo+n], int64(co))
			return err
		})
		d.mu.RUnlock()
		if err == nil {
			return len(p), nil
		}
		if !d.fail(c) {
			return 0, err
		}
	}
}

func (c *copyState) dirtyIn(off, n uint64) bool {
	if len(c.dirty) == 0 {
		return false
	}
	for r := off / sfcimg.RegionSize; r <= (off+n-1)/sfcimg.RegionSize; r++ {
		if c.dirty[r] {
			return true
		}
	}
	return false
}

// WriteAt writes every healthy copy. A copy that fails is taken out and the
// regions it misses from then on are marked for the resync.
func (d *Disk) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || uint64(off)+uint64(len(p)) > d.size {
		return 0, sfcimg.ErrRange
	}
	// The read lock is held through the writes, so a resync (which holds
	// the write lock per region) never copies around a write.
	d.mu.RLock()
	written, failed := 0, []*copyState{}
	var lastErr error
	for _, c := range d.copies {
		if !c.ok {
			continue
		}
		err := c.span(uint64(off), uint64(len(p)), func(ch chunk, co, bo, n uint64) error {
			_, err := ch.img.WriteAt(p[bo:bo+n], int64(co))
			return err
		})
		if err != nil {
			failed, lastErr = append(failed, c), err
			continue
		}
		written++
	}
	d.mu.RUnlock()
	for _, c := range failed {
		if !d.fail(c) && written == 0 {
			return 0, lastErr
		}
	}
	if written == 0 {
		return 0, errors.New("diskfs: no copy took the write")
	}
	if err := d.markMissed(uint64(off), uint64(len(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// fail takes a mirror copy out. It returns false when it was the last one
// (or the bundle is linear), so the error goes up.
func (d *Disk) fail(c *copyState) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	healthy := 0
	for _, x := range d.copies {
		if x.ok && x != c {
			healthy++
		}
	}
	if d.spec.Mode != "mirror" || healthy == 0 {
		return false
	}
	c.ok = false
	d.notify()
	return true
}

// markMissed records the regions of [off, off+n) for every copy that is
// out, before the write is acknowledged.
func (d *Disk) markMissed(off, n uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	changed := false
	for _, c := range d.copies {
		if c.ok {
			continue
		}
		for r := off / sfcimg.RegionSize; r <= (off+n-1)/sfcimg.RegionSize; r++ {
			if !c.dirty[r] {
				c.dirty[r], changed = true, true
			}
		}
	}
	if changed {
		return d.saveDirty()
	}
	return nil
}

type dirtyFile struct {
	Copy    int
	Regions []uint64
}

func (d *Disk) dirtyPaths(of int) []string {
	paths := []string{}
	for n, c := range d.copies {
		if n == of || !c.ok {
			continue
		}
		for _, ch := range c.chunks {
			paths = append(paths, filepath.Join(ch.spec.Dir, fmt.Sprintf("sync-%d", of+1)))
		}
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// saveDirty writes each out copy's missed regions next to the healthy
// copies' chunks (the caller holds mu).
func (d *Disk) saveDirty() error {
	for n, c := range d.copies {
		regions := make([]uint64, 0, len(c.dirty))
		for r := range c.dirty {
			regions = append(regions, r)
		}
		slices.Sort(regions)
		raw, _ := json.Marshal(dirtyFile{Copy: n + 1, Regions: regions})
		for _, path := range d.dirtyPaths(n) {
			if len(regions) == 0 {
				_ = os.Remove(path)
				continue
			}
			tmp := path + ".tmp"
			if err := os.WriteFile(tmp, raw, 0o600); err != nil {
				return err
			}
			f, err := os.Open(tmp)
			if err == nil {
				err = f.Sync()
				f.Close()
			}
			if err != nil {
				return err
			}
			if err := os.Rename(tmp, path); err != nil {
				return err
			}
		}
	}
	return nil
}

// loadDirty reads the missed regions the healthy copies kept; a copy that
// was out and is back gets them resynced.
func (d *Disk) loadDirty() {
	for n, c := range d.copies {
		for _, path := range d.dirtyPaths(n) {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var f dirtyFile
			if json.Unmarshal(raw, &f) == nil && f.Copy == n+1 {
				for _, r := range f.Regions {
					c.dirty[r] = true
				}
			}
		}
	}
}

func (d *Disk) notify() {
	select {
	case d.changed <- struct{}{}:
	default:
	}
}

// Sync flushes every healthy copy.
func (d *Disk) Sync() error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var errs []error
	for _, c := range d.copies {
		if !c.ok {
			continue
		}
		for _, ch := range c.chunks {
			errs = append(errs, ch.img.Sync())
		}
	}
	return errors.Join(errs...)
}

// Resync copies the missed regions to each copy that is open again. It
// runs until done or stop closes.
func (d *Disk) Resync(stop <-chan struct{}) {
	buf := make([]byte, sfcimg.RegionSize)
	for n := range d.copies {
		d.mu.Lock()
		c := d.copies[n]
		if !c.ok || len(c.dirty) == 0 {
			d.mu.Unlock()
			continue
		}
		c.syncing = true
		d.notify()
		d.mu.Unlock()
		for {
			select {
			case <-stop:
				return
			default:
			}
			d.mu.Lock()
			var region uint64
			found := false
			for r := range c.dirty {
				if !found || r < region {
					region, found = r, true
				}
			}
			d.mu.Unlock()
			if !found {
				break
			}
			off := region * sfcimg.RegionSize
			n := min(uint64(sfcimg.RegionSize), d.size-off)
			// The copy is read from the others under the read lock of a
			// write-free moment: hold mu so no write lands between.
			d.mu.Lock()
			var src *copyState
			for _, x := range d.copies {
				if x != c && x.ok && !x.dirtyIn(off, n) {
					src = x
					break
				}
			}
			err := errors.New("diskfs: no source copy")
			if src != nil {
				err = src.span(off, n, func(ch chunk, co, bo, l uint64) error {
					_, e := ch.img.ReadAt(buf[bo:bo+l], int64(co))
					return e
				})
				if err == nil {
					err = c.span(off, n, func(ch chunk, co, bo, l uint64) error {
						_, e := ch.img.WriteAt(buf[bo:bo+l], int64(co))
						return e
					})
				}
			}
			if err == nil {
				delete(c.dirty, region)
				if len(c.dirty)%64 == 0 {
					err = d.saveDirty()
				}
			}
			if err != nil {
				c.ok, c.syncing = false, false
				d.notify()
				d.mu.Unlock()
				break
			}
			d.mu.Unlock()
		}
		d.mu.Lock()
		if c.ok {
			c.syncing = false
			for _, ch := range c.chunks {
				_ = ch.img.Sync()
			}
			_ = d.saveDirty()
		}
		d.notify()
		d.mu.Unlock()
	}
}

// Status is status.json, which sfcd reads for the device report.
type Status struct {
	Bundle      string
	Size        uint64
	State       string // ok | degraded | syncing
	SyncPercent uint8
	Copies      []CopyStatus
}

type CopyStatus struct {
	Copy  int
	State string // ok | missing | syncing
	Disks []string
}

func (d *Disk) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	s := Status{Bundle: d.spec.Bundle, Size: d.size, State: "ok"}
	regions := int((d.size + sfcimg.RegionSize - 1) / sfcimg.RegionSize)
	total, left := 0, 0
	for n, c := range d.copies {
		cs := CopyStatus{Copy: n + 1, State: "ok"}
		for _, ch := range c.chunks {
			if !slices.Contains(cs.Disks, ch.spec.Part) {
				cs.Disks = append(cs.Disks, ch.spec.Part)
			}
		}
		switch {
		case !c.ok:
			cs.State = "missing"
			if s.State == "ok" {
				s.State = "degraded"
			}
		case c.syncing || len(c.dirty) > 0:
			cs.State = "syncing"
			if s.State == "ok" {
				s.State = "syncing"
			}
			left += len(c.dirty)
			total += regions
		}
		s.Copies = append(s.Copies, cs)
	}
	if s.State == "syncing" && total > 0 {
		s.SyncPercent = uint8(100 - min(100, left*100/total))
	}
	return s
}
