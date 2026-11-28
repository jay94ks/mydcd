// SPDX-License-Identifier: Apache-2.0

package diskfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jay94ks/seafield/internal/sfcimg"
)

// Plan splits each member's bytes into chunks of at most sfcimg.MaxChunk.
// members are per copy, in order: {dir, bytes, disk, part}.
type Member struct {
	Dir        string
	Bytes      uint64
	Disk, Part string
}

// Layout builds the chunk list of a copy from its members.
func Layout(members []Member) []ChunkSpec {
	out := []ChunkSpec{}
	start := uint64(0)
	for _, m := range members {
		left := m.Bytes / sfcimg.RegionSize * sfcimg.RegionSize
		for left > 0 {
			n := min(left, sfcimg.MaxChunk)
			out = append(out, ChunkSpec{Dir: m.Dir, File: fmt.Sprintf("%03d.sfcimg", len(out)), Start: start, Length: n, Disk: m.Disk, Part: m.Part})
			start, left = start+n, left-n
		}
	}
	return out
}

// Create makes every chunk file of spec. A reserve bundle allocates all of
// its space now and fails when a partition is short; on failure the files
// made so far are removed.
func Create(spec Spec, grow bool) error {
	if !spec.Valid() {
		return errors.New("diskfs: invalid spec")
	}
	made := []string{}
	fail := func(err error) error {
		for _, p := range made {
			os.Remove(p)
		}
		return err
	}
	mode := uint8(0)
	if spec.Mode == "mirror" {
		mode = 1
	}
	for n, chunks := range spec.Copies {
		for i, c := range chunks {
			if err := os.MkdirAll(c.Dir, 0o700); err != nil {
				return fail(err)
			}
			copyNumber := uint8(0)
			if mode == 1 {
				copyNumber = uint8(n + 1)
			}
			path := filepath.Join(c.Dir, c.File)
			img, err := sfcimg.Create(path, sfcimg.Header{Bundle: spec.ID, Mode: mode, Grow: grow, Copy: copyNumber, Index: uint32(i), Start: c.Start, Length: c.Length, Generation: 1})
			if err != nil {
				return fail(fmt.Errorf("chunk %s: %w", path, err))
			}
			img.Close()
			made = append(made, path)
		}
	}
	return nil
}

// Remove deletes the chunk files and sync marks of spec and the bundle
// directories when empty.
func Remove(spec Spec) error {
	var errs []error
	for _, chunks := range spec.Copies {
		for _, c := range chunks {
			if err := os.Remove(filepath.Join(c.Dir, c.File)); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			for k := range spec.Copies {
				_ = os.Remove(filepath.Join(c.Dir, fmt.Sprintf("sync-%d", k+1)))
			}
			_ = os.Remove(c.Dir)
		}
	}
	return errors.Join(errs...)
}
