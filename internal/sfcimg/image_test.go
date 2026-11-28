// SPDX-License-Identifier: Apache-2.0

package sfcimg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestChunkReserveAndGrow(t *testing.T) {
	for _, grow := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "000.sfcimg")
		h := Header{Bundle: [16]byte{1}, Grow: grow, Index: 0, Start: 0, Length: 5*RegionSize + 100, Generation: 1}
		img, err := Create(path, h)
		if err != nil {
			t.Fatal(err)
		}
		st, _ := os.Stat(path)
		if grow && st.Size() != h.DataOffset() || !grow && st.Size() != h.DataOffset()+int64(h.Length) {
			t.Fatal("size", grow, st.Size())
		}
		data := bytes.Repeat([]byte("abcdefgh"), 300000) // spans regions
		if _, err := img.WriteAt(data, RegionSize-10); err != nil {
			t.Fatal(err)
		}
		if _, err := img.WriteAt([]byte("tail"), int64(h.Length-4)); err != nil {
			t.Fatal(err)
		}
		if _, err := img.WriteAt([]byte("x"), int64(h.Length)); err != ErrRange {
			t.Fatal("past the end", err)
		}
		if err := img.Sync(); err != nil {
			t.Fatal(err)
		}
		img.Close()
		img, err = Open(path)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(data))
		if _, err := img.ReadAt(got, RegionSize-10); err != nil || !bytes.Equal(got, data) {
			t.Fatal("read back", grow, err)
		}
		zero := make([]byte, 10)
		if _, err := img.ReadAt(zero, 5); err != nil || !bytes.Equal(zero, make([]byte, 10)) {
			t.Fatal("unwritten reads zero", err)
		}
		if grow && (img.Allocated() != 5*RegionSize || !img.Written(0) || img.Written(4*RegionSize)) {
			t.Fatal("allocated", img.Allocated())
		}
		img.Close()
		if hh, _, err := Check(path); err != nil || hh != h {
			t.Fatal("check", hh, err)
		}
	}
}

func TestChunkSurvivesAnUnmappedAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "000.sfcimg")
	h := Header{Grow: true, Length: 3 * RegionSize, Generation: 1}
	img, err := Create(path, h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := img.WriteAt([]byte("keep"), 0); err != nil {
		t.Fatal(err)
	}
	img.Close()
	// A crash after the data append but before the map entry: stale bytes
	// at the file end must never show in a new region.
	f, _ := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0)
	f.Write(bytes.Repeat([]byte{0xee}, RegionSize))
	f.Close()
	img, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if _, err := img.WriteAt([]byte("new"), 2*RegionSize); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8)
	img.ReadAt(got, 2*RegionSize)
	if string(got) != "new\x00\x00\x00\x00\x00" {
		t.Fatalf("stale bytes: %q", got)
	}
	img.ReadAt(got[:4], 0)
	if string(got[:4]) != "keep" {
		t.Fatal("lost data")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("opened a missing file")
	}
}
