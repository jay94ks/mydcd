// SPDX-License-Identifier: Apache-2.0

package diskfs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/sfcimg"
)

func spec(t *testing.T, mode string, copies int, bytesPer uint64) Spec {
	s := Spec{Schema: 1, Bundle: "pool", ID: [16]byte{9}, Mode: mode}
	for c := 0; c < copies; c++ {
		dirA, dirB := filepath.Join(t.TempDir(), ".sfc-disks", "pool"), filepath.Join(t.TempDir(), ".sfc-disks", "pool")
		s.Copies = append(s.Copies, Layout([]Member{{Dir: dirA, Bytes: bytesPer, Disk: "sdb", Part: "sdb1"}, {Dir: dirB, Bytes: bytesPer, Disk: "sdc", Part: "sdc1"}}))
	}
	return s
}

func TestLinearSpansMembers(t *testing.T) {
	s := spec(t, "linear", 1, 3*sfcimg.RegionSize)
	if err := Create(s, true); err != nil {
		t.Fatal(err)
	}
	d, err := Open(s)
	if err != nil {
		t.Fatal(err)
	}
	if d.Size() != 6*sfcimg.RegionSize {
		t.Fatal("size", d.Size())
	}
	data := bytes.Repeat([]byte{7}, 2*sfcimg.RegionSize)
	if _, err := d.WriteAt(data, 2*sfcimg.RegionSize); err != nil { // crosses the member boundary
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := d.ReadAt(got, 2*sfcimg.RegionSize); err != nil || !bytes.Equal(got, data) {
		t.Fatal("read", err)
	}
	if _, err := d.WriteAt([]byte{1}, int64(d.Size())); err == nil {
		t.Fatal("wrote past the end")
	}
	d.Close()
	// A linear bundle with a chunk gone does not open.
	os.Remove(filepath.Join(s.Copies[0][1].Dir, s.Copies[0][1].File))
	if _, err := Open(s); err == nil {
		t.Fatal("opened a linear bundle with a chunk missing")
	}
	if err := Remove(s); err != nil {
		t.Fatal(err)
	}
}

func TestMirrorDegradesAndResyncs(t *testing.T) {
	s := spec(t, "mirror", 2, 2*sfcimg.RegionSize)
	if err := Create(s, false); err != nil {
		t.Fatal(err)
	}
	// Copy 2 is gone while the bundle runs: writes go to copy 1 and are
	// marked for copy 2.
	gone := s.Copies[1][0]
	moved := filepath.Join(t.TempDir(), "kept")
	if err := os.Rename(filepath.Join(gone.Dir, gone.File), moved); err != nil {
		t.Fatal(err)
	}
	d, err := Open(s)
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.State != "degraded" || st.Copies[1].State != "missing" {
		t.Fatalf("degraded %+v", st)
	}
	data := bytes.Repeat([]byte("mirror!!"), sfcimg.RegionSize/8)
	if _, err := d.WriteAt(data, sfcimg.RegionSize/2); err != nil {
		t.Fatal(err)
	}
	if err := d.Sync(); err != nil {
		t.Fatal(err)
	}
	d.Close()
	// It comes back: the missed regions are copied, then copy 2 alone
	// holds the data.
	if err := os.Rename(moved, filepath.Join(gone.Dir, gone.File)); err != nil {
		t.Fatal(err)
	}
	d, err = Open(s)
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Status(); st.State != "syncing" || st.Copies[1].State != "syncing" {
		t.Fatalf("syncing %+v", st)
	}
	d.Resync(make(chan struct{}))
	if st := d.Status(); st.State != "ok" {
		t.Fatalf("after resync %+v", st)
	}
	d.Close()
	for _, c := range s.Copies[0] {
		os.Rename(filepath.Join(c.Dir, c.File), filepath.Join(c.Dir, c.File+".off"))
	}
	only := s
	d, err = Open(only)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	got := make([]byte, len(data))
	if _, err := d.ReadAt(got, sfcimg.RegionSize/2); err != nil || !bytes.Equal(got, data) {
		t.Fatal("copy 2 after resync", err)
	}
}
