// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"errors"
	"testing"
)

func TestChunkWriterAndChunk(t *testing.T) {
	var wire bytes.Buffer
	header := [32]byte{7}
	payload := bytes.Repeat([]byte{1, 2, 3}, ChunkSize) // three chunks
	stop := errors.New("stop")
	calls := 0
	w := &ChunkWriter{Stream: &wire, Purpose: VolumeFile, Request: 9, Header: header, Check: func() error { calls++; return nil }}
	if n, err := w.Write(payload); err != nil || n != len(payload) || w.Offset != uint64(len(payload)) || calls != 3 {
		t.Fatalf("write n=%d err=%v offset=%d calls=%d", n, err, w.Offset, calls)
	}
	var got []byte
	for wire.Len() > 0 {
		f, err := ReadFrame(&wire, chunkBudget)
		if err != nil || f.Purpose != VolumeFile || f.Request != 9 {
			t.Fatal(f, err)
		}
		if _, err := Chunk(f, [32]byte{8}, uint64(len(got)), uint64(len(payload)-len(got))); err == nil {
			t.Fatal("foreign header accepted")
		}
		if _, err := Chunk(f, header, uint64(len(got))+1, uint64(len(payload)-len(got))); err == nil {
			t.Fatal("gap accepted")
		}
		if _, err := Chunk(f, header, uint64(len(got)), 1); err == nil {
			t.Fatal("overlong chunk accepted")
		}
		data, err := Chunk(f, header, uint64(len(got)), uint64(len(payload)-len(got)))
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, data...)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload changed")
	}
	w.Check = func() error { return stop }
	if n, err := w.Write([]byte{1}); n != 0 || !errors.Is(err, stop) {
		t.Fatal(n, err)
	}
	if WriteChunk(&wire, VolumeFile, 1, header, 0, nil) == nil || WriteChunk(&wire, VolumeFile, 1, header, 0, make([]byte, ChunkSize+1)) == nil {
		t.Fatal("empty or oversized chunk written")
	}
}
