// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"bytes"
	"testing"
)

func FuzzFrameDecoder(f *testing.F) {
	seed, _ := Encode(sample())
	f.Add(seed, uint16(17))
	f.Add([]byte("MDG1"), uint16(1))
	f.Fuzz(func(t *testing.T, b []byte, split uint16) {
		if len(b) > HeaderSize+MaxBody {
			return
		}
		d, _ := NewDecoder(MaxBody)
		n := int(split) % (len(b) + 1)
		first, used, err := d.Feed(b[:n])
		if used < 0 || used > n || d.Buffered() > HeaderSize+MaxBody {
			t.Fatal("decoder bounds")
		}
		consumed := used
		got := first
		if err == nil && got == nil {
			var k int
			got, k, err = d.Feed(b[n:])
			consumed += k
		}
		if err != nil {
			if x, _, e := d.Feed(seed); e == nil || x != nil {
				t.Fatal("poisoned stream resumed")
			}
			return
		}
		if got == nil {
			if len(b) > 0 && d.Close() == nil {
				t.Fatal("truncation accepted")
			}
			return
		}
		wire, e := Encode(*got)
		if e != nil || consumed > len(b) || !bytes.Equal(wire, b[:consumed]) {
			t.Fatal("canonical frame roundtrip", e)
		}
	})
}
