// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"testing"
)

func TestVolumeForeignConsumerPreviewUsesAcquireMatrixWithoutChangingOriginalPins(t *testing.T) {
	for _, writer := range []bool{false, true} {
		for _, wantedWriter := range []bool{false, true} {
			f := makeFixture(t)
			original := f.acquire("original", 7, writer)
			before, _ := f.s.Encode()
			want := writer || wantedWriter
			conflicts := f.s.ForeignConsumerConflicts("new-task", wantedWriter)
			if f.s.ConflictsWithForeignConsumer("new-task", wantedWriter) != want || (len(conflicts) != 0) != want {
				t.Fatal("preview differs from reader/writer policy", writer, wantedWriter, conflicts)
			}
			if want && (len(conflicts) != 1 || conflicts[0] != original) {
				t.Fatal("preview lost the exact original unknown pin")
			}
			_, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "new-task", 13, wantedWriter)
			if (err != nil) != want {
				t.Fatal("preview and actual Acquire disagree", writer, wantedWriter, err)
			}
			if f.s.ConflictsWithForeignConsumer("original", wantedWriter) || len(f.s.ForeignConsumerConflicts("original", wantedWriter)) != 0 {
				t.Fatal("preview inferred a future Task generation from an original consumer")
			}
			_, replay, err := f.s.Acquire(f.c, "admin", 0, "original", 7, writer)
			if err != nil || replay != original {
				t.Fatal("exact original pin replay changed", err)
			}
			if _, _, err := f.s.Acquire(f.c, "admin", f.s.Revision(), "original", 8, writer); err == nil {
				t.Fatal("preview exemption authorized a new generation before closure")
			}
			if len(conflicts) != 0 {
				conflicts[0].Lease.Token++
			}
			after, _ := f.s.Encode()
			if !bytes.Equal(before, after) {
				t.Fatal("preview or failed candidate mutated the original volume")
			}
		}
	}
}
