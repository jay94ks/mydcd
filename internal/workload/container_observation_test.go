// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/jay94ks/seafield/internal/containerops"
)

type observationTestBody struct {
	io.Reader
	closed *bool
}

func (b observationTestBody) Close() error { *b.closed = true; return nil }
func observationFrame(kind byte, value string) []byte {
	header := make([]byte, 8)
	header[0] = kind
	binary.BigEndian.PutUint32(header[4:], uint32(len(value)))
	return append(header, []byte(value)...)
}
func TestContainerObservationLogsBoundBothStreamsAndClose(t *testing.T) {
	for _, tty := range []bool{false, true} {
		input := append(observationFrame(1, "stdout"), observationFrame(2, "stderr")...)
		if tty {
			input = []byte("stdoutstderr")
		}
		closed := false
		stdout, stderr, truncated, err := readObservationLogs(observationTestBody{bytes.NewReader(input), &closed}, tty, 9)
		if err != nil || !closed || !truncated || len(stdout)+len(stderr) != 9 {
			t.Fatal(tty, string(stdout), string(stderr), truncated, closed, err)
		}
		if tty && len(stderr) != 0 || !tty && (string(stdout) != "stdout" || string(stderr) != "std") {
			t.Fatal("stream identity lost")
		}
	}
	for _, data := range [][]byte{{1, 0}, append(observationFrame(1, "abcdef")[:8], []byte("a")...), {1, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff}} {
		closed := false
		_, _, _, err := readObservationLogs(observationTestBody{bytes.NewReader(data), &closed}, false, containerops.MaxOutput)
		if !closed || !errors.Is(err, ErrProbeExecStream) {
			t.Fatal("partial/oversized Docker frame became success", closed, err)
		}
	}
}
