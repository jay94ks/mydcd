// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

func TestNodeLogLinesSplitStreamsAndLimit(t *testing.T) {
	lines := []control.NodeLogLine{
		{Seq: 1, Time: "T1", Data: []byte("out")},
		{Seq: 2, Time: "T2", Stderr: true, Data: []byte("err")},
		{Seq: 3, Time: "T3", Partial: true, Data: []byte("part")},
	}
	var out, errOut bytes.Buffer
	writeNodeLogLines(&out, &errOut, lines, true)
	if out.String() != "T1 out\nT3 part" || errOut.String() != "T2 err\n" {
		t.Fatalf("%q %q", out.String(), errOut.String())
	}
	kept, printed := limitLines(lines, 7, 1)
	if len(kept) != 2 || printed != 7 {
		t.Fatal(len(kept), printed)
	}
	if kept, printed := limitLines(lines, 100, 0); len(kept) != 3 || printed != 10 {
		t.Fatal(len(kept), printed)
	}
}
