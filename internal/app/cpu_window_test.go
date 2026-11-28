// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"
	"time"
)

func TestShortCPUWindowKeepsLongerSample(t *testing.T) {
	at := time.Unix(1000, 0)
	switch {
	case shortCPUWindow(nil, time.Time{}, at):
		t.Fatal("first sample kept nothing")
	case !shortCPUWindow(nil, at, at.Add(2*time.Second)):
		t.Fatal("a 2s window replaced the kept sample")
	case shortCPUWindow(nil, at, at.Add(minCPUWindow)):
		t.Fatal("a full window was not taken")
	case shortCPUWindow(errors.New("read"), at, at.Add(time.Second)):
		t.Fatal("a failed read kept a stale counter")
	}
}
