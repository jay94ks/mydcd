// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"errors"
	"runtime/pprof"
	"sync"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// ErrProfileBusy: another diagnostics read is recording a CPU profile; the
// Go runtime runs one CPU profile per process at a time.
var ErrProfileBusy = errors.New("a CPU profile is already being recorded on this server")

var diagnosticCPUProfile sync.Mutex

// diagnosticProfiles returns the goroutine profile and, when seconds > 0, a
// CPU profile of that length, CPU first: when the bundle cannot hold both,
// the goroutine profile is the one left out. A cancelled read stops the CPU
// profile early and fails.
func diagnosticProfiles(ctx context.Context, seconds uint8) ([]diagnosticProfile, error) {
	if seconds > control.NodeDiagnosticsMaxCPUProfileSeconds {
		return nil, errors.New("CPU profile too long")
	}
	out := []diagnosticProfile{}
	if seconds > 0 {
		if !diagnosticCPUProfile.TryLock() {
			return nil, ErrProfileBusy
		}
		var cpu bytes.Buffer
		err := pprof.StartCPUProfile(&cpu)
		if err != nil {
			diagnosticCPUProfile.Unlock()
			return nil, ErrProfileBusy
		}
		timer := time.NewTimer(time.Duration(seconds) * time.Second)
		select {
		case <-ctx.Done():
			err = ctx.Err()
		case <-timer.C:
		}
		timer.Stop()
		pprof.StopCPUProfile()
		diagnosticCPUProfile.Unlock()
		if err != nil {
			return nil, err
		}
		out = append(out, diagnosticProfile{"profile-cpu.pb.gz", cpu.Bytes()})
	}
	var goroutines bytes.Buffer
	if p := pprof.Lookup("goroutine"); p != nil && p.WriteTo(&goroutines, 0) == nil {
		out = append(out, diagnosticProfile{"profile-goroutine.pb.gz", goroutines.Bytes()})
	}
	return out, nil
}
