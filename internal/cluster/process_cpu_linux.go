// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"syscall"
	"time"
)

// Diagnostic process CPU, including concurrent goroutines and runtime threads.
// It is not the CPU cost of one RPC, nor a source of state or admission input.
func processCPUTime() time.Duration {
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) != nil {
		return -1
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func processCPUUsed(start time.Duration) time.Duration {
	end := processCPUTime()
	if start < 0 || end < start {
		return -1
	}
	return end - start
}
