// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"testing"
	"time"
)

func TestModulePassCoalescesOwnCommitsAfterCompletion(t *testing.T) {
	// The pass itself closed the subscription while publishing an observation.
	// A persistent ticker could also already have a pending tick here. Neither
	// is a reason to skip the interval after this completed pass.
	changed := make(chan struct{})
	close(changed)
	const interval = 20 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for range 2 {
		completed := time.Now()
		if !waitModulePass(ctx, changed, true, interval) {
			t.Fatal("poll canceled", ctx.Err())
		}
		if time.Since(completed) < interval {
			t.Fatal("own commit caused an immediate second reconciliation")
		}
	}
}

func TestModulePassIdleChangeAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	changed := make(chan struct{})
	result := make(chan bool, 1)
	go func() { result <- waitModulePass(ctx, changed, false, time.Hour) }()
	close(changed)
	if !<-result {
		t.Fatal("idle change did not wake before the one-hour poll", ctx.Err())
	}
	for _, reconciled := range []bool{false, true} {
		child, stop := context.WithCancel(ctx)
		waiting := make(chan struct{})
		go func() { result <- waitModulePass(child, waiting, reconciled, time.Hour) }()
		stop()
		if <-result {
			t.Fatal("canceled loop requested another reconciliation")
		}
	}
}
