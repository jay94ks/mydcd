// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegistryIOGateJoinsReaderAndCancelsWriterWithoutLeakingFence(t *testing.T) {
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	var gate registryIOGate
	reader, err := gate.acquire(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	defer reader()
	writerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		release, err := gate.acquire(writerCtx, true)
		if err == nil {
			release()
		}
		done <- err
	}()
	for {
		gate.mu.Lock()
		waiting := gate.waiting
		changed := gate.changed
		exclusive := gate.exclusive
		gate.mu.Unlock()
		if exclusive {
			t.Fatal("writer entered while original request was active")
		}
		if waiting > 0 {
			break
		}
		select {
		case <-changed:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	canceled, stopRead := context.WithCancel(ctx)
	stopRead()
	if release, err := gate.acquire(canceled, false); !errors.Is(err, context.Canceled) {
		if release != nil {
			release()
		}
		t.Fatal("new request bypassed queued maintenance", err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	second, err := gate.acquire(ctx, false)
	if err != nil {
		t.Fatal("canceled maintenance retained admission fence", err)
	}
	second()
	reader()
	writer, err := gate.acquire(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	writer()
	writer()
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.active != 0 || gate.waiting != 0 || gate.exclusive {
		t.Fatal("gate ownership leaked")
	}
}
