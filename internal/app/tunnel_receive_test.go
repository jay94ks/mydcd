// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/sfcp"
)

func TestTunnelPacketReceiverDoesNotWaitForControlIO(t *testing.T) {
	// Without a serving plane, rejection must not take the IO mutex or
	// dereference the session.
	i := &tunnelInstance{r: &Runtime{}}
	i.mu.Lock()
	defer i.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- i.receive(nil, sfcp.Frame{}) }()
	select {
	case err := <-done:
		if !errors.Is(err, errTunnelPending) {
			t.Fatal("absent serving plane did not deny", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("single DATAGRAM receive loop blocked behind native/control I/O")
	}
}
