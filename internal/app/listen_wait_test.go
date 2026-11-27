// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// Just after boot the listen address may not be on the server yet: sfcd
// waits for it instead of exiting, and stops waiting when it is closed.
func TestListenWaitsForTheAddress(t *testing.T) {
	old := listenRetry
	listenRetry = 5 * time.Millisecond
	defer func() { listenRetry = old }()

	// A real bind to an address this host does not have fails with
	// EADDRNOTAVAIL, the error the wait keys on.
	_, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("192.0.2.77")})
	if !errors.Is(err, syscall.EADDRNOTAVAIL) {
		t.Skip("this host does not refuse a foreign address with EADDRNOTAVAIL", err)
	}
	tries := 0
	err = listenWhenAddressReady(context.Background(), "192.0.2.77:7443", func(string) error {
		if tries++; tries < 3 {
			_, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("192.0.2.77")})
			return e
		}
		return nil
	})
	if err != nil || tries != 3 {
		t.Fatal("listen did not wait for the address", tries, err)
	}

	other := errors.New("permission denied")
	if err = listenWhenAddressReady(context.Background(), "x", func(string) error { return other }); !errors.Is(err, other) {
		t.Fatal("another bind error was retried", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	err = listenWhenAddressReady(ctx, "192.0.2.77:7443", func(string) error { return syscall.EADDRNOTAVAIL })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("closing did not stop the wait", err)
	}
}
