// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"errors"
	"log"
	"syscall"
	"time"
)

// listenRetry is how long listenWhenAddressReady waits between tries.
var listenRetry = time.Second

// listenWhenAddressReady binds with listen, and while the bind fails only
// because node.yaml's listen address is not on this server yet (just after
// boot, before DHCP or the interface brings it up), tries again every
// listenRetry until it is or ctx ends. Any other error is returned at once.
func listenWhenAddressReady(ctx context.Context, address string, listen func(string) error) error {
	var since, logged time.Time
	for {
		err := listen(address)
		if !errors.Is(err, syscall.EADDRNOTAVAIL) {
			if err == nil && !since.IsZero() {
				log.Printf("listen %s: address is up after %s", address, time.Since(since).Round(time.Second))
			}
			return err
		}
		now := time.Now()
		if since.IsZero() {
			since = now
		}
		if logged.IsZero() || now.Sub(logged) >= time.Minute {
			logged = now
			log.Printf("listen %s: the address is not on this server yet; waiting for it (%v)", address, err)
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), err)
		case <-time.After(listenRetry):
		}
	}
}
