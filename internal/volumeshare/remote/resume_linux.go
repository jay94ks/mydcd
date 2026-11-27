// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/fdstore"
)

// Resume serves again, right away, every held consumer whose mount an
// earlier sfcd left in the FD store: the kernel queues the containers'
// requests until then. It retries while the home is unreachable and stops
// with ctx. Stored descriptors of consumers no longer held are dropped.
func (m *Mounts) Resume(ctx context.Context) {
	stored := map[string]bool{}
	for _, n := range fdstore.Names() {
		if strings.HasPrefix(n, "sfc-remote-") {
			stored[strings.SplitN(n, ".", 2)[0]] = true
		}
	}
	m.mu.Lock()
	var live []string
	for name := range stored {
		if r, ok := m.records[name]; ok && !r.Released {
			live = append(live, name)
			delete(stored, name)
		}
	}
	m.mu.Unlock()
	for name := range stored {
		for _, n := range fdstore.Names() {
			if strings.HasPrefix(n, name+".") {
				for _, f := range fdstore.Take(n) {
					_ = f.Close()
				}
				_ = fdstore.Remove(n)
			}
		}
	}
	for _, name := range live {
		go func(name string) {
			wait := 200 * time.Millisecond
			for {
				if _, err := m.ensure(ctx, name); err == nil || err == ErrUnknown {
					return
				} else {
					log.Printf("shared volume %s: resume after restart: %v", name, err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
				if wait < 10*time.Second {
					wait *= 2
				}
			}
		}(name)
	}
}
