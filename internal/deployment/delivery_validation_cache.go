// SPDX-License-Identifier: Apache-2.0

package deployment

import "sync"

// This caches a deterministic syntax/invariant check of exact canonical bytes,
// never current authority, clocks, observations or a decoded mutable record.
// DecodeDelivery still owns a freshly unmarshaled record on every hit.
// Blueprint.Encode uses a separate instance for metadata checks and always
// marshals fresh returned bytes; neither instance stores decoded records.
const deliveryValidationBytes = 8 << 20
const deliveryValidationEntries = 32
const deliveryValidationEntryBytes = 1 << 20

type deliveryValidationCache struct {
	mu      sync.Mutex
	entries map[string]struct{}
	bytes   int
}

var validatedDeliveryBytes deliveryValidationCache

func (c *deliveryValidationCache) contains(raw []byte) bool {
	if len(raw) > deliveryValidationEntryBytes {
		return false
	}
	c.mu.Lock()
	_, ok := c.entries[string(raw)]
	c.mu.Unlock()
	return ok
}
func (c *deliveryValidationCache) remember(raw []byte) {
	if len(raw) > deliveryValidationEntryBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[string(raw)]; ok {
		return
	}
	if len(c.entries) >= deliveryValidationEntries || c.bytes+len(raw) > deliveryValidationBytes {
		c.entries = nil
		c.bytes = 0
	}
	if c.entries == nil {
		c.entries = make(map[string]struct{})
	}
	c.entries[string(raw)] = struct{}{}
	c.bytes += len(raw)
}
