// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"sync"
)

const artifactParseEntries = 32
const artifactParseBytes = 8 << 20

type artifactParseKey struct {
	digest [32]byte
	kind   string
}

type artifactParseEntry struct{ body, model []byte }

// Only the pure interpretation of already checked, immutable source bytes is
// memoized. Current catalog/authority, candidate/plan, signature and native
// admission checks remain in their existing callers. Nothing is persisted.
type artifactParseCache struct {
	mu      sync.Mutex
	entries map[artifactParseKey]artifactParseEntry
	bytes   int
}

var parsedDeliveryArtifacts artifactParseCache

// artifactComposeKind must verify source metadata and digest before calling.
// Each result owns all of its maps, slices and pointers: candidate validation
// and scope/default/override resolution must never mutate another reader.
func (c *artifactParseCache) compose(a deliveryArtifact, kind string) (Compose, error) {
	key := artifactParseKey{a.Digest, kind}
	c.mu.Lock()
	if old, ok := c.entries[key]; ok && bytes.Equal(old.body, a.Body) {
		raw := old.model
		c.mu.Unlock()
		var model Compose
		err := json.Unmarshal(raw, &model)
		return model, err
	}
	// A bounded cold parse is synchronous and coalesced. Do not hold this lock
	// during any authority check, external I/O or mutable candidate operation.
	model, err := parseCompose(a.Body, kind == "app")
	if err == nil {
		if raw, encodeErr := json.Marshal(model); encodeErr == nil {
			size := len(a.Body) + len(raw)
			if size <= artifactParseBytes {
				if len(c.entries) >= artifactParseEntries || c.bytes+size > artifactParseBytes {
					c.entries, c.bytes = nil, 0
				}
				if c.entries == nil {
					c.entries = make(map[artifactParseKey]artifactParseEntry)
				}
				if old, exists := c.entries[key]; exists {
					c.bytes -= len(old.body) + len(old.model)
				}
				c.entries[key] = artifactParseEntry{bytes.Clone(a.Body), raw}
				c.bytes += size
			}
		}
	}
	c.mu.Unlock()
	return model, err
}
