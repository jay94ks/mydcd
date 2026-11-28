// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// imageTagCopies is this server's record of the digest each workspace's
// tag last resolved to when a container was made from it here. A deploy that
// cannot reach the registry, or is told the tag is gone, makes the
// container from that copy instead (deployment.LocalCopyAllowed). It is this
// server's cache fact, so it stays out of Raft.
type imageTagCopies struct {
	mu     sync.Mutex
	path   string
	loaded bool
	Tags   map[string]imageTagCopy // tenant "\x00" normalized tag
}

type imageTagCopy struct {
	Digest string
	At     int64
}

const maxImageTagCopies = 4096

func newImageTagCopies(stateDir string) *imageTagCopies {
	return &imageTagCopies{path: filepath.Join(stateDir, "image-tags.json"), Tags: map[string]imageTagCopy{}}
}

func (c *imageTagCopies) loadLocked() {
	if c.loaded {
		return
	}
	c.loaded = true
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	var saved imageTagCopies
	if json.Unmarshal(raw, &saved) == nil && saved.Tags != nil {
		c.Tags = saved.Tags
	}
}

// Get returns the digest reference tenant's tag last made a container here.
func (c *imageTagCopies) Get(tenant, tag string) (string, bool) {
	if c == nil {
		return "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	v, ok := c.Tags[tenant+"\x00"+tag]
	return v.Digest, ok
}

// Set records that tenant's tag made a container here from digest.
func (c *imageTagCopies) Set(tenant, tag, digest string, now time.Time) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadLocked()
	key := tenant + "\x00" + tag
	if old, ok := c.Tags[key]; ok && old.Digest == digest {
		return nil
	}
	c.Tags[key] = imageTagCopy{Digest: digest, At: now.Unix()}
	for len(c.Tags) > maxImageTagCopies {
		oldest := ""
		for k, v := range c.Tags {
			if oldest == "" || v.At < c.Tags[oldest].At {
				oldest = k
			}
		}
		delete(c.Tags, oldest)
	}
	raw, err := json.Marshal(struct{ Tags map[string]imageTagCopy }{c.Tags})
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err = os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
