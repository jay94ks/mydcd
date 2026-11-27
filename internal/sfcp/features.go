// SPDX-License-Identifier: Apache-2.0

package sfcp

import (
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/buildinfo"
)

// ErrUnsupported means the peer (or this build) lacks a feature the
// purpose/kind needs, so nothing was sent. Callers treat it like an absent
// capability, not a transport failure.
var ErrUnsupported = errors.New("SFCP peer does not support this feature")

// featureCache keeps each member's last announced feature set and the last
// cluster intersection. Feature sets are live per node (Jay 2026-11-28): the
// intersection is recomputed only when a member announces a different set or
// the member list changes, and is never stored in Raft. Caller holds t.mu.
type featureCache struct {
	// seen is each member's set from its latest session in this process; a
	// disconnected member keeps it (devel/design/upgrades.md 3-4).
	seen             map[Identity]buildinfo.Features
	gen, computedGen uint64
	members          []Identity
	set              buildinfo.Features
	valid            bool
}

func (c *featureCache) saw(key Identity, f buildinfo.Features) {
	if old, ok := c.seen[key]; ok && old == f {
		return
	}
	if c.seen == nil {
		c.seen = map[Identity]buildinfo.Features{}
	}
	c.seen[key] = f
	c.gen++
}

// ClusterFeatures is the intersection of this build's features and every
// given member's last announced set. A disconnected member counts with the
// set it last announced; one never seen since this process started counts
// as the empty set, so an old server that is away keeps a new feature off
// (upgrades.md 3-4). members is the current membership; this node's own key
// is skipped.
func (t *Transport) ClusterFeatures(members []Identity) buildinfo.Features {
	sorted := slices.Clone(members)
	slices.SortFunc(sorted, compareKeys)
	sorted = slices.Compact(sorted)
	t.mu.Lock()
	defer t.mu.Unlock()
	c := &t.features
	if c.valid && c.computedGen == c.gen && slices.Equal(c.members, sorted) {
		return c.set
	}
	self := Identity(t.self.Public)
	set := t.own
	for _, key := range sorted {
		if key != self {
			set = set.And(c.seen[key]) // never seen: zero
		}
	}
	c.members, c.set, c.computedGen, c.valid = sorted, set, c.gen, true
	return set
}

// PeerFeatures is the set key last announced, and whether it has a live
// session now.
func (t *Transport) PeerFeatures(key Identity) (buildinfo.Features, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.peerOf(key)
	return t.features.seen[key], p != nil && p.live > 0
}

func compareKeys(a, b Identity) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
