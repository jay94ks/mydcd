// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"encoding/hex"
	"slices"
)

// Space is a read-back, not a reservation or hard quota. Its caller obtains
// current authorized node observations. Mixing boots or duplicate root samples
// fails rather than treating stale/partial responses as a zero-use filesystem.
type Space struct {
	Root                   Reference
	Directory              Directory
	Total, Free, Available uint64
}
type Capacity struct {
	Node                   string
	Key                    [32]byte
	Filesystem             string
	UUID                   [16]byte
	Roots                  int
	Total, Free, Available uint64
}

func (c Catalog) Capacities(samples []Space) ([]Capacity, error) {
	for _, s := range samples {
		r, ok := c.roots[rootKey(s.Root.Node, s.Root.ID)]
		if !ok || r.Attestation == nil || s.Root != r.Reference(c.cluster) || !s.Directory.MatchesOriginal(r.Attestation.Directory) {
			return nil, ErrStorage
		}
	}
	return AggregateSpaces(samples)
}

// AggregateSpaces is also used by the CLI AFTER its authenticated native
// readbacks have been matched to the same current catalog revision. It is
// physical accounting, not membership/ACL validation or a hard quota grant.
func AggregateSpaces(samples []Space) ([]Capacity, error) {
	type bucket struct {
		capacity Capacity
		identity Directory
	}
	groups := map[string]bucket{}
	seen := map[string]bool{}
	type owner struct{ Key, Boot, Namespace [32]byte }
	nodes := map[string]owner{}
	keysToNodes := map[[32]byte]string{}
	var cluster [32]byte
	for _, s := range samples {
		if s.Root.Validate() != nil || s.Directory.Validate() != nil || s.Total == 0 || s.Free > s.Total || s.Available > s.Free {
			return nil, ErrStorage
		}
		if cluster == ([32]byte{}) {
			cluster = s.Root.Cluster
		}
		if cluster != s.Root.Cluster {
			return nil, ErrStorage
		}
		nativeOwner := owner{s.Root.Key, s.Directory.Boot, s.Directory.Namespace}
		if previous, ok := nodes[s.Root.Node]; ok && previous != nativeOwner {
			return nil, ErrStorage
		}
		if previous, ok := keysToNodes[s.Root.Key]; ok && previous != s.Root.Node {
			return nil, ErrStorage
		}
		nodes[s.Root.Node], keysToNodes[s.Root.Key] = nativeOwner, s.Root.Node
		root := rootKey(s.Root.Node, s.Root.ID)
		if seen[root] {
			return nil, ErrStorage
		}
		seen[root] = true
		key := hex.EncodeToString(s.Root.Key[:]) + "/" + s.Directory.Filesystem + "/" + hex.EncodeToString(s.Directory.UUID[:])
		b, exists := groups[key]
		if !exists {
			b = bucket{Capacity{Node: s.Root.Node, Key: s.Root.Key, Filesystem: s.Directory.Filesystem, UUID: s.Directory.UUID, Total: s.Total, Free: s.Free, Available: s.Available}, s.Directory}
		} else {
			if b.capacity.Node != s.Root.Node || b.identity.Boot != s.Directory.Boot || b.identity.Namespace != s.Directory.Namespace || b.identity.DeviceMajor != s.Directory.DeviceMajor || b.identity.DeviceMinor != s.Directory.DeviceMinor {
				return nil, ErrStorage
			}
			// Several directories/bind views of one filesystem are ONE pool.
			// A later sample may reflect usage/online growth; retain conservative
			// minima instead of summing or declaring a physical quota guarantee.
			b.capacity.Total = min(b.capacity.Total, s.Total)
			b.capacity.Free = min(b.capacity.Free, s.Free)
			b.capacity.Available = min(b.capacity.Available, s.Available)
		}
		b.capacity.Roots++
		groups[key] = b
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	result := make([]Capacity, 0, len(keys))
	for _, k := range keys {
		result = append(result, groups[k].capacity)
	}
	return result, nil
}
