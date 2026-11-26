// SPDX-License-Identifier: Apache-2.0

package control

import "github.com/jay94ks/mydcd/internal/cluster/state"

// ownsResource authenticates the current node while retaining an immutable
// resource owner. Callers must first resolve the exact original resource or
// accepted job; this helper is never a current command/issuer/TLS lookup.
func (p Policy) ownsResource(s state.State, current, original [32]byte) bool {
	members, err := p.Members(s)
	return err == nil && members.OwnsResource(current, original)
}
func (p Policy) resourceNodeOwner(s state.State, node string, original [32]byte, work bool) bool {
	current, err := p.nodeOwner(s, node)
	if work {
		current, err = p.workNodeOwner(s, node)
	}
	return err == nil && p.ownsResource(s, current, original)
}

// resourceCallerForNode is for reducers consuming an already retained recipe.
// Public adapters must authenticate the actual caller with ownsResource first.
func (p Policy) resourceCallerForNode(s state.State, node string, original [32]byte) [32]byte {
	current, err := p.nodeOwner(s, node)
	if err != nil || !p.ownsResource(s, current, original) {
		return [32]byte{}
	}
	return current
}

// currentResourceKey resolves a retained owner only after the caller has found
// the exact source/use/job. The returned key must still have current membership
// (and work eligibility when requested); historical keys never authenticate.
func (p Policy) currentResourceKey(s state.State, original [32]byte, work bool) [32]byte {
	members, err := p.Members(s)
	if err != nil {
		return [32]byte{}
	}
	for _, entry := range members.Entries {
		if !members.ResourceKeyForNode(entry.Peer.ID, original) {
			continue
		}
		current := p.resourceCallerForNode(s, entry.Peer.ID, original)
		if current != ([32]byte{}) && (!work || members.WorkKey(current)) {
			return current
		}
	}
	return [32]byte{}
}

// ResourceWorkKey resolves an already selected original resource owner to its
// current installed, work-eligible node key in this exact committed state.
// It is not permission to select a different source, tenant or generation.
func (p Policy) ResourceWorkKey(s state.State, original [32]byte) [32]byte {
	return p.currentResourceKey(s, original, true)
}
