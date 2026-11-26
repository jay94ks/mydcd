// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/engine"
)

// NativeCacheRetirementGrant comes from the existing committed tenant
// retirement work. It authorizes disposal of engine-owned cache, not tenant
// Volumes or a new build. Tenant IDs cannot be recreated after retirement.
type NativeCacheRetirementGrant struct {
	Source                        JobSpec
	Operation                     string
	InventoryHash, OwnersHash     [32]byte
	StartedRevision, Index, Epoch uint64
}

func (g NativeCacheRetirementGrant) Valid() bool {
	return g.Source.Validate() == nil && lifecycle.ValidID(g.Operation) && g.InventoryHash != ([32]byte{}) && g.OwnersHash != ([32]byte{}) && g.StartedRevision > 0 && g.Index >= g.StartedRevision && g.Epoch > 0
}

// The delete intent lives beside the original cache lease. It precedes any
// unlink, preserves both original inodes and survives unlink/DB/Return loss.
type NativeCacheRetirement struct {
	Schema                            uint8
	Tenant, Operation                 string
	Source, InventoryHash, OwnersHash [32]byte
	StartedRevision, Index, Epoch     uint64
	Root, Directory                   NativeDirectory
	Unlinked                          bool
}

func (r NativeCacheRetirement) valid(c nativeCacheBorrow) bool {
	if r.Schema != 1 || !lifecycle.ValidID(r.Tenant) || !lifecycle.ValidID(r.Operation) || r.Source == ([32]byte{}) || r.InventoryHash == ([32]byte{}) || r.OwnersHash == ([32]byte{}) || r.StartedRevision == 0 || r.Index < r.StartedRevision || r.Epoch == 0 || c.Owner != ([32]byte{}) || c.RootHold == nil {
		return false
	}
	if r.Root != (NativeDirectory{}) && !r.Root.valid() || r.Directory != (NativeDirectory{}) && !r.Directory.valid() || r.Directory.valid() && !r.Root.valid() {
		return false
	}
	if r.Unlinked {
		return c.Directory == (NativeDirectory{}) && c.RootHold.Returning
	}
	return !c.RootHold.Returning && !c.RootHold.Returned && (c.Directory == (NativeDirectory{}) || c.Directory == r.Directory)
}

func (r NativeCacheRetirement) matches(g NativeCacheRetirementGrant) bool {
	return g.Valid() && r.Tenant == g.Source.Tenant && r.Source == g.Source.Digest() && r.Operation == g.Operation && r.InventoryHash == g.InventoryHash && r.OwnersHash == g.OwnersHash && r.StartedRevision == g.StartedRevision && g.Index >= r.Index && g.Epoch >= r.Epoch
}

func (n *NativeJobs) validCacheRetirementGrant(g NativeCacheRetirementGrant) bool {
	return g.Valid() && n.docker.Owner == engine.Owner(g.Source.Cluster, g.Source.Scope.Root.Key)
}
