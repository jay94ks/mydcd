// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import "github.com/jay94ks/mydcd/internal/schema"

// Read the original durable records, without taking CompilerOwner's native
// Wait lock. No live owner calls back into SourceStore during collection.
func (m *SourceStore) localCompilerCacheReferences() ([]CacheReference, error) {
	rows, err := m.db.SizesBounded(compilerRecordPrefix, maxBuildJobs, maxBuildJobs*256)
	if err != nil {
		return nil, err
	}
	validator := &CompilerOwner{identity: compilerOwnerIdentity{Cluster: m.identity.Cluster, Node: m.identity.Node}}
	var refs []CacheReference
	for key := range rows {
		raw, err := m.db.GetBounded(key, maxCompilerRecordBytes)
		if err != nil {
			return nil, err
		}
		record, err := schema.Decode[compilerDisk](raw)
		if err != nil || validator.validate(record) != nil || key != compilerRecordPrefix+compilerJobKey(record.Intent) {
			return nil, ErrCompilerOwner
		}
		if record.Closure == nil {
			for _, input := range record.Intent.Inputs {
				refs = append(refs, CacheReference{record.Intent.Tenant, input.Content})
			}
		}
	}
	return refs, nil
}
