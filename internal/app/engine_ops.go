// SPDX-License-Identifier: Apache-2.0

package app

import "github.com/jay94ks/seafield/internal/engineops"

// engineOps lists every request the engine may ask this node over its
// engine-only session (purpose 35 volume, 36 network, 37 image). A feature
// adds its ops here as engineops.Op(...) values written in its own files;
// nothing else changes. The engine session hands each request body to
// r.engineOps.Serve. See devel/refactor/18-sfcd-structure.md 5.3 and
// seafield/docs/sfcd-socket.md.
func (r *Runtime) engineOpEntries() []engineops.Entry {
	var entries []engineops.Entry
	entries = append(entries, r.volumeEngineOps()...)
	entries = append(entries, r.engineImageEntries()...)
	entries = append(entries, r.engineNetworkOps()...)
	return entries
}

// newEngineOps builds the table once at start; a duplicate op is a build
// mistake and stops the daemon before it serves the engine.
func (r *Runtime) newEngineOps() (*engineops.Table, error) {
	return engineops.NewTable(r.engineOpEntries()...)
}
