// SPDX-License-Identifier: Apache-2.0

package app

import "testing"

// Reuses the owned native rollback/CLI fixture. Policy is enabled after the
// original app acceptance and before probe/restart/DB-reopen/retirement checks.
// The existing checker verifier exercises a real Yaegi probe and Docker SDK
// stop/start; the same original Volume/Secret/App bindings remain authoritative.
func TestRV6ManagedNodeCLIPolicyKeepsOwnerLifecycleAndRetirement(t *testing.T) {
	runManagedAppOwner(t, true, true, true, true, managedAppNodeCLIPolicy, true, false, false)
}
