// SPDX-License-Identifier: Apache-2.0

package mydc

import "github.com/jay94ks/mydcd/internal/cluster/control"

// Root revisions per command key, as mydcd keeps one object (and CAS root)
// per control module: userauth.Client.Prepare signs each action with the
// root of control.CommandKey(action) (AppsRootRevision for apps actions,
// VaultRootRevision for vault actions, …; everything else the catalog root).
//
// The fake still has one global index (w.root, the Result Index and page
// revisions). Each key's root is the index of the last change of that key
// (seed: the index after the fixture). Whoami.Roots reports them and
// Whoami.RootFor(action) picks one.
//
// By default submit checks only the key's root, as mydcd does.
// Fake.StrictRoots(false) also accepts the old global root.

// rootKeys: the command keys Whoami.Roots reports.
var rootKeys = []string{control.CatalogKey, control.MembersKey, control.ResourcesKey, control.VolumesKey, control.VaultKey, control.AppsKey,
	control.RegistryMaintenanceKey, control.ImageBuildKey, control.ImageCacheKey, control.TunnelReconnectKey, control.CompactKey, control.StorageKey,
	control.NodeStorageKey, control.LifecycleKey, control.RegistriesKey, control.ExternalRegistriesKey, control.CertificatesKey,
	control.IngressManagementKey, control.NodeShellKey}

// StrictRoots(true), the default, makes submit check only the action's own
// key root; false also accepts the global root.
func (f *Fake) StrictRoots(strict bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.w.strictRoots = strict
}

func (w *world) keyRoot(key string) uint64 {
	if r, ok := w.keyRoots[key]; ok {
		return r
	}
	return w.seedRoot
}

// bumpKey: an owner-side change of key's object (a report, a settled job).
func (w *world) bumpKey(key string) {
	w.root++
	w.keyRoots[key] = w.root
}

// catalogRoot: Whoami.RootRevision. Until strict, the global root, which
// the lenient check accepts for every key.
func (w *world) catalogRoot() uint64 {
	if w.strictRoots {
		return w.keyRoot(control.CatalogKey)
	}
	return w.root
}

func (w *world) rootAccepted(key string, root uint64) bool {
	return root == w.keyRoot(key) || !w.strictRoots && root == w.root
}

func (w *world) rootsView() map[string]uint64 {
	out := make(map[string]uint64, len(rootKeys))
	for _, k := range rootKeys {
		out[k] = w.keyRoot(k)
	}
	return out
}
