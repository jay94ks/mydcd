// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"maps"

	"github.com/jay94ks/mydcd/internal/access"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

type CheckerModuleProgress struct {
	Sequence uint64
	Fact     *checker.ModuleFact `json:",omitempty"`
}

func CheckerModulePin(i CheckerScriptIntent, path string) (checker.ModulePin, bool) {
	for _, pin := range i.Descriptor.Modules {
		if pin.Path == path {
			return pin, true
		}
	}
	return checker.ModulePin{}, false
}

func validCheckerModules(i CheckerScriptIntent) bool {
	if len(i.ModuleProgress) > len(i.Descriptor.Modules) {
		return false
	}
	for path, progress := range i.ModuleProgress {
		pin, ok := CheckerModulePin(i, path)
		if !ok || progress.Sequence > 128 {
			return false
		}
		f := progress.Fact
		if f != nil && (f.Verify() != nil || f.Cluster != i.Cluster || f.Owner != i.Provider.Key || f.Tenant != i.Tenant || f.Module != pin) {
			return false
		}
	}
	return true
}

// ReplaceCheckerModule changes one original lock's local send/fact progress,
// never the initial signature, bytes, provider, root progress or Raft operation.
// A sequence-zero fact can reuse the same tenant/pin already staged by another
// source intent; it does not imply this workflow previously sent an upload.
func ReplaceCheckerModule(home string, c Client, current access.Session, old CheckerScriptIntent, path string, progress CheckerModuleProgress) (CheckerScriptIntent, error) {
	before := old.ModuleProgress[path]
	if c.Verify(current) != nil || !validCheckerIntent(c, current.User, old) || progress.Sequence < before.Sequence || progress.Sequence > before.Sequence+1 || before.Fact != nil && (progress.Sequence != before.Sequence || !samePublic(before.Fact, progress.Fact)) || progress.Sequence != before.Sequence && progress.Fact != nil {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	next := old
	next.ModuleProgress = maps.Clone(old.ModuleProgress)
	if next.ModuleProgress == nil {
		next.ModuleProgress = map[string]CheckerModuleProgress{}
	}
	if progress.Fact != nil {
		fact := progress.Fact.Clone()
		progress.Fact = &fact
	}
	next.ModuleProgress[path] = progress
	if !validCheckerIntent(c, current.User, next) {
		return CheckerScriptIntent{}, ErrPrivateState
	}
	if err := replaceCheckerIntent(home, c, current, old, next); err != nil {
		return CheckerScriptIntent{}, err
	}
	return next, nil
}
