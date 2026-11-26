// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"regexp"
	"slices"
)

// Shared helpers of the fake (REQ-17's real model is in
// fake_external_registries_real.go).

const builtinRegistryHost = "registry.mydc.local"

var identifierRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func (w *world) vaultObject(realm, id string) *VaultView {
	i := slices.IndexFunc(w.vault, func(v VaultView) bool { return v.Realm == realm && v.ID == id && v.Kind == "object" })
	if i < 0 {
		return nil
	}
	return &w.vault[i]
}

// SetRegistryLoginResult forces registry-login-test for an authority to code
// (the real vocabulary, or the old lower-case names: ok, unauthorized,
// forbidden, unreachable, secret-unavailable); "" restores the derived one.
func (f *Fake) SetRegistryLoginResult(authority, code string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code == "" {
		delete(f.w.loginResult, authority)
	} else {
		f.w.loginResult[authority] = code
	}
}
