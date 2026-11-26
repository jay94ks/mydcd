// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"encoding/hex"
	"errors"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func engineBinding(o Options) []byte {
	key := o.Mesh.LocalKey()
	if len(o.IdentityTransitions) != 0 {
		key = mydcp.Identity(o.IdentityTransitions[0].Proof.Old)
	}
	return engineBindingKey(o, key)
}

// ownEngineIdentity validates before any root is opened. Only the complete
// lineage ending at the actual current transport key can select an original
// binding. All other bound policy/configuration fields remain unchanged.
func ownEngineIdentity(o Options) (Options, error) {
	o.IdentityTransitions = lifecycle.OwnIdentityTransitions(o.IdentityTransitions)
	if len(o.IdentityTransitions) != 0 {
		original := o.IdentityTransitions[0].Proof.Old
		current, valid := lifecycle.ValidIdentityTransitions(o.Cluster, o.ID, original, o.IdentityTransitions)
		if !valid || current != [32]byte(o.Mesh.LocalKey()) {
			return Options{}, errors.New("state root identity transition mismatch")
		}
	}
	return o, nil
}

func engineBindingKey(o Options, key mydcp.Identity) []byte {
	b := []byte(hex.EncodeToString(o.Cluster[:]) + "/" + o.ID + "/" + o.Admin + "/" + hex.EncodeToString(key[:]) + "/" + hex.EncodeToString(o.Manifest[:]))
	if o.ModuleID != ([32]byte{}) {
		b = append(b, []byte("/module/"+hex.EncodeToString(o.ModuleID[:]))...)
	}
	if o.TrackConfiguration {
		b = append(b, []byte("/configuration-index-1")...)
	}
	if o.AdmitMutation != nil {
		b = append(b, []byte("/delegated-mutations-1")...)
	}
	if o.AdmitModulePatch != nil {
		b = append(b, []byte("/related-control-patches-1")...)
	}
	return b
}

// ModuleEnabledAt reports whether this engine admits module commands. A root
// either has the user catalog module from installation or never has it.
func (e *Engine) ModuleEnabledAt(state.State) bool { return e.hasModule }

func (e *Engine) ModuleEnabled() bool {
	view := e.fsm.readView.Load()
	return view != nil && view.err == nil && e.hasModule
}
