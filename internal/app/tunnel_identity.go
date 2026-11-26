// SPDX-License-Identifier: Apache-2.0

package app

import (
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

// Resolve only after selecting an original source/reference in this same view.
// The original owner remains in endpoint IDs, journals and native receipts.
func (r *Runtime) tunnelWireKey(s state.State, original [32]byte) ([32]byte, error) {
	current := r.controlPolicy.ResourceWorkKey(s, original)
	if current == ([32]byte{}) {
		return current, mydcp.ErrAdmission
	}
	return current, nil
}
func (r *Runtime) localTunnelWireKey(v cluster.View) ([32]byte, error) {
	key, err := r.tunnelWireKey(v.State, r.Identity.Public)
	if err != nil || key != r.commandIdentity().Public {
		return [32]byte{}, mydcp.ErrAdmission
	}
	return key, nil
}
