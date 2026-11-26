// SPDX-License-Identifier: Apache-2.0

package lifecycle

// ResourceIdentity verifies a frozen physical-node key lineage. It permits
// referencing an original resource, never authenticating with its old key.
// Current command/transport authority must be checked separately.
func ResourceIdentity(cluster [32]byte, node string, current, original [32]byte, rows []IdentityTransition) bool {
	if current == ([32]byte{}) || original == ([32]byte{}) {
		return false
	}
	if len(rows) == 0 {
		return current == original
	}
	key, valid := ValidIdentityTransitions(cluster, node, rows[0].Proof.Old, rows)
	if !valid || key != current {
		return false
	}
	if original == current {
		return true
	}
	for _, row := range rows {
		if row.Proof.Old == original {
			return true
		}
	}
	return false
}
