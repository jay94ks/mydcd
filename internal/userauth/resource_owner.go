// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// resourceOwner resolves a retained native source to its installed physical
// node's CURRENT key. It never looks up a historical key for TLS/issuer/command
// admission; every caller still checks its exact job and current user permit.
func (s Service) resourceOwner(view state.State, node string, original [32]byte) ([32]byte, error) {
	members, err := s.Policy.Members(view)
	if err != nil || !members.ResourceKeyForNode(node, original) {
		return [32]byte{}, sfcp.ErrAdmission
	}
	entry, ok := members.Entry(node)
	if !ok {
		return [32]byte{}, sfcp.ErrAdmission
	}
	key, err := identity.ParseKey(entry.CurrentPeer().Key)
	if err != nil || !members.MemberKey(key) {
		return [32]byte{}, sfcp.ErrAdmission
	}
	return key, nil
}
