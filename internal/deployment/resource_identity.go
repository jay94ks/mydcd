// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

func (n PlanningNode) resourceIdentity(cluster [32]byte, node string, original [32]byte) bool {
	return lifecycle.ResourceIdentity(cluster, node, n.Key, original, n.ResourceKeys)
}
func (n Needs) resourceIdentity(cluster [32]byte, original [32]byte) bool {
	return lifecycle.ResourceIdentity(cluster, n.Use.Node, n.Use.NodeKey, original, n.ResourceKeys)
}
func ownerKey(owner string, cluster [32]byte) [32]byte {
	parts := strings.Split(owner, "/")
	var key [32]byte
	if len(parts) != 2 || parts[0] != hex.EncodeToString(cluster[:]) {
		return key
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return key
	}
	copy(key[:], raw)
	return key
}

// sameNodeGoalOwner relates exact decoded resource recipes on one physical
// node. Either recipe may predate an installed key switch, but neither an old
// key nor a same-name node is current command/native admission. That remains
// with the committed control policy. Two retained prefixes must agree exactly.
func sameNodeGoalOwner(cluster [32]byte, a, b GoalCommand) bool {
	if cluster == ([32]byte{}) || a.Schema != 1 || b.Schema != 1 || a.Cluster != cluster || b.Cluster != cluster || a.Node == "" || a.Node != b.Node || !lifecycle.ResourceIdentity(cluster, a.Node, a.Owner, a.Owner, a.ResourceKeys) || !lifecycle.ResourceIdentity(cluster, b.Node, b.Owner, b.Owner, b.ResourceKeys) {
		return false
	}
	for i := 0; i < min(len(a.ResourceKeys), len(b.ResourceKeys)); i++ {
		left, _ := json.Marshal(a.ResourceKeys[i])
		right, _ := json.Marshal(b.ResourceKeys[i])
		if !bytes.Equal(left, right) {
			return false
		}
	}
	return lifecycle.ResourceIdentity(cluster, a.Node, a.Owner, b.Owner, a.ResourceKeys) || lifecycle.ResourceIdentity(cluster, b.Node, b.Owner, a.Owner, b.ResourceKeys)
}
