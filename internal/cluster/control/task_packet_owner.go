// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

// Read only the Task's exact frozen attachment. Packet ownership follows the
// borrowed native network; Task/inputs authorization still follows its signer.
func (p Policy) taskPacketOwner(s state.State, task deployment.GoalCommand, alias string, objects map[string]state.Object) ([32]byte, error) {
	material, err := deployment.ResolveRetainedTaskNetwork(p.Cluster, task, alias, objects)
	if err != nil {
		return [32]byte{}, err
	}
	owner := material.NativeOwner(p.Cluster)
	if !p.taskPacketLineage(s, task, owner) {
		return [32]byte{}, ErrCatalog
	}
	return owner, nil
}

func (p Policy) taskPacketLineage(s state.State, task deployment.GoalCommand, owner [32]byte) bool {
	if task.Cluster != p.Cluster || task.Kind != "task" || !lifecycle.ResourceIdentity(p.Cluster, task.Node, task.Owner, owner, task.ResourceKeys) {
		return false
	}

	// Unmanaged projection has no membership catalog. Preserve its existing
	// same-owner contract; key replacement always requires managed lineage.

	members, err := p.Members(s)
	if err != nil || owner == ([32]byte{}) || !members.ResourceKeyForNode(task.Node, task.Owner) || !members.ResourceKeyForNode(task.Node, owner) {
		return false
	}
	entry, found := members.Entry(task.Node)
	if !found || len(task.ResourceKeys) > len(entry.Keys) {
		return false
	}
	frozen, _ := json.Marshal(task.ResourceKeys)
	installed, _ := json.Marshal(entry.Keys[:len(task.ResourceKeys)])
	// nil and empty both mean the original installed key, before any transition.
	if len(task.ResourceKeys) > 0 && !bytes.Equal(frozen, installed) {
		return false
	}
	return true
}
