// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"encoding/hex"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"strings"
)

func (s ContainerSpec) resourceOwner(cluster [32]byte, node string, original [32]byte) bool {
	parts := strings.Split(s.Node, "/")
	if len(parts) != 2 || parts[0] != hex.EncodeToString(cluster[:]) {
		return false
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return false
	}
	var current [32]byte
	copy(current[:], raw)
	return lifecycle.ResourceIdentity(cluster, node, current, original, s.ResourceKeys)
}
func (d *DockerDriver) taskNetworkManager(s ContainerSpec) BridgeProvider {
	if d.Network == nil {
		return nil
	}
	if s.BridgeOwner == "" || s.BridgeOwner == s.Node {
		return d.Network
	}
	if owner, ok := d.Network.(interface{ Retained(string) *network.Manager }); ok {
		retained := owner.Retained(s.BridgeOwner)
		if retained == nil {
			return nil
		}
		return retained
	}
	return nil
}
func (s ContainerSpec) validBridgeOwner() bool {
	if s.BridgeOwner == "" {
		return true
	}
	if len(s.ResourceKeys) == 0 {
		return false
	}
	row := s.ResourceKeys[0].Proof
	parts := strings.Split(s.BridgeOwner, "/")
	if len(parts) != 2 {
		return false
	}
	raw, err := hex.DecodeString(parts[1])
	if err != nil || len(raw) != 32 {
		return false
	}
	var owner [32]byte
	copy(owner[:], raw)
	return s.BridgeOwner == engine.Owner(row.Cluster, owner) && s.resourceOwner(row.Cluster, row.Node, owner)
}
