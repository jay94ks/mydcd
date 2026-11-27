// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jay94ks/seafield/internal/web/config"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// newClient opens the real sfcd adapter for the pinned node behind the
// socket. The fake adapter in internal/web/sfc is a test double only.
func newClient(cfg config.Config) (sfc.Client, error) {
	cluster, err := cfg.ClusterKey()
	if err != nil {
		return nil, err
	}
	key, err := cfg.NodeIdentityKey()
	if err != nil {
		return nil, err
	}
	return sfc.NewReal(sfc.RealConfig{Socket: cfg.Socket, Cluster: cluster, Node: cfg.Node, NodeKey: key})
}
