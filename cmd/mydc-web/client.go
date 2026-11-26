// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/jay94ks/mydcd/internal/web/config"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// newClient opens the real mydcd adapter for the pinned node behind the
// socket. The fake adapter in internal/web/mydc is a test double only.
func newClient(cfg config.Config) (mydc.Client, error) {
	cluster, err := cfg.ClusterKey()
	if err != nil {
		return nil, err
	}
	key, err := cfg.NodeIdentityKey()
	if err != nil {
		return nil, err
	}
	return mydc.NewReal(mydc.RealConfig{Socket: cfg.Socket, Cluster: cluster, Node: cfg.Node, NodeKey: key})
}
