// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/config"
)

// ManagedManifest identifies the managed runtime policy of one cluster.
func ManagedManifest(clusterID, admin [32]byte, genesis config.Peer) [32]byte {
	raw, _ := json.Marshal(struct {
		Mode           string
		Cluster, Admin [32]byte
		Genesis        config.Peer
	}{"managed", clusterID, admin, genesis})
	return sha256.Sum256(raw)
}
