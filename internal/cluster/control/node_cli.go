// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
)

type NodeCLIChange struct {
	DisableNodeCLIOperation bool `json:"disable_node_cli_operation" yaml:"disable_node_cli_operation"`
}

func (p Policy) nodeKeyContext(s state.State, c access.Catalog) (access.Catalog, error) {
	members, err := p.Members(s)
	if err != nil {
		return c, err
	}
	keys := make([][32]byte, 0, len(members.Entries))
	for _, member := range members.Entries {
		key, err := identity.ParseKey(member.CurrentPeer().Key)
		if err != nil {
			return c, err
		}
		keys = append(keys, key)
	}
	return c.WithNodeKeys(keys), nil
}

// NodeCLIAllowed is only the legacy raw-command/query boundary. Typed user
// operations and original owner reports have their own stronger authorization.
func (p Policy) NodeCLIAllowed(s state.State) bool {
	c, err := p.Catalog(s)
	return err == nil && !c.NodeCLI().DisableNodeCLIOperation
}
