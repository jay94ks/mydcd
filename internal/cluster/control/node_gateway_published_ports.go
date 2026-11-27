// SPDX-License-Identifier: Apache-2.0

package control

import (
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

// nodeGatewayHostPortUse is only the listener geometry of a verified gateway
// record. It is not authorization, a second reservation, or an applied/bind
// receipt. Addresses/Ports are allow lists; only enabled actual Listeners own
// sockets. Shared app mappings borrow these sockets and add no competing use.
func nodeGatewayHostPortUse(node string, owner [32]byte, configuration ingress.GatewayConfiguration) (deployment.HostPortUse, error) {
	if !validID(node) || owner == ([32]byte{}) || configuration.Validate() != nil {
		return deployment.HostPortUse{}, ErrCatalog
	}
	var declaration deployment.IngressDeclaration
	for _, gateway := range []ingress.Gateway{configuration.External, configuration.Local} {
		if !gateway.Enabled {
			continue
		}
		for _, listener := range gateway.Listeners {
			declaration.Listeners = append(declaration.Listeners, deployment.ListenerDeclaration{Address: listener.Address, TLS: listener.TLS, HTTP3: listener.HTTP3})
		}
	}
	// One stable key per managed node preserves CheckHostPortUses' existing
	// exact key+owner self-claim exception for an unchanged/replaced gateway.
	// Neither listener ID nor an app's public name can manufacture this identity.
	return deployment.IngressHostPortUse(IngressManagementKey+"/node-gateways/"+node, node, owner, declaration)
}

func (p Policy) nodeGatewayHostPortUses(s state.State) ([]deployment.HostPortUse, error) {
	book, err := p.IngressManagement(s)
	if err != nil {
		return nil, err
	}
	nodes := make([]string, 0, len(book.NodeGatewaysRecords))
	for _, record := range book.NodeGatewaysRecords {
		nodes = append(nodes, record.Node)
	}
	slices.Sort(nodes)
	var uses []deployment.HostPortUse
	for i, node := range nodes {
		if i > 0 && nodes[i-1] == node {
			return nil, ErrCatalog
		}
		record, found := book.NodeGateways(node)
		if !found {
			return nil, ErrCatalog
		}
		// IngressManagement validated the exact original user signature, node
		// evidence signature and its Configuration match. Keep that accepted owner
		// even when it is offline; current observations cannot release its intent.
		var change NodeGatewaysChange
		if canonical(record.Origin.Change.Payload, &change) != nil || change.Node != node || change.Evidence == nil {
			return nil, ErrCatalog
		}
		use, err := nodeGatewayHostPortUse(node, change.Evidence.Reporter, record.Configuration)
		if err != nil {
			return nil, err
		}
		if len(use.Ports) > 0 {
			uses = append(uses, use)
		}
	}
	return uses, nil
}
