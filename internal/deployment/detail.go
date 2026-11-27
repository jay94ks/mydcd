// SPDX-License-Identifier: Apache-2.0

package deployment

import "github.com/jay94ks/seafield/internal/containerops"

// ServiceIngress returns only declared public associations. It does not assert
// readiness of an independently owned gateway or copy certificate references.
func (b Blueprint) ServiceIngress(service string) []containerops.DetailIngress {
	definition := b.d.Input.Sfc.Ingress
	if definition == nil || definition.Backend.Service != service {
		return nil
	}
	link := containerops.DetailIngress{Host: definition.Host, Node: definition.Node, BackendPort: definition.Backend.Port, State: "declared"}
	for _, listener := range definition.Listeners {
		link.Listeners = append(link.Listeners, listener.Address)
	}
	return []containerops.DetailIngress{link}
}
