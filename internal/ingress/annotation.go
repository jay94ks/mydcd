// SPDX-License-Identifier: Apache-2.0

package ingress

// Display/selection annotations were added without changing installed socket
// or network identities. They can be derived again from the same committed
// Task source and do not require releasing an original network dependency.
func annotationSpec(s Spec) string {
	s.Tenant, s.App = "", ""
	s.Services = append([]Service(nil), s.Services...)
	for at := range s.Services {
		s.Services[at].Backends = append([]BackendSpec(nil), s.Services[at].Backends...)
		for index := range s.Services[at].Backends {
			b := &s.Services[at].Backends[index]
			b.Node, b.Version = "", ""
			b.Labels = nil
		}
	}
	return marshal(s)
}
