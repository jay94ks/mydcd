// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/tenancy"
	"slices"
)

// DNSPolicyView is desired policy and its exact source CAS. Resolver addresses
// are filled only by the current native owner after inspecting real sockets.
type DNSPolicyView struct {
	Revision  uint64
	Policy    services.ManagedDNSPolicy
	Resolvers []string
	Ready     *bool `json:",omitempty"`
	State     string
}
type NetworkDNSTarget struct {
	Source                deployment.ObjectRef
	Owner                 [32]byte
	Node, Tenant, Network string
}

func (p Policy) NetworkDNSView(s state.State, n tenancy.Network) (*DNSPolicyView, NetworkDNSTarget, error) {
	sources, err := p.ManagedDNS(s)
	if err != nil {
		return nil, NetworkDNSTarget{}, err
	}
	key := services.ManagedDNSKey(n.Tenant, n.Logical)
	source, ok := sources[key]
	if !ok {
		return nil, NetworkDNSTarget{}, nil
	}
	policy := source.Definition.Policy
	policy.Upstreams = slices.Clone(policy.Upstreams)
	policy.Transports = slices.Clone(policy.Transports)
	o := s.Object(key)
	return &DNSPolicyView{Revision: o.Revision, Policy: policy, Resolvers: []string{}, State: "unknown"}, NetworkDNSTarget{Source: deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}, Owner: n.Owner, Node: n.Node, Tenant: n.Tenant, Network: n.Logical}, nil
}
