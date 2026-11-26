// SPDX-License-Identifier: Apache-2.0

package tenancy

import "strings"

const ManagedNetworkSourcePrefix = "control/network-sources/"

// SourceIdentity names committed management metadata, not a native effect or
// a grant to create/adopt one. The catalog remains the ownership authority.
type SourceIdentity struct {
	Kind, Tenant, Network, Node string
}

// MemberID is the existing catalog identity for this validated source name.
func (s SourceIdentity) MemberID() string {
	if s.Key() == "" {
		return ""
	}
	return logicalMemberID(s.Tenant, s.Network, s.Node)
}

// systemSegment stands for the system network's empty tenant in source keys.
// It is not a valid tenant ID, so it cannot name a tenant's source.
const systemSegment = "@system"

func scopeSegment(tenant, network string) string {
	if tenant == "" {
		if network != SystemNetwork {
			return ""
		}
		return systemSegment
	}
	if !validID(tenant) {
		return ""
	}
	return tenant
}

func (s SourceIdentity) Key() string {
	scope := scopeSegment(s.Tenant, s.Network)
	if s.Kind != "bridge" && s.Kind != "tun" || scope == "" || !validID(s.Network) || !validID(s.Node) {
		return ""
	}
	return ManagedNetworkSourcePrefix + s.Kind + "/" + scope + "/" + s.Network + "/" + s.Node
}

func ParseSourceIdentity(key string) (SourceIdentity, error) {
	parts := strings.Split(key, "/")
	if len(parts) != 6 || parts[0] != "control" || parts[1] != "network-sources" {
		return SourceIdentity{}, ErrPolicy
	}
	s := SourceIdentity{Kind: parts[2], Tenant: parts[3], Network: parts[4], Node: parts[5]}
	if s.Tenant == systemSegment {
		s.Tenant = ""
	}
	if s.Key() == "" || s.Key() != key {
		return SourceIdentity{}, ErrPolicy
	}
	return s, nil
}

func PacketNamespace(tenant, name string) string {
	if tenant == "" && name == SystemNetwork {
		return "system/network/" + name
	}
	if !validID(tenant) || !validID(name) {
		return ""
	}
	return "tenant/" + tenant + "/network/" + name
}
