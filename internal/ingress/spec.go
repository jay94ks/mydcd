// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/schema"
	"net/netip"
	"strconv"
)

// Certificate is an installation-local reference; private bytes never enter
// Shared Desired or the ingress journal.
type Certificate struct{ CertFile, KeyFile string }
type Listener struct {
	ID      string `yaml:"id"`
	Address string `yaml:"address,omitempty"`
	// TLS serves HTTPS with the store certificate linked to each SNI host.
	TLS    bool   `json:",omitempty" yaml:"tls,omitempty"`
	Shared string `json:",omitempty" yaml:"shared,omitempty"`
	HTTP3  bool   `yaml:"http3,omitempty"`
}
type BackendSpec struct {
	Revision            uint64 `json:",omitempty"`
	Draining, Suspended bool   `json:",omitempty"`
	ID, Task, Network   string
	Node, Version       string            `json:",omitempty"`
	Labels              map[string]string `json:",omitempty"`
	Generation          uint64
	Address             netip.Addr
	Port                uint16
	Weight, Capacity    int
	HealthPath          string
}
type Service struct {
	ID       string
	Backends []BackendSpec
	Balance  *Balance `json:",omitempty"`
}
type Spec struct {
	DynamicBackends                                                            bool   `json:",omitempty"`
	BindingRevision                                                            uint64 `json:",omitempty"`
	Schema                                                                     uint8
	Owner                                                                      string
	Tenant, App                                                                string `json:",omitempty"`
	SystemWildcard                                                             bool   `json:",omitempty"`
	Listeners                                                                  []Listener
	Routes                                                                     []Route
	Services                                                                   []Service
	MaxRequests, MaxConnections, MaxHeaderBytes, BufferBytes                   int
	MaxBodyBytes                                                               int64
	RequestTimeoutMS, DialTimeoutMS, ResponseHeaderTimeoutMS, HealthIntervalMS int
	Lifecycle                                                                  schema.Lifecycle
}

func DecodeSpec(value string) (Spec, error) {
	s, err := schema.Decode[Spec]([]byte(value))
	if err != nil || s.Schema != 1 || s.Owner == "" || !s.Lifecycle.Valid() || len(s.Listeners) == 0 || len(s.Listeners) > 64 || len(s.Routes) == 0 || len(s.Routes) > 256 || len(s.Services) == 0 || len(s.Services) > 128 || ValidateLimits(s) != nil {
		return s, ErrRoute
	}
	if s.DynamicBackends != (s.BindingRevision != 0) {
		return s, ErrRoute
	}
	ports, _ := network.NewPorts(128)
	ids := map[string]bool{}
	for _, l := range s.Listeners {
		if l.Shared != "" {
			if l.ID == "" || ids[l.ID] || l.Address != "" || l.TLS || l.HTTP3 || !tokenName(l.Shared) {
				return s, ErrRoute
			}
			ids[l.ID] = true
			continue
		}
		a, e := netip.ParseAddrPort(l.Address)
		if e != nil || l.Address != a.String() || a.Port() == 0 || a.Addr().Zone() != "" || a.Addr().Is4In6() || a.Addr().IsMulticast() || l.ID == "" || len(l.ID) > 128 || ids[l.ID] || l.HTTP3 && !l.TLS {
			return s, ErrRoute
		}
		ids[l.ID] = true
		for _, proto := range []uint8{6, 17} {
			if proto == 17 && !l.HTTP3 {
				continue
			}
			ports, e = ports.Reserve(network.Listener{ID: l.ID + "/" + strconv.Itoa(int(proto)), Owner: s.Owner, Generation: 1, Address: a.Addr(), Protocol: proto, Port: a.Port()})
			if e != nil {
				return s, ErrRoute
			}
		}
	}
	services := map[string]bool{}
	backendIDs := map[string]bool{}
	for _, v := range s.Services {
		if v.ID == "" || services[v.ID] || len(v.Backends) == 0 && !s.DynamicBackends || len(v.Backends) > 128 {
			return s, ErrRoute
		}
		services[v.ID] = true
		if v.Balance != nil && v.Balance.Validate() != nil {
			return s, ErrRoute
		}
		for _, b := range v.Backends {
			if len(b.Labels) > 64 {
				return s, ErrRoute
			}
			for key, value := range b.Labels {
				if key == "" || len(key) > 128 || len(value) > 1024 {
					return s, ErrRoute
				}
			}
			if s.DynamicBackends && b.Revision < b.Generation || !s.DynamicBackends && (b.Revision != 0 || b.Draining || b.Suspended) {
				return s, ErrRoute
			}
			if b.ID == "" || len(b.ID) > 128 || backendIDs[b.ID] || b.Task == "" || b.Network == "" || b.Generation == 0 || !b.Address.IsValid() || b.Address.Is4In6() || b.Address.Zone() != "" || b.Address.IsUnspecified() || b.Address.IsMulticast() || b.Port == 0 || b.Weight < 1 || b.Weight > 1024 || b.Capacity < 1 || b.Capacity > s.MaxRequests || !validPath(b.HealthPath) {
				return s, ErrRoute
			}
			backendIDs[b.ID] = true
		}
	}
	if len(backendIDs) > 1024 {
		return s, ErrRoute
	}
	for _, r := range s.Routes {
		if !services[r.Service] || r.Gateway != "" && r.Gateway != "local" && r.Gateway != "external" && r.Gateway != "both" || r.Balance != nil && r.Balance.Validate() != nil {
			return s, ErrRoute
		}
	}
	for _, gateway := range []string{"local", "external"} {
		if _, err = routeTable(s.Routes, gateway); err != nil {
			return s, err
		}
	}
	return s, nil
}

// ValidateLimits shares the real server budgets with declaration validation.
func ValidateLimits(s Spec) error {
	if s.MaxRequests < 1 || s.MaxRequests > 1024 || s.MaxConnections < 1 || s.MaxConnections > 4096 || s.MaxHeaderBytes < 1024 || s.MaxHeaderBytes > 64<<10 || s.MaxBodyBytes < 1 || s.MaxBodyBytes > 64<<20 || s.BufferBytes < s.MaxRequests*(64<<10) || s.BufferBytes > 64<<20 || s.DialTimeoutMS < 1 || s.DialTimeoutMS > 30000 || s.ResponseHeaderTimeoutMS < 1 || s.ResponseHeaderTimeoutMS > 60000 || s.RequestTimeoutMS < 1 || s.RequestTimeoutMS > 3600000 || s.HealthIntervalMS < 50 || s.HealthIntervalMS > 60000 {
		return ErrRoute
	}
	return nil
}
