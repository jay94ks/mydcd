// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/moby/moby/api/types/container"
	dockernet "github.com/moby/moby/api/types/network"
)

var ErrPublishedPorts = errors.New("INVALID_PUBLISHED_PORTS")

// PublishedPort is the normalized Compose intent shared by app and standalone
// Tasks. Published empty requests Docker allocation; a range lets Docker choose
// within that range. Neither is a cluster allocation or a native receipt.
type PublishedPort struct {
	Name        string `yaml:"name,omitempty" json:",omitempty"`
	HostIP      string `yaml:"host_ip,omitempty" json:",omitempty"`
	Target      uint32 `yaml:"target"`
	Published   string `yaml:"published,omitempty" json:",omitempty"`
	Protocol    string `yaml:"protocol,omitempty"`
	Mode        string `yaml:"mode,omitempty" json:",omitempty"`
	AppProtocol string `yaml:"app_protocol,omitempty" json:",omitempty"`
}

func NormalizePublishedPorts(input []PublishedPort) ([]PublishedPort, error) {
	var out []PublishedPort
	for _, p := range input {
		p.Protocol = strings.ToLower(p.Protocol)
		if p.Mode == "" {
			p.Mode = "ingress"
		}
		if p.Protocol == "" {
			p.Protocol = "tcp"
		}
		if p.Target == 0 || p.Target > 65535 || p.Protocol != "tcp" && p.Protocol != "udp" || p.Mode != "" && p.Mode != "host" && p.Mode != "ingress" || strings.ContainsAny(p.Name+p.AppProtocol, "\x00\r\n") {
			return nil, ErrPublishedPorts
		}
		if p.HostIP != "" {
			a, err := netip.ParseAddr(p.HostIP)
			if err != nil || a.Is4In6() || a.Zone() != "" || a.IsMulticast() {
				return nil, ErrPublishedPorts
			}
			p.HostIP = a.String()
		}
		if p.Published == "0" {
			p.Published = ""
		}
		if p.Published != "" {
			r, err := dockernet.ParsePortRange(p.Published + "/" + p.Protocol)
			if err != nil || r.Start() == 0 {
				return nil, ErrPublishedPorts
			}
			p.Published = strconv.Itoa(int(r.Start()))
			if r.End() != r.Start() {
				p.Published += "-" + strconv.Itoa(int(r.End()))
			}
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b PublishedPort) int {
		if a.Target != b.Target {
			if a.Target < b.Target {
				return -1
			}
			return 1
		}
		for _, pair := range [][2]string{{a.Protocol, b.Protocol}, {a.HostIP, b.HostIP}, {a.Published, b.Published}, {a.Mode, b.Mode}, {a.Name, b.Name}, {a.AppProtocol, b.AppProtocol}} {
			if n := strings.Compare(pair[0], pair[1]); n != 0 {
				return n
			}
		}
		return 0
	})
	return out, nil
}

func ValidatePublishedPorts(ports []PublishedPort) error {
	normal, err := NormalizePublishedPorts(ports)
	if err != nil || !slices.Equal(normal, ports) {
		return ErrPublishedPorts
	}
	return nil
}

// FixedPublishedListener exposes only a deterministic host-port choice. Docker
// selects dynamic/range choices itself; no whole range is reserved here.
func FixedPublishedListener(p PublishedPort) (network.Listener, bool) {
	if p.Published == "" || strings.Contains(p.Published, "-") {
		return network.Listener{}, false
	}
	n, err := strconv.ParseUint(p.Published, 10, 16)
	if err != nil || n == 0 {
		return network.Listener{}, false
	}
	a := netip.IPv6Unspecified()
	if p.HostIP != "" {
		a, err = netip.ParseAddr(p.HostIP)
		if err != nil {
			return network.Listener{}, false
		}
	}
	proto := uint8(6)
	if p.Protocol == "udp" {
		proto = 17
	}
	return network.Listener{Address: a, Port: uint16(n), Protocol: proto, DualStack: a == netip.IPv6Unspecified()}, true
}

func PublishedPortsConflict(a, b PublishedPort) bool {
	x, ok := FixedPublishedListener(a)
	y, other := FixedPublishedListener(b)
	return ok && other && network.ListenerConflict(x, y)
}

func nativePublishedPorts(ports []PublishedPort) (dockernet.PortSet, dockernet.PortMap, error) {
	if ValidatePublishedPorts(ports) != nil {
		return nil, nil, ErrPublishedPorts
	}
	if len(ports) == 0 {
		return nil, nil, nil
	}
	exposed, bindings := dockernet.PortSet{}, dockernet.PortMap{}
	for _, p := range ports {
		port, ok := dockernet.PortFrom(uint16(p.Target), dockernet.IPProtocol(p.Protocol))
		if !ok {
			return nil, nil, ErrPublishedPorts
		}
		var ip netip.Addr
		if p.HostIP != "" {
			ip, _ = netip.ParseAddr(p.HostIP)
		}
		exposed[port] = struct{}{}
		binding := dockernet.PortBinding{HostIP: ip, HostPort: p.Published}
		if !slices.Contains(bindings[port], binding) {
			bindings[port] = append(bindings[port], binding)
		}
	}
	return exposed, bindings, nil
}

func bindingIPMatches(want, got netip.Addr) bool {
	if !want.IsValid() {
		// An omitted HostIP delegates the default bind address to Docker. The
		// daemon may choose a specific configured address rather than wildcard.
		return !got.IsValid() || got.Zone() == "" && !got.Is4In6() && !got.IsMulticast()
	}
	return want == got
}

func bindingPortMatches(want, got string, selected bool) bool {
	if !selected && (want == got || want == "" && got == "0") {
		return true
	}
	n, err := strconv.ParseUint(got, 10, 16)
	if err != nil || n == 0 {
		return false
	}
	if want == "" {
		return true
	}
	r, err := dockernet.ParsePortRange(want)
	return err == nil && uint16(n) >= r.Start() && uint16(n) <= r.End()
}

// Both requested HostConfig and selected native bindings belong to this exact
// matched container. Extra image EXPOSE metadata grants no host publication.
// Stopped containers may have no active NAT entries; their frozen intent still
// has to match. A restart/recover never adopts another container or port spec.
func matchPublishedPorts(ports []PublishedPort, got container.InspectResponse) bool {
	if got.Config == nil || got.HostConfig == nil || got.NetworkSettings == nil || got.State == nil || got.HostConfig.PublishAllPorts {
		return false
	}
	exposed, want, err := nativePublishedPorts(ports)
	if err != nil {
		return false
	}
	for port := range exposed {
		if _, ok := got.Config.ExposedPorts[port]; !ok {
			return false
		}
	}
	matches := func(binding dockernet.PortBinding, candidates []dockernet.PortBinding, selected bool) bool {
		if selected && !binding.HostIP.IsValid() {
			return false
		}
		for _, p := range candidates {
			if bindingIPMatches(p.HostIP, binding.HostIP) && bindingPortMatches(p.HostPort, binding.HostPort, selected) {
				return true
			}
		}
		return false
	}
	for port, bindings := range got.HostConfig.PortBindings {
		for _, binding := range bindings {
			if !matches(binding, want[port], false) {
				return false
			}
		}
	}
	for port, bindings := range want {
		for _, binding := range bindings {
			found := false
			for _, actual := range got.HostConfig.PortBindings[port] {
				if bindingIPMatches(binding.HostIP, actual.HostIP) && bindingPortMatches(binding.HostPort, actual.HostPort, false) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	for port, bindings := range got.NetworkSettings.Ports {
		for _, binding := range bindings {
			if !matches(binding, want[port], true) {
				return false
			}
		}
	}
	if got.State.Running {
		for port, bindings := range want {
			for _, binding := range bindings {
				found := false
				for _, actual := range got.NetworkSettings.Ports[port] {
					if actual.HostIP.IsValid() && bindingIPMatches(binding.HostIP, actual.HostIP) && bindingPortMatches(binding.HostPort, actual.HostPort, true) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}
		}
	}
	return true
}
