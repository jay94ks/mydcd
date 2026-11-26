// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/workload"
	"net/netip"
	"slices"
	"strconv"
)

// HostPortUse is a derived view of accepted/held original resources, never a
// separate allocator or permission grant. Keys retain tenant and native scope.
type HostPortUse struct {
	Key, Node string
	Owner     [32]byte
	Ports     []workload.PublishedPort
}

func StepHostPortUse(s Step) (HostPortUse, error) {
	u := HostPortUse{Key: s.Key, Node: s.Node, Owner: s.Owner}
	switch s.Kind {
	case "task":
		var service ComposeService
		if json.Unmarshal(s.Goal, &service) != nil || workload.ValidatePublishedPorts(service.Ports) != nil {
			return u, ErrInputs
		}
		u.Ports = slices.Clone(service.Ports)
	case "ingress":
		var d IngressDeclaration
		if json.Unmarshal(s.Goal, &d) != nil {
			return u, ErrInputs
		}
		var err error
		u.Ports, err = ingressPublishedPorts(d)
		if err != nil {
			return u, err
		}
	}
	return u, nil
}

func CheckHostPortUses(current []HostPortUse, candidate HostPortUse) error {
	for i, p := range candidate.Ports {
		for _, prior := range candidate.Ports[:i] {
			if workload.PublishedPortsConflict(p, prior) {
				return inputError("HOST_PORT_CONFLICT", candidate.Key)
			}
		}
		for _, u := range current {
			if u.Node != candidate.Node || u.Key == candidate.Key && u.Owner == candidate.Owner {
				continue
			}
			for _, prior := range u.Ports {
				if workload.PublishedPortsConflict(p, prior) {
					return inputError("HOST_PORT_CONFLICT", candidate.Key)
				}
			}
		}
	}
	return nil
}

func ingressPublishedPorts(d IngressDeclaration) ([]workload.PublishedPort, error) {
	var ports []workload.PublishedPort
	for _, l := range d.Listeners {
		if l.Shared != "" {
			continue
		}
		a, err := netip.ParseAddrPort(l.Address)
		if err != nil || a.Port() == 0 {
			return nil, ErrInputs
		}
		p := workload.PublishedPort{HostIP: a.Addr().String(), Target: uint32(a.Port()), Published: strconv.Itoa(int(a.Port())), Protocol: "tcp"}
		ports = append(ports, p)
		if l.HTTP3 {
			p.Protocol = "udp"
			ports = append(ports, p)
		}
	}
	return workload.NormalizePublishedPorts(ports)
}

func (b Blueprint) checkPublishedPorts(ctx PlanningContext) error {
	uses := slices.Clone(ctx.HostPorts)
	for _, step := range b.d.Steps {
		u, err := StepHostPortUse(step)
		if err != nil {
			return err
		}
		if err = CheckHostPortUses(uses, u); err != nil {
			return err
		}
		if len(u.Ports) > 0 {
			uses = append(uses, u)
		}
	}
	return nil
}

func IngressHostPortUse(key, node string, owner [32]byte, d IngressDeclaration) (HostPortUse, error) {
	ports, err := ingressPublishedPorts(d)
	return HostPortUse{Key: key, Node: node, Owner: owner, Ports: ports}, err
}
