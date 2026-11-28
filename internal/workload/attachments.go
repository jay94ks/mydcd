// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/network"
)

// MaxTaskNetworks matches the compose limit of networks per service.
const MaxTaskNetworks = 16

// TaskAttachment is one network of a Task: the exact committed Bridge the
// container joins, its pin generation and the Task's fixed addresses there.
// The primary attachment lives in ContainerSpec's own Bridge fields, so a
// single-network Task keeps its original bytes; Attachments holds the rest.
type TaskAttachment struct {
	Bridge           string
	BridgeGeneration uint64
	BridgeOwner      string `json:",omitempty"`
	IPv4, IPv6       netip.Addr
	// Routes leave through this attachment's gateway, like the primary
	// attachment's ContainerSpec.Routes.
	Routes []ContainerRoute `json:",omitempty"`
}

// Networks lists every attachment, primary first. The order is the recipe's
// and is the order of the leases the driver holds for them.
func (s ContainerSpec) Networks() []TaskAttachment {
	out := make([]TaskAttachment, 0, 1+len(s.Attachments))
	out = append(out, TaskAttachment{Bridge: s.Bridge, BridgeGeneration: s.BridgeGeneration, BridgeOwner: s.BridgeOwner, IPv4: s.IPv4, IPv6: s.IPv6, Routes: s.Routes})
	return append(out, s.Attachments...)
}

func validTaskAddresses(v4, v6 netip.Addr) bool {
	if !v4.IsValid() && !v6.IsValid() {
		return false
	}
	if v4.IsValid() && (!v4.Is4() || v4.IsUnspecified() || v4.IsMulticast()) {
		return false
	}
	return !v6.IsValid() || v6.Is6() && !v6.Is4In6() && v6.Zone() == "" && !v6.IsUnspecified() && !v6.IsMulticast()
}

func (s ContainerSpec) validAttachments() bool {
	networks := s.Networks()
	if len(networks) > MaxTaskNetworks {
		return false
	}
	seen := map[string]bool{}
	addresses := map[netip.Addr]bool{}
	for _, a := range networks {
		if a.Bridge == "" || a.BridgeGeneration == 0 || seen[a.Bridge] || !validTaskAddresses(a.IPv4, a.IPv6) || !s.validOwner(a.BridgeOwner) {
			return false
		}
		seen[a.Bridge] = true
		for _, ip := range []netip.Addr{a.IPv4, a.IPv6} {
			if !ip.IsValid() {
				continue
			}
			if addresses[ip] {
				return false
			}
			addresses[ip] = true
		}
	}
	return true
}

// acquireNetworks pins every attachment, primary first. A failure leaves the
// earlier pins in place; releaseDependencies returns them all (a missing pin
// returns as nil), so a partial acquisition is never orphaned.
func (d *DockerDriver) acquireNetworks(ctx context.Context, s ContainerSpec, id engine.Identity) ([]network.BridgeLease, error) {
	return d.networkLeases(ctx, s, id, true)
}

// inspectNetworks reads the existing pins only; it never creates one.
func (d *DockerDriver) inspectNetworks(ctx context.Context, s ContainerSpec, id engine.Identity) ([]network.BridgeLease, error) {
	return d.networkLeases(ctx, s, id, false)
}

func (d *DockerDriver) networkLeases(ctx context.Context, s ContainerSpec, id engine.Identity, acquire bool) ([]network.BridgeLease, error) {
	networks := s.Networks()
	out := make([]network.BridgeLease, 0, len(networks))
	for _, a := range networks {
		bridges := d.bridgeManager(s, a.BridgeOwner)
		if bridges == nil {
			return out, engine.ErrOwnership
		}
		var l network.BridgeLease
		var err error
		if acquire {
			l, err = bridges.Acquire(ctx, a.Bridge, containerConsumer(id), a.BridgeGeneration)
		} else {
			l, err = bridges.InspectConsumer(ctx, a.Bridge, containerConsumer(id), a.BridgeGeneration)
		}
		if err != nil {
			return out, err
		}
		out = append(out, l)
	}
	return out, nil
}

// returnNetworks returns every attachment's pin. It tries all of them even
// after a failure, so one stuck Bridge does not keep the others pinned.
func (d *DockerDriver) returnNetworks(s ContainerSpec, consumer string) error {
	var errs []error
	for _, a := range s.Networks() {
		bridges := d.bridgeManager(s, a.BridgeOwner)
		if bridges == nil {
			errs = append(errs, engine.ErrOwnership)
			continue
		}
		if err := bridges.ReturnConsumer(a.Bridge, consumer, a.BridgeGeneration); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func bridgeSpecs(leases []network.BridgeLease) []network.BridgeSpec {
	out := make([]network.BridgeSpec, len(leases))
	for i, l := range leases {
		out[i] = l.Spec
	}
	return out
}

// allowedTaskAddress is a usable host address of one of the Bridge's pools.
func allowedTaskAddress(address netip.Addr, spec network.BridgeSpec) bool {
	for _, p := range spec.Pools {
		if p.Prefix.Contains(address) && address != p.Gateway && address != p.Prefix.Addr() && (!address.Is4() || p.Prefix.Contains(address.Next())) {
			return true
		}
	}
	return false
}
