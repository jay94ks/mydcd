// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strconv"

	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"

	cerrdefs "github.com/containerd/errdefs"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

type BridgeSpec struct {
	Schema         uint8
	Network, Owner string
	MTU            int
	Pools          []Pool
	Internal       bool
	Lifecycle      schema.Lifecycle
	GatewayMode    string `json:",omitempty"`
}

const ManagedGatewayMode = "nat-unprotected"

// DecodeBridge uses the same allocation policy as the A7 core. Pool addresses
// are explicit committed input; the Engine is never asked to choose a subnet.
func DecodeBridge(value string) (BridgeSpec, error) {
	s, err := schema.Decode[BridgeSpec]([]byte(value))
	if err != nil || s.Schema != 1 || s.Network == "" || s.Owner == "" || s.MTU < 1280 || s.MTU > 65535 || len(s.Pools) == 0 || len(s.Pools) > 32 || !s.Lifecycle.Valid() || s.GatewayMode != "" && s.GatewayMode != ManagedGatewayMode || s.GatewayMode == ManagedGatewayMode && s.Internal {
		return s, ErrPolicy
	}
	b, _ := NewBook(1)
	last := ""
	for _, p := range s.Pools {
		if p.ID <= last || p.Network != s.Network || p.Owner != s.Owner || p.MTU != s.MTU || p.Draining {
			return s, ErrPolicy
		}
		b, err = b.AddPool(p)
		if err != nil {
			return s, err
		}
		last = p.ID
	}
	return s, nil
}

type BridgeProtection func(context.Context, string, reconcile.Resource) error

type BridgeDriver struct {
	Engine  *engine.Client
	Protect BridgeProtection
	// Nil uses the native netlink query. Tests inject only this OS boundary;
	// it supplies absence, never a successful SDK/native creation result.
	lookupBridge func(string) (netlink.Link, error)
}

func (d *BridgeDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.Inspect(ctx, key, op)
}

func bridgeOptions(s BridgeSpec, id engine.Identity) client.NetworkCreateOptions {
	v4, v6 := false, false
	ipam := &dockernet.IPAM{Driver: "default"}
	for _, p := range s.Pools {
		v4 = v4 || p.Prefix.Addr().Is4()
		v6 = v6 || p.Prefix.Addr().Is6()
		config := dockernet.IPAMConfig{Subnet: p.Prefix, Gateway: p.Gateway, IPRange: p.IPAM.Dynamic}
		ipam.Config = append(ipam.Config, config)
	}
	// A deterministic kernel name fits IFNAMSIZ and remains tied to this exact
	// Engine object. Full labels/spec and readback establish ownership.
	bridgeName := bridgeDeviceName(id)
	options := map[string]string{"com.docker.network.bridge.name": bridgeName, "com.docker.network.driver.mtu": strconv.Itoa(s.MTU)}
	if s.GatewayMode == ManagedGatewayMode {
		options["com.docker.network.bridge.enable_ip_masquerade"] = "false"
		if v4 {
			options["com.docker.network.bridge.gateway_mode_ipv4"] = s.GatewayMode
		}
		if v6 {
			options["com.docker.network.bridge.gateway_mode_ipv6"] = s.GatewayMode
		}
	}
	return client.NetworkCreateOptions{Driver: "bridge", Scope: "local", EnableIPv4: &v4, EnableIPv6: &v6, IPAM: ipam, Internal: s.Internal, Options: options, Labels: id.Labels}
}

func bridgeDeviceName(id engine.Identity) string { return "md" + id.Name[len(id.Name)-12:] }

// BridgeDeviceName reuses the Engine's exact original identity, without SDK
// effects or a second naming algorithm for policy routing dependencies.
func BridgeDeviceName(owner, key string, generation uint64, digest [32]byte) (string, error) {
	if owner == "" {
		return "", engine.ErrOwnership
	}
	identity, err := (&engine.Client{Owner: owner}).IdentityDigest("bridge", key, generation, digest)
	if err != nil {
		return "", err
	}
	return bridgeDeviceName(identity), nil
}

func matchBridge(n dockernet.Inspect, s BridgeSpec, id engine.Identity) bool {
	options := bridgeOptions(s, id)
	if !id.Matches(n.Name, n.Labels) || n.ID == "" || n.Driver != "bridge" || n.Scope != "local" || n.Internal != s.Internal || n.EnableIPv4 != *options.EnableIPv4 || n.EnableIPv6 != *options.EnableIPv6 || n.Ingress || n.ConfigOnly || n.IPAM.Driver != "default" || len(n.IPAM.Options) != 0 || len(n.IPAM.Config) != len(options.IPAM.Config) {
		return false
	}
	for k, v := range options.Options {
		if n.Options[k] != v {
			return false
		}
	}
	if s.GatewayMode == "" {
		for _, family := range []string{"ipv4", "ipv6"} {
			mode := n.Options["com.docker.network.bridge.gateway_mode_"+family]
			if mode != "" && mode != "nat" {
				return false
			}
		}
	}
	a := append([]dockernet.IPAMConfig(nil), n.IPAM.Config...)
	b := append([]dockernet.IPAMConfig(nil), options.IPAM.Config...)
	sort.Slice(a, func(i, j int) bool { return a[i].Subnet.String() < a[j].Subnet.String() })
	sort.Slice(b, func(i, j int) bool { return b[i].Subnet.String() < b[j].Subnet.String() })
	for i := range a {
		if a[i].Subnet != b[i].Subnet || a[i].Gateway != b[i].Gateway || a[i].IPRange != b[i].IPRange || !maps.Equal(a[i].AuxAddress, b[i].AuxAddress) {
			return false
		}
	}
	return true
}

func (d *BridgeDriver) parameters(key string, op reconcile.Operation) (BridgeSpec, engine.Identity, error) {
	if d.Engine == nil {
		return BridgeSpec{}, engine.Identity{}, engine.ErrOwnership
	}
	s, err := DecodeBridge(op.Target.Spec)
	if err != nil || s.Owner != d.Engine.Owner {
		return s, engine.Identity{}, engine.ErrOwnership
	}
	id, err := d.Engine.Identity("bridge", key, op.Target)
	return s, id, err
}

func (d *BridgeDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	api := d.Engine.API
	got, err := api.NetworkInspect(ctx, id.Name, client.NetworkInspectOptions{})
	if err != nil && !cerrdefs.IsNotFound(err) {
		return reconcile.EffectUnknown, err
	}
	if err == nil && !matchBridge(got.Network, s, id) {
		return reconcile.EffectUnknown, engine.ErrOwnership
	}
	if op.Kind == reconcile.Remove {
		if cerrdefs.IsNotFound(err) {
			return d.Inspect(ctx, key, op)
		}
		if len(got.Network.Containers) != 0 {
			return reconcile.EffectUnknown, errors.New("bridge still has Engine endpoints")
		}
		if _, err = api.NetworkRemove(ctx, got.Network.ID, client.NetworkRemoveOptions{}); err != nil {
			return reconcile.EffectUnknown, err
		}
	} else if op.Kind == reconcile.Apply {
		if cerrdefs.IsNotFound(err) {
			if s.GatewayMode == ManagedGatewayMode {
				if d.Protect == nil {
					return reconcile.EffectNotApplied, errors.New("managed gateway requires original native protection before create")
				}
				if err := d.Protect(ctx, key, op.Target); err != nil {
					return reconcile.EffectNotApplied, err // SDK create positively not sent.
				}
			}
			lookup := d.lookupBridge
			if lookup == nil {
				lookup = netlink.LinkByName
			}
			if _, err := lookup(bridgeDeviceName(id)); err == nil {
				// Docker may configure an existing user-created bridge even
				// when it has no corresponding network record. Never adopt it.
				return reconcile.EffectNotApplied, engine.ErrOwnership
			} else {
				var missing netlink.LinkNotFoundError
				if !errors.As(err, &missing) {
					return reconcile.EffectNotApplied, err
				}
			}
			if err := ctx.Err(); err != nil {
				return reconcile.EffectNotApplied, err
			}
			if _, err = api.NetworkCreate(ctx, id.Name, bridgeOptions(s, id)); err != nil {
				return reconcile.EffectUnknown, err
			}
		}
	} else {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	return d.Inspect(ctx, key, op)
}

func (d *BridgeDriver) Inspect(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	got, err := d.Engine.API.NetworkInspect(ctx, id.Name, client.NetworkInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if op.Kind == reconcile.Remove {
			name := bridgeOptions(s, id).Options["com.docker.network.bridge.name"]
			if _, linkErr := netlink.LinkByName(name); linkErr == nil {
				return reconcile.EffectUnknown, nil
			} else {
				var missing netlink.LinkNotFoundError
				if !errors.As(linkErr, &missing) {
					return reconcile.EffectUnknown, linkErr
				}
			}
			return reconcile.EffectApplied, nil
		}
		// An absent network cannot prove an accepted create terminated.
		return reconcile.EffectUnknown, nil
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if !matchBridge(got.Network, s, id) {
		return reconcile.EffectUnknown, engine.ErrOwnership
	}
	if op.Kind == reconcile.Apply {
		if err := inspectBridgeKernel(s, id); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	return reconcile.EffectUnknown, nil
}

func inspectBridgeKernel(s BridgeSpec, id engine.Identity) error {
	name := bridgeOptions(s, id).Options["com.docker.network.bridge.name"]
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if link.Type() != "bridge" || link.Attrs().MTU != s.MTU {
		return engine.ErrOwnership
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for _, p := range s.Pools {
		found := false
		for _, a := range addresses {
			bits, _ := a.Mask.Size()
			if a.IP.String() == p.Gateway.String() && bits == p.Prefix.Bits() {
				found = true
			}
		}
		if !found {
			return errors.New("Engine bridge gateway absent from kernel")
		}
	}
	return nil
}
