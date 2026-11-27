// SPDX-License-Identifier: Apache-2.0

package network

import (
	"context"
	"errors"
	"maps"
	"sort"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"

	cerrdefs "github.com/containerd/errdefs"
	dockernet "github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
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
	// Hooks answers the engine's sfc network driver. Execute registers each
	// create with it before sending; without it nothing is created.
	Hooks *EngineHooks
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
	// The sfc driver takes the device name and MTU from the create hook
	// (EngineHooks.Create) and never masquerades; only the gateway mode is
	// asked for here.
	options := map[string]string{}
	if s.GatewayMode == ManagedGatewayMode {
		if v4 {
			options["com.docker.network.bridge.gateway_mode_ipv4"] = s.GatewayMode
		}
		if v6 {
			options["com.docker.network.bridge.gateway_mode_ipv6"] = s.GatewayMode
		}
	}
	return client.NetworkCreateOptions{Driver: EngineDriver, Scope: "local", EnableIPv4: &v4, EnableIPv6: &v6, IPAM: ipam, Internal: s.Internal, Options: options, Labels: id.Labels}
}

// EngineDriver is the engine's built-in network driver: the bridge driver
// with a synchronous call to sfcd around each step (seafield patch 0011).
const EngineDriver = "sfc"

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
	if !id.Matches(n.Name, n.Labels) || n.ID == "" || n.Driver != EngineDriver || n.Scope != "local" || n.Internal != s.Internal || n.EnableIPv4 != *options.EnableIPv4 || n.EnableIPv6 != *options.EnableIPv6 || n.Ingress || n.ConfigOnly || n.IPAM.Driver != "default" || len(n.IPAM.Options) != 0 || len(n.IPAM.Config) != len(options.IPAM.Config) {
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
			if d.Hooks == nil {
				return reconcile.EffectNotApplied, errors.New("no engine network hooks: the sfc driver would refuse the create")
			}
			if err := ctx.Err(); err != nil {
				return reconcile.EffectNotApplied, err
			}
			stage, err := d.Hooks.Expect(key, op, s, id)
			if err != nil {
				return reconcile.EffectNotApplied, err
			}
			_, err = api.NetworkCreate(ctx, id.Name, bridgeOptions(s, id))
			// The sfc driver asks the create hook before it makes anything,
			// so what the hook saw decides: never asked, refused or undone
			// by the engine means nothing was made. After done, a late
			// create hook for this name is answered not-owner, so even a
			// cancelled call that never reached the hook made nothing.
			if reached := stage(); err != nil {
				if hookRefusedCreate(reached) {
					return reconcile.EffectNotApplied, err
				}
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
			// The sfc driver removes the device before the engine drops
			// the network record, so an absent record means it is gone.
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
		// The created hook checked the device when it was made; after a
		// restart the engine's record is what the joins are matched to.
		if d.Hooks != nil {
			d.Hooks.Adopt(got.Network.ID, key, op.Target.Generation, s.MTU)
		}
		return reconcile.EffectApplied, nil
	}
	return reconcile.EffectUnknown, nil
}
