// SPDX-License-Identifier: Apache-2.0

package services

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/network"
	"github.com/jay94ks/seafield/internal/tenancy"
)

func verifyDNSOwnerRecreatedBridge(t *testing.T, ctx context.Context, old *DNSOwner, n *network.Manager, policy DNSOwnerPolicy, bridge network.BridgeSpec, bridgeKey string, allocation network.Allocation, closed *ReferenceClose, native string, key ed25519.PrivateKey, publish func(DNSOwnerPolicy)) (*DNSOwner, DNSOwnerPolicy) {
	t.Helper()
	c, networks, a := policy.Catalog, policy.Networks, policy.Authority
	// The original Task/Bridge and all DNS sockets/pins have positively stopped
	// in the caller. These exact signed native facts permit shared retirement.
	var err error
	a, err = a.BeginStaticRetirement(c, networks, "admin", a.Revision(), allocation, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	fence, ok := a.AddressRetirement(allocation)
	if !ok {
		t.Fatal("original address fence missing")
	}
	proof := AddressOwnerClose{Cluster: networks.Cluster(), Target: fence.ID, Epoch: fence.Epoch, Owner: closed.Owner, Boot: old.boot, At: time.Now().Unix(), Native: native, Fenced: true, Stopped: true}
	proof.Signature = ed25519.Sign(key, AddressOwnerCloseBytes(proof))
	a, err = a.ReleaseStatic(allocation, proof, proof.At)
	if err != nil {
		t.Fatal("old Task allocation release", err)
	}
	previous, _ := networks.Network("first", "lan")
	networks, err = networks.Drain(c, "admin", "first", "lan", previous.Revision)
	if err != nil {
		t.Fatal(err)
	}
	a, err = a.SyncPools(networks)
	if err != nil {
		t.Fatal(err)
	}
	drained, _ := networks.Network("first", "lan")
	gone := tenancy.NetworkClosure{Cluster: networks.Cluster(), Tenant: drained.Tenant, Network: drained.ID, Node: drained.Node, Owner: drained.Owner, Generation: drained.Generation, Revision: drained.Revision, NativeGone: true}
	gone.Signature = ed25519.Sign(key, tenancy.NetworkClosureBytes(gone))
	a, networks, err = a.RetireNetwork(c, networks, "admin", gone)
	if err != nil {
		t.Fatal("old logical pool retirement", err)
	}
	next := previous
	next.Generation = 0
	next.Revision = 0
	next.Draining = false
	networks, err = networks.Create(c, "admin", networks.Revision(), next)
	if err != nil {
		t.Fatal(err)
	}
	a, err = a.SyncPools(networks)
	if err != nil {
		t.Fatal(err)
	}
	current, _ := networks.Network("first", "lan")
	if current.Generation <= previous.Generation {
		t.Fatal("old network generation reused")
	}
	if err = n.Desired(bridgeKey, 5, current.Generation, &bridge, 8); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	local, _ := source(networks, networks.Cluster(), "first", "lan", "pool")
	cfg := ownDNSConfig(policy.Config)
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = true
	cfg.Names = nil
	a, ref, err := a.GrantDNSInstance(c, networks, "admin", a.DNSReferenceGeneration("first", "dns", local), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ID == closed.Consumer || ref.Lifetime == closed.Lifetime {
		t.Fatal("closed shared lifetime reused")
	}
	policy.Networks, policy.Authority, policy.Config, policy.BridgeGeneration = networks, a, cfg, current.Generation
	// Keep the same live owner/DB and its original synchronized callback.
	publish(policy)
	o := old
	if o.closed {
		t.Fatal("owner unexpectedly closed before second lifecycle")
	}
	if err = o.Apply(ctx, "first", "dns"); err != nil {
		t.Fatal("new Bridge generation DNS apply", err)
	}
	status, err := o.Inspect(ctx, "first", "dns")
	if err != nil || !status.Ready || status.Settings.Applied != cfg.Source || status.Settings.Observed != cfg.Source {
		t.Fatal("new generation DNS publication", status, err)
	}
	// Retire the new empty view and close its exact new native group before the
	// final fixture deletes the second Bridge. No fake native Ready is supplied.
	cfg.Source++
	cfg.Serial++
	cfg.Enabled = false
	policy.Authority, _, err = policy.Authority.GrantDNSInstance(c, networks, "admin", ref.Generation, cfg)
	if err != nil {
		t.Fatal(err)
	}
	policy.Config = cfg
	publish(policy)
	for {
		receipt, e := o.Retire(ctx, "first", "dns")
		if e == nil {
			policy.Authority, err = policy.Authority.ObserveReferenceClose(*receipt, time.Now().Unix())
			if err != nil {
				t.Fatal(err)
			}
			break
		}
		if ctx.Err() != nil {
			t.Fatal(ctx.Err(), e)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err(), e)
		case <-time.After(25 * time.Millisecond):
		}
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	if err = n.Desired(bridgeKey, 6, current.Generation, nil, 8); err != nil {
		t.Fatal(err)
	}
	if err = n.Step(ctx, bridgeKey); err != nil {
		t.Fatal(err)
	}
	if gone, err := n.Gone(ctx, bridgeKey, 6, current.Generation, bridge); err != nil || !gone {
		t.Fatal("second Bridge not gone", gone, err)
	}
	t.Log("same owner DB: positive original native/lifetime/address/CIDR closure -> fresh logical and native Bridge generation -> new DNS lifetime/socket publication -> exact second retirement and Bridge return")
	return o, policy
}
