// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

// Actual SDK/kernel/journal migration input inside the existing private Engine.
// Policy admission is a model here; the real management drain/fence/current
// grant is covered by verifyManagedTUNReconfiguration, not fabricated below.
func verifyLegacyBridgeGatewayNative(t *testing.T, ctx context.Context, root, socket, manifest string) {
	t.Helper()
	host, tag := os.Getenv("MYDC_KERNEL_HOST_NETNS"), os.Getenv("MYDC_KERNEL_TEST_OWNER")
	current, err := os.Readlink("/proc/self/ns/net")
	relative, relativeErr := filepath.Rel(root, socket)
	if err != nil || relativeErr != nil || host == "" || tag == "" || current == host || os.Geteuid() != 0 || !filepath.IsAbs(root) || !filepath.IsAbs(socket) || !filepath.IsLocal(relative) || socket == "/var/run/docker.sock" || socket == "/run/docker.sock" {
		t.Fatal("legacy adapter requires the original owned namespace and private Engine", err)
	}
	owner := engine.Owner(sha256.Sum256([]byte(tag+"/legacy-cluster")), sha256.Sum256([]byte(tag+"/legacy-node")))
	c, err := engine.Open(ctx, "unix://"+socket, owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	key := "bridge/legacy-gateway"
	prefix := netip.MustParsePrefix("198.19.80.240/28")
	pool := network.Pool{ID: "pool", Network: "legacy-gateway", Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}
	legacy := network.BridgeSpec{Schema: 1, Network: pool.Network, Owner: owner, MTU: 1280, Pools: []network.Pool{pool}, Internal: true}
	managed := legacy
	managed.Internal, managed.GatewayMode = false, network.ManagedGatewayMode
	legacyRaw, _ := json.Marshal(legacy)
	managedRaw, _ := json.Marshal(managed)
	resources := []reconcile.Resource{
		{Present: true, Generation: 1, Spec: string(legacyRaw)},
		{Present: true, Generation: 2, Spec: string(managedRaw)},
		{Present: true, Generation: 3, Spec: string(managedRaw)},
	}
	var identities []engine.Identity
	var devices []string
	for _, resource := range resources {
		id, err := c.Identity("bridge", key, resource)
		if err != nil {
			t.Fatal(err)
		}
		device, err := network.BridgeDeviceName(owner, key, resource.Generation, sha256.Sum256([]byte(resource.Spec)))
		if err != nil {
			t.Fatal(err)
		}
		identities, devices = append(identities, id), append(devices, device)
	}
	protection, err := network.NormalizeIsolation(network.IsolationSpec{Schema: 1, Owner: owner,
		Prefixes: []network.TenantPrefix{{Tenant: "legacy-adapter", Prefix: prefix}},
		Bridges:  []network.IsolationBridge{{Tenant: "legacy-adapter", Device: devices[2], Prefixes: []netip.Prefix{prefix}, Managed: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "legacy-gateway.db")
	input, err := os.ReadFile(manifest)
	var evidence map[string]any
	if err != nil || json.Unmarshal(input, &evidence) != nil || evidence == nil {
		t.Fatal("original public fixture manifest", err)
	}
	foreignAlias := "mydc-legacy-kernel-conflict-" + devices[0]
	evidence["legacy_gateway"] = map[string]any{"owner": owner, "key": key, "socket": socket, "journal": path, "resources": resources, "identities": identities, "devices": devices, "protection": protection, "admission": "model; actual SDK/kernel/journal only", "kernel_conflict": map[string]any{"device": devices[0], "alias": foreignAlias, "type": "bridge", "mtu": 1500}}
	input, err = json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, input, 0644); err != nil {
		t.Fatal(err)
	}
	listOwned := func(ctx context.Context) (int, error) {
		rows, err := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.mydc.owner="+owner)})
		return len(rows.Items), err
	}
	if count, err := listOwned(ctx); err != nil || count != 0 {
		t.Fatal("legacy fixture owner must initially have no networks", count, err)
	}
	if exists, err := network.IsolationExists(owner); err != nil || exists {
		t.Fatal("legacy fixture protection table must initially be absent", err)
	}
	for i, id := range identities {
		if _, err := c.API.NetworkInspect(ctx, id.Name, client.NetworkInspectOptions{}); !cerrdefs.IsNotFound(err) {
			t.Fatal("refuse existing native name", id.Name, err)
		}
		if _, err := netlink.LinkByName(devices[i]); !isLegacyBridgeAbsent(err) {
			t.Fatal("refuse existing native device", devices[i], err)
		}
	}
	var manager *network.Manager
	driver := &network.BridgeDriver{Engine: c}
	rolledBack := false
	rollback := func() {
		if rolledBack {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		gone := true
		for i := len(resources) - 1; i >= 0; i-- {
			outcome, err := driver.Execute(cleanup, key, reconcile.Operation{Kind: reconcile.Remove, Target: resources[i]})
			if err != nil || outcome != reconcile.EffectApplied {
				t.Error("exact legacy gateway rollback", resources[i].Generation, outcome, err)
				gone = false
			}
		}
		if gone {
			if exists, err := network.IsolationExists(owner); err != nil {
				t.Error("legacy gateway rollback table readback", err)
				gone = false
			} else if exists {
				if err := network.RemoveIsolation(cleanup, protection); err != nil {
					t.Error("exact legacy gateway protection rollback", err)
					gone = false
				}
			}
		}
		if count, err := listOwned(cleanup); err != nil || count != 0 {
			t.Error("legacy gateway owner baseline not restored", count, err)
			gone = false
		}
		for _, device := range devices {
			if _, err := netlink.LinkByName(device); !isLegacyBridgeAbsent(err) {
				t.Error("legacy gateway device baseline not restored", device, err)
				gone = false
			}
		}
		if exists, err := network.IsolationExists(owner); err != nil || exists {
			t.Error("legacy gateway protection baseline not restored", exists, err)
			gone = false
		}
		if manager != nil {
			if err := manager.Close(); err != nil {
				t.Error("legacy gateway journal close", err)
				gone = false
			}
			manager = nil
		}
		rolledBack = gone
	}
	t.Cleanup(rollback) // Installed before journal creation or any SDK/native effect.
	guards := 0
	open := func() {
		t.Helper()
		manager, err = network.OpenManagerWithAdmission(path, c, func(_ context.Context, actual string, _ reconcile.Desired) (network.ConsumerBudget, error) {
			if actual != key {
				return network.ConsumerBudget{}, network.ErrPolicy
			}
			return network.ConsumerBudget{Scope: reconcile.ConsumerScope{Tenant: "legacy-adapter", Node: "node-a", Owner: owner}, NodeMaxConsumers: 2, TenantMaxConsumers: 2}, nil
		}, func(ctx context.Context, actual string, target reconcile.Resource) error {
			guards++
			if actual != key || target != resources[2] || !network.IsolationCoversBridge(protection, key, target) {
				return network.ErrPolicy
			}
			present, err := network.InspectIsolation(protection)
			if err != nil || !present {
				return errors.Join(err, network.ErrKernelOwnership)
			}
			return ctx.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	open()
	if err := manager.Desired(key, 1, 1, &legacy, 2); err != nil {
		t.Fatal(err)
	}
	foreignAttempted := false
	foreignIndex := 0
	foreignMarked := false
	removeForeign := func() {
		if !foreignAttempted {
			return
		}
		link, err := netlink.LinkByName(devices[0])
		if isLegacyBridgeAbsent(err) {
			foreignAttempted = false
			return
		}
		if err != nil || link.Type() != "bridge" || foreignIndex == 0 || link.Attrs().Index != foreignIndex || (link.Attrs().Alias != foreignAlias && (foreignMarked || link.Attrs().Alias != "")) {
			t.Error("preserve changed kernel conflict marker", err)
			return
		}
		if err := netlink.LinkDel(link); err != nil {
			t.Error("exact kernel conflict marker rollback", err)
			return
		}
		foreignAttempted = false
	}
	t.Cleanup(removeForeign) // Runs before the already registered native rollback.
	foreignAttempted = true  // Even a lost LinkAdd ACK needs this exact read-back.
	if err := netlink.LinkAdd(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: devices[0], MTU: 1500}}); err != nil {
		t.Fatal(err)
	}
	foreign, err := netlink.LinkByName(devices[0])
	if err != nil || foreign.Type() != "bridge" || foreign.Attrs().Alias != "" || foreign.Attrs().MTU != 1500 {
		t.Fatal("initial kernel conflict Bridge read-back", err)
	}
	foreignIndex = foreign.Attrs().Index
	// The creation ACK does not guarantee that an initial Alias was installed.
	// Set it explicitly and bind cleanup to this positively observed ifindex.
	if err := netlink.LinkSetAlias(foreign, foreignAlias); err != nil {
		t.Fatal("mark original kernel conflict Bridge", err)
	}
	foreign, err = netlink.LinkByName(devices[0])
	if err != nil || foreign.Attrs().Index != foreignIndex || foreign.Attrs().Alias != foreignAlias {
		t.Fatal("kernel conflict marker read-back", err)
	}
	foreignMarked = true
	foreignSnapshot := func() []byte {
		t.Helper()
		link, err := netlink.LinkByName(devices[0])
		if err != nil {
			t.Fatal(err)
		}
		addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"index": link.Attrs().Index, "type": link.Type(), "alias": link.Attrs().Alias, "mtu": link.Attrs().MTU, "mac": link.Attrs().HardwareAddr.String(), "flags": link.Attrs().Flags, "addresses": addresses})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	foreignBefore := foreignSnapshot()
	if err := manager.Step(ctx, key); !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("first SDK create adopted an existing kernel bridge", err)
	}
	if _, err := c.API.NetworkInspect(ctx, identities[0].Name, client.NetworkInspectOptions{}); !cerrdefs.IsNotFound(err) {
		t.Fatal("refused kernel collision created an Engine network", err)
	}
	foreignAfter := foreignSnapshot()
	if !bytes.Equal(foreignBefore, foreignAfter) {
		t.Fatal("first create preflight modified foreign kernel bridge", string(foreignBefore), string(foreignAfter))
	}
	evidence["legacy_kernel_conflict_before"], evidence["legacy_kernel_conflict_after"] = json.RawMessage(foreignBefore), json.RawMessage(foreignAfter)
	rawEvidence, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, rawEvidence, 0644); err != nil {
		t.Fatal(err)
	}
	removeForeign()
	if foreignAttempted {
		t.Fatal("kernel conflict marker is not Gone")
	}
	if err := manager.Step(ctx, key); err != nil {
		t.Fatal("actual legacy SDK create", err)
	}
	originalID, err := manager.Inspect(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	originalJournal, err := manager.View(key)
	if err != nil || originalJournal.State.Pending != nil || originalJournal.State.Applied != resources[0] || originalJournal.State.LastID != 2 {
		t.Fatal("refused SDK call was not positively unsent before actual original creation", err)
	}
	lease, err := manager.Acquire(ctx, key, "original-consumer", 1)
	if err != nil || lease.NetworkID != originalID {
		t.Fatal("actual original Bridge pin/readback", err)
	}
	changed := resources[0]
	changed.Spec = string(managedRaw)
	if outcome, err := driver.Recover(ctx, key, reconcile.Operation{Kind: reconcile.Apply, Target: changed}); outcome != reconcile.EffectUnknown || !errors.Is(err, engine.ErrOwnership) {
		t.Fatal("same-generation mode substitution adopted legacy native", outcome, err)
	}
	if err := manager.Desired(key, 2, 2, &managed, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) || guards != 0 {
		t.Fatal("live original pin allowed native replacement", err, guards)
	}
	blocked, err := manager.View(key)
	if err != nil || blocked.State.Pending != nil || blocked.State.Applied != resources[0] || blocked.State.LastID != originalJournal.State.LastID || blocked.Pins == nil || !blocked.Pins.Draining || len(blocked.Pins.Active) != 1 || blocked.Pins.Active[0] != lease.Pin {
		t.Fatal("replacement did not durably drain the exact original pin before dispatch", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager = nil
	open()
	restored, err := manager.InspectConsumer(ctx, key, lease.Consumer, 1)
	view, viewErr := manager.View(key)
	if err != nil || viewErr != nil || restored.Pin != lease.Pin || restored.NetworkID != originalID || !restored.Spec.Internal || restored.Spec.GatewayMode != "" || view.State.Applied != resources[0] || view.State.Pending != nil || view.State.LastID != originalJournal.State.LastID {
		t.Fatal("same DB lost original native/spec/pin while replacement was blocked", err, viewErr)
	}
	if _, err := manager.Acquire(ctx, key, "new-consumer", 2); err == nil {
		t.Fatal("new generation acquired the old native")
	}
	if err := manager.Desired(key, 3, 2, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); !errors.Is(err, reconcile.ErrPending) {
		t.Fatal("drain bypassed the original pin", err)
	}
	if err := manager.Return(lease); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); err != nil {
		t.Fatal("actual original Bridge removal", err)
	}
	if outcome, err := driver.Inspect(ctx, key, reconcile.Operation{Kind: reconcile.Remove, Target: resources[0]}); outcome != reconcile.EffectApplied || err != nil {
		t.Fatal("original native was not actually Gone before replacement", outcome, err)
	}
	if err := network.ApplyIsolation(ctx, nil, protection, true); err != nil {
		t.Fatal("install exact protection before managed native create", err)
	}
	if err := manager.Desired(key, 4, 3, &managed, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); err != nil {
		t.Fatal("actual protected managed SDK create", err)
	}
	newID, err := manager.Inspect(ctx, key)
	native, nativeErr := c.API.NetworkInspect(ctx, identities[2].Name, client.NetworkInspectOptions{})
	if err != nil || nativeErr != nil || newID == originalID || native.Network.ID != newID || native.Network.Internal || native.Network.Options["com.docker.network.bridge.gateway_mode_ipv4"] != network.ManagedGatewayMode || native.Network.Options["com.docker.network.bridge.enable_ip_masquerade"] != "false" || guards != 1 {
		t.Fatal("managed native readback did not match explicit new generation/options", err, nativeErr, guards)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager = nil
	open()
	if id, err := manager.Inspect(ctx, key); err != nil || id != newID || guards != 1 {
		t.Fatal("managed DB reopen replaced original native", id, err, guards)
	}
	if err := manager.Desired(key, 5, 3, nil, 2); err != nil {
		t.Fatal(err)
	}
	if err := manager.Step(ctx, key); err != nil {
		t.Fatal(err)
	}
	if gone, err := manager.Gone(ctx, key, 5, 3, managed); err != nil || !gone {
		t.Fatal("managed terminal journal/native is not Gone", err)
	}
	rollback()
	if !rolledBack {
		t.Fatal("legacy gateway adapter rollback incomplete")
	}
	t.Logf("legacy SDK/journal transition: owner=%s key=%s original=%s managed=%s pin=%+v; no quorum/reboot claim", owner, key, originalID, newID, lease.Pin)
}

func isLegacyBridgeAbsent(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing)
}
