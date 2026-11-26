// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/network/services"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/moby/moby/client"
	"github.com/vishvananda/netlink"
)

// This is an explicit guest input, not proof of host KVM acceleration. The
// final run must retain the host's actual QMP/VM/disk and rollback evidence.
type kernelRouteGuest struct {
	Schema                       uint8
	GuestID, MachineID, BootUUID string
}

type kernelRouteInput struct {
	Schema                       uint8
	GuestID, MachineID, Owner    string
	Boot                         [32]byte
	Reference                    services.ReferenceConsumer
	Prepared                     routeOwnerRecord
	Bridge                       network.BridgeSpec
	Protection                   network.IsolationSpec
	Catalog, Networks, Authority json.RawMessage
	Before                       json.RawMessage
	DNS                          kernelDNSPlan
}

type kernelRouteReady struct {
	Schema       uint8
	InputDigest  [32]byte
	Record       routeOwnerRecord
	BridgeID     string
	NativeBefore json.RawMessage
	DNS          kernelDNSReady
}

type kernelRouteAdmission struct {
	Schema      uint8
	InputDigest [32]byte
}

// Run only inside the explicitly owned persistent guest. prepare deliberately
// stays live until a HOST-initiated kernel reset; it is not a passing test.
// verify consumes the original disk, actual boot difference and product
// retirement. Policy/current grant is model input, not a Raft/CLI/peer claim.
func TestRealBoundaryRouteKernelReboot(t *testing.T) {
	phase, root := os.Getenv("MYDC_E3_KERNEL_PHASE"), os.Getenv("MYDC_E3_KERNEL_ROOT")
	if phase == "" {
		t.Skip("explicit owned guest prepare/reset/verify with persistent disk required")
	}
	if phase != "prepare" && phase != "verify" && phase != "rollback" {
		t.Fatal("unknown kernel fixture phase")
	}
	authorityPath := os.Getenv("MYDC_E3_KERNEL_AUTHORITY")
	checkKernelRoutePrivate(t, authorityPath, false)
	authorityRaw, err := os.ReadFile(authorityPath)
	var guest kernelRouteGuest
	if err != nil || len(authorityRaw) > 4096 || json.Unmarshal(authorityRaw, &guest) != nil {
		t.Fatal("invalid explicit guest authority input", err)
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		t.Fatal(err)
	}
	uuid, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || guest.Schema != 1 || guest.GuestID == "" || len(guest.GuestID) > 63 || guest.MachineID != strings.TrimSpace(string(machine)) || guest.MachineID == "" || guest.BootUUID != strings.TrimSpace(string(uuid)) || os.Geteuid() != 0 || root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		t.Fatal("owned guest/machine/current boot/private persistent root required", err)
	}
	boot, err := services.NativeBootID()
	if err != nil {
		t.Fatal(err)
	}
	if phase == "prepare" {
		if err := os.Mkdir(root, 0700); err != nil {
			t.Fatal("prepare requires a fresh persistent root", err)
		}
	}
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root {
		t.Fatal("persistent root must not traverse symlinks", err)
	}
	checkKernelRoutePrivate(t, root, true)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	inputPath := filepath.Join(root, "input.json")
	var input kernelRouteInput
	var ready kernelRouteReady
	var inputDigest [32]byte
	var key ed25519.PrivateKey
	var upstream *net.UDPConn
	if phase == "prepare" {
		key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{161}, 32)) // Explicit fixture policy key.
		cluster := sha256.Sum256([]byte("mydc-e3-kernel-route-1/" + guest.GuestID))
		owner := engine.Owner(cluster, [32]byte(key.Public().(ed25519.PublicKey)))
		source := tenancy.SourceIdentity{Kind: "bridge", Tenant: "first", Network: "lan", Node: "node-a"}
		prefix := netip.MustParsePrefix("10.61.0.0/24")
		bridge := network.BridgeSpec{Schema: 1, Network: source.MemberID(), Owner: owner, MTU: 1280, GatewayMode: network.ManagedGatewayMode,
			Pools: []network.Pool{{ID: "pool", Network: source.MemberID(), Owner: owner, Prefix: prefix, Gateway: prefix.Addr().Next(), MTU: 1280}}}
		bridgeRaw, _ := json.Marshal(bridge)
		binding := services.RouteNativeBinding{Key: source.Key(), Generation: 1, Revision: 1, Spec: sha256.Sum256(bridgeRaw)}
		ref, record, catalog, networks, authority := routeOwnerCoreFixture(t, routeOwnerFixtureNative{Cluster: cluster, Boot: boot, Binding: binding})
		record.Report = nil
		ref.Dispatch = &record.Dispatch // Model shared grant, never a native fact.
		dnsPlan, dnsAuthority, dnsUpstream := planKernelDNS(t, guest.GuestID, catalog, networks, authority, ref.Route.Source)
		authority, upstream = dnsAuthority, dnsUpstream
		device, err := network.BridgeDeviceName(owner, binding.Key, binding.Generation, binding.Spec)
		if err != nil {
			t.Fatal(err)
		}
		protection, err := network.NormalizeIsolation(network.IsolationSpec{Schema: 1, Owner: owner,
			Prefixes: []network.TenantPrefix{{Tenant: "first", Prefix: prefix}, {Tenant: "second", Prefix: netip.MustParsePrefix("10.62.0.0/24")}},
			Bridges:  []network.IsolationBridge{{Tenant: "first", Device: device, Prefixes: []netip.Prefix{prefix}, Managed: true}},
		})
		if err != nil {
			t.Fatal(err)
		}
		input = kernelRouteInput{Schema: 1, GuestID: guest.GuestID, MachineID: guest.MachineID, Owner: owner, Boot: boot, Reference: ref, Prepared: record, Bridge: bridge, Protection: protection, Before: kernelRouteSnapshot(t), DNS: dnsPlan}
		input.Catalog, err = catalog.Encode()
		if err != nil {
			t.Fatal(err)
		}
		input.Networks, err = networks.Encode()
		if err != nil {
			t.Fatal(err)
		}
		input.Authority, err = authority.Encode()
		if err != nil {
			t.Fatal(err)
		}
		writeKernelRouteFile(t, filepath.Join(root, "key.bin"), []byte(key))
		inputDigest = writeKernelRouteJSON(t, inputPath, input)
	} else {
		input = readKernelRouteFile[kernelRouteInput](t, inputPath)
		if input.Schema != 1 || input.GuestID != guest.GuestID || input.MachineID != guest.MachineID || input.Boot == ([32]byte{}) || input.Reference.Native == nil {
			t.Fatal("original kernel fixture identity/input is missing or changed")
		}
		if phase == "verify" && boot == input.Boot {
			t.Fatal("same kernel boot cannot verify physical reboot; original inputs unchanged")
		}
		raw, err := os.ReadFile(inputPath)
		if err != nil {
			t.Fatal(err)
		}
		inputDigest = sha256.Sum256(raw)
		admitted := readKernelRouteFile[kernelRouteAdmission](t, filepath.Join(root, "admitted.json"))
		if admitted.Schema != 1 || admitted.InputDigest != inputDigest {
			t.Fatal("original native admission/prestate record is missing or changed")
		}
		for _, name := range []string{"bridge.db", "observations.db"} {
			checkKernelRoutePrivate(t, filepath.Join(root, name), false)
		}
		checkKernelRoutePrivate(t, filepath.Join(root, "key.bin"), false)
		key, err = os.ReadFile(filepath.Join(root, "key.bin"))
		if err != nil || len(key) != ed25519.PrivateKeySize || [32]byte(key.Public().(ed25519.PublicKey)) != input.Reference.Local.Owner || engine.Owner(input.Reference.Local.Cluster, input.Reference.Local.Owner) != input.Owner {
			t.Fatal("original stored guest owner key is missing or changed", err)
		}
		if phase == "verify" || boot != input.Boot {
			ready = readKernelRouteFile[kernelRouteReady](t, filepath.Join(root, "ready.json"))
			if ready.Schema != 1 || ready.InputDigest != inputDigest || !ready.Record.NativeStarted || ready.Record.NativeBoot != input.Boot {
				t.Fatal("original pre-reset ready checkpoint is invalid")
			}
		}
		if phase == "verify" {
			for _, name := range []string{"dns.db", "dns.db.owner", "dns-workload.db", "dns-client.json"} {
				checkKernelRoutePrivate(t, filepath.Join(root, name), false)
			}
			if ready.DNS.Status.Queries != 1 || ready.DNS.Status.Settings.Users != 1 || ready.DNS.DBDigest == ([32]byte{}) || ready.DNS.ClientDigest == ([32]byte{}) || kernelFileDigest(t, filepath.Join(root, "dns-client.json")) != ready.DNS.ClientDigest || kernelFileDigest(t, filepath.Join(root, "dns.db")) != ready.DNS.DBDigest {
				t.Fatal("original unfinished DNS query did not span this reset; do not reopen or recreate its DB")
			}
			for _, name := range []string{"rollback.json", "complete.json"} {
				if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refuse to repeat a rolled-back/completed kernel scenario", name, err)
				}
			}
		}
	}
	defer clear(key)
	c, err := engine.Open(ctx, "unix:///var/run/docker.sock", input.Owner)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m, err := network.OpenManagerWithAdmission(filepath.Join(root, "bridge.db"), c, func(_ context.Context, source string, _ reconcile.Desired) (network.ConsumerBudget, error) {
		if source != input.Reference.Native.Key {
			return network.ConsumerBudget{}, network.ErrPolicy
		}
		return network.ConsumerBudget{Scope: reconcile.ConsumerScope{Tenant: "first", Node: "node-a", Owner: input.Owner}, NodeMaxConsumers: 3, TenantMaxConsumers: 3}, nil
	}, func(ctx context.Context, source string, target reconcile.Resource) error {
		if !network.IsolationCoversBridge(input.Protection, source, target) {
			return network.ErrPolicy
		}
		present, err := network.InspectIsolation(input.Protection)
		if err != nil || !present {
			return errors.Join(err, network.ErrKernelOwnership)
		}
		return ctx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	db, err := storage.Open(filepath.Join(root, "observations.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	driver := &network.TunnelDriver{Owner: input.Owner}
	defer driver.Close()
	r := &Runtime{owner: input.Owner, reports: db, network: m, routeDriver: driver, Identity: &identity.Identity{Private: key, Public: input.Reference.Local.Owner}}
	r.tunnel = &tunnelRuntime{r: r}
	dnsRuntime := newKernelDNS(t, root, input, c, m, key)
	defer dnsRuntime.close()
	productDone := false
	currentProtection := false
	cleanupEnabled := phase != "prepare"
	// A reset does not run this callback. Timeout/failure and the explicit
	// rollback phase do; forced fixture cleanup is never product completion.
	defer func() {
		if productDone || !cleanupEnabled {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		dnsErr := dnsRuntime.finish(cleanup)
		resource, err := originalRouteResource(input.Reference, input.Prepared)
		if err == nil && boot != input.Boot {
			absent, readErr := driver.RouteAbsent(cleanup, input.Reference.RouteNativeKey(), resource)
			if readErr != nil || !absent {
				err = errors.Join(readErr, errors.New("preserve conflicting current-kernel route native"))
			}
		} else if err == nil {
			err = driver.QuiesceRoute(cleanup, input.Reference.RouteNativeKey(), resource)
			if err == nil {
				outcome, removeErr := driver.Execute(cleanup, input.Reference.RouteNativeKey(), reconcile.Operation{Kind: reconcile.Remove, Target: resource})
				if removeErr != nil || outcome != reconcile.EffectApplied {
					err = errors.Join(removeErr, errors.New("original route fixture native removal remains unknown"))
				}
			}
		}
		if err == nil {
			err = m.ReturnConsumer(input.Reference.Native.Key, input.Reference.RouteNativeKey(), input.Reference.Native.Generation)
		}
		if err == nil && dnsErr != nil {
			err = dnsErr
		}
		if err == nil {
			row, readErr := m.View(input.Reference.Native.Key)
			if readErr != nil || len(row.Consumers) != 0 {
				err = errors.Join(readErr, errors.New("preserve original Bridge while DNS/client consumers remain"))
			}
		}
		if err == nil {
			bridgeRaw, _ := json.Marshal(input.Bridge)
			original := reconcile.Resource{Present: true, Generation: input.Reference.Native.Generation, Spec: string(bridgeRaw)}
			if boot != input.Boot {
				id, identityErr := c.Identity("bridge", input.Reference.Native.Key, original)
				if identityErr != nil {
					err = identityErr
				} else {
					got, readErr := c.API.NetworkInspect(cleanup, id.Name, client.NetworkInspectOptions{})
					if readErr != nil && !cerrdefs.IsNotFound(readErr) {
						err = readErr
					} else if readErr == nil && (ready.BridgeID == "" || got.Network.ID != ready.BridgeID) {
						err = errors.New("preserve replacement current-kernel Engine network")
					}
				}
			}
			if err == nil {
				outcome, removeErr := (&network.BridgeDriver{Engine: c}).Execute(cleanup, input.Reference.Native.Key, reconcile.Operation{Kind: reconcile.Remove, Target: original})
				if removeErr != nil || outcome != reconcile.EffectApplied {
					err = errors.Join(removeErr, errors.New("original fixture Bridge removal remains unknown"))
				}
			}
		}
		if err == nil {
			if exists, readErr := network.IsolationExists(input.Owner); readErr != nil {
				err = readErr
			} else if exists {
				if boot != input.Boot && !currentProtection {
					err = errors.New("preserve current-kernel isolation table after reboot")
				} else {
					err = network.RemoveIsolation(cleanup, input.Protection)
				}
			}
		}
		message := ""
		if err != nil {
			message = err.Error()
			t.Error("kernel fixture exact rollback incomplete; retain root and guest", err)
		}
		writeKernelRouteJSON(t, filepath.Join(root, "rollback.json"), map[string]any{"Schema": 1, "ProductCompleted": false, "Error": message, "After": kernelRouteSnapshot(t)})
	}()
	if phase == "rollback" {
		if err := dnsRuntime.reopenRollback(t); err != nil {
			t.Fatal("original DNS rollback recovery", err)
		}
		return
	}
	if phase == "prepare" {
		rows, err := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.mydc.owner="+input.Owner)})
		if err != nil || len(rows.Items) != 0 {
			t.Fatal("kernel fixture owner must initially have no Engine networks", err)
		}
		if exists, err := network.IsolationExists(input.Owner); err != nil || exists {
			t.Fatal("kernel fixture owner isolation must initially be absent", err)
		}
		if _, err := netlink.LinkByName(input.Protection.Bridges[0].Device); err == nil {
			t.Fatal("kernel fixture must not adopt an existing Bridge device")
		} else {
			var missing netlink.LinkNotFoundError
			if !errors.As(err, &missing) {
				t.Fatal("kernel fixture Bridge prestate is unknown", err)
			}
		}
		resource, err := originalRouteResource(input.Reference, input.Prepared)
		if err != nil {
			t.Fatal(err)
		}
		if absent, err := driver.RouteAbsent(ctx, input.Reference.RouteNativeKey(), resource); err != nil || !absent {
			t.Fatal("kernel fixture native identities must initially be absent", err)
		}
		writeKernelRouteJSON(t, filepath.Join(root, "admitted.json"), kernelRouteAdmission{Schema: 1, InputDigest: inputDigest})
		cleanupEnabled = true
		if err := r.saveRouteOwner(input.Prepared, input.Reference); err != nil {
			t.Fatal(err)
		}
		if err := network.ApplyIsolation(ctx, nil, input.Protection, true); err != nil {
			t.Fatal(err)
		}
		if err := m.Desired(input.Reference.Native.Key, 1, 1, &input.Bridge, 3); err != nil {
			t.Fatal(err)
		}
		if err := m.Step(ctx, input.Reference.Native.Key); err != nil {
			t.Fatal(err)
		}
		record := input.Prepared
		core, err := services.DecodeRouteRuntime(record.Core)
		if err != nil {
			t.Fatal(err)
		}
		core, err = core.Dispatch(1)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.saveRouteCore(&record, input.Reference, core); err != nil {
			t.Fatal(err)
		}
		if err := r.acquireRouteBridge(ctx, input.Reference, &record); err != nil {
			t.Fatal(err)
		}
		if err := r.runRouteDriver(ctx, input.Reference, &record, core, *core.Journal().Pending, driver, true, false); err != nil {
			t.Fatal("actual original route native execution", err)
		}
		id, err := m.Inspect(ctx, input.Reference.Native.Key)
		if err != nil {
			t.Fatal(err)
		}
		dnsReady := dnsRuntime.prepare(t, ctx, upstream)
		writeKernelRouteJSON(t, filepath.Join(root, "ready.json"), kernelRouteReady{Schema: 1, InputDigest: inputDigest, Record: record, BridgeID: id, NativeBefore: kernelRouteSnapshot(t), DNS: dnsReady})
		t.Log("prepared actual route/TUN/Bridge journals; awaiting host kernel reset, not test success")
		// No graceful daemon restart substitutes for this kernel boundary.
		select {
		case <-t.Context().Done():
		case <-time.After(15 * time.Minute):
		}
		t.Fatal("host did not reset this owned guest within the prepared reboot window")
	}
	record, found, err := r.loadRouteOwner(input.Reference)
	want, _ := json.Marshal(ready.Record)
	got, _ := json.Marshal(record)
	if err != nil || !found || !bytes.Equal(want, got) {
		t.Fatal("reset changed or lost the original private route checkpoint", err)
	}
	lease, err := m.InspectConsumer(ctx, input.Reference.Native.Key, input.Reference.RouteNativeKey(), input.Reference.Native.Generation)
	if err != nil || lease.Pin != ready.Record.Bridge || lease.NetworkID != ready.BridgeID {
		t.Fatal("same persistent Engine/Bridge journal did not preserve original ID/pin", err)
	}
	if exists, err := network.IsolationExists(input.Owner); err != nil || exists {
		t.Fatal("old isolation must be absent before current-boot protection", err)
	}
	if err := network.ApplyIsolation(ctx, nil, input.Protection, true); err != nil {
		t.Fatal(err)
	}
	currentProtection = true
	dnsRuntime.resume(t, ctx, ready.DNS, boot)
	catalog, err := access.Decode(input.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	networks, err := tenancy.Decode(input.Networks)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := services.DecodeAuthority(ready.DNS.Authority)
	if err != nil {
		t.Fatal(err)
	}
	policy, _ := networks.Route("first", "database")
	networks, err = networks.Withdraw(catalog, "admin", "first", "database", "first", policy.Revision)
	if err != nil {
		t.Fatal(err)
	}
	core, err := services.DecodeRouteRuntime(record.Core)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.Sync(catalog, networks, authority)
	if err != nil {
		t.Fatal(err)
	}
	core, err = core.ResumeBoot(boot)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.saveRouteCore(&record, input.Reference, core); err != nil {
		t.Fatal(err)
	}
	core, err = r.retirePreviousBootRoute(ctx, input.Reference, &record, core, boot, driver)
	if err != nil {
		t.Fatal("actual previous kernel native retirement", err)
	}
	if err := r.returnRouteBridge(input.Reference, &record, core); err != nil {
		t.Fatal(err)
	}
	if record.NativeBoot != input.Boot || !record.BridgeReturned || record.Nonce != ready.Record.Nonce || !sameRouteDispatch(record.Dispatch, ready.Record.Dispatch) {
		t.Fatal("kernel retirement replaced original provenance or lost Bridge return")
	}
	if err := m.Desired(input.Reference.Native.Key, 2, 1, nil, 3); err != nil {
		t.Fatal(err)
	}
	if err := m.Step(ctx, input.Reference.Native.Key); !errors.Is(err, reconcile.ErrLease) {
		t.Fatal("route return removed Bridge still borrowed by DNS/client", err)
	}
	if err := dnsRuntime.finish(ctx); err != nil {
		t.Fatal("original DNS/client/TTL retirement", err)
	}
	if err := m.Step(ctx, input.Reference.Native.Key); err != nil {
		t.Fatal(err)
	}
	if gone, err := m.Gone(ctx, input.Reference.Native.Key, 2, 1, input.Bridge); err != nil || !gone {
		t.Fatal("original Bridge is not actually Gone", err)
	}
	if err := network.RemoveIsolation(ctx, input.Protection); err != nil {
		t.Fatal(err)
	}
	currentProtection = false
	if exists, err := network.IsolationExists(input.Owner); err != nil || exists {
		t.Fatal("current-boot protection not Gone after all original consumers", err)
	}
	rows, err := c.API.NetworkList(ctx, client.NetworkListOptions{Filters: client.Filters{}.Add("label", "org.mydc.owner="+input.Owner)})
	if err != nil || len(rows.Items) != 0 {
		t.Fatal("kernel fixture retains original Engine networks", err)
	}
	writeKernelRouteJSON(t, filepath.Join(root, "complete.json"), map[string]any{"Schema": 1, "BootBefore": input.Boot, "BootAfter": boot, "Record": record, "DNSClosed": dnsRuntime.claim, "BridgeGone": true, "After": kernelRouteSnapshot(t), "Scope": "actual local kernel/TUN/DNS queries/SDK/DB/Bridge pin; policy/grant and client SDK restart are fixture input; not CLI/Raft/peer/product restart/KVM2"})
	productDone = true
}

func checkKernelRoutePrivate(t *testing.T, path string, directory bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0077 != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		t.Fatal("kernel fixture requires root-owned private regular files/directories", path)
	}
}

func readKernelRouteFile[T any](t *testing.T, path string) T {
	t.Helper()
	checkKernelRoutePrivate(t, path, false)
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 8<<20 {
		t.Fatal("kernel fixture bounded input", err)
	}
	value, err := schema.Decode[T](raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func writeKernelRouteJSON(t *testing.T, path string, value any) [32]byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	writeKernelRouteFile(t, path, raw)
	return sha256.Sum256(raw)
}

func writeKernelRouteFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("do not replace original kernel fixture input/evidence", err)
	}
	_, writeErr := f.Write(raw)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		t.Fatal(err)
	}
}

func kernelRouteSnapshot(t *testing.T) json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	rows := map[string]json.RawMessage{}
	for name, args := range map[string][]string{"link": {"ip", "-j", "link"}, "addr": {"ip", "-j", "addr"}, "rules": {"ip", "-j", "-4", "rule"}, "routes": {"ip", "-j", "-4", "route", "show", "table", "all"}, "nft": {"nft", "-j", "list", "ruleset"}} {
		raw, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatal("guest native snapshot", name, err, string(raw))
		}
		rows[name] = raw
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
