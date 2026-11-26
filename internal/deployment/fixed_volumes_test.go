// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/network"
	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/tenancy"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

// Signed identities here are simulated inputs to the real planning/Binding
// core. They prove no actual ext4 registration, Docker mount or Raft commit.
func fixedAppFixture(t *testing.T) (*fixture, Compose, PlanningContext, volumes.NativeReady) {
	t.Helper()
	f := makeFixture(t)
	input := smallCompose(t)
	keep := true
	input.Volumes["mysql-data"] = ComposeVolume{Name: "registered-data", External: true, MyDC: VolumeExtension{Driver: "local", Access: "single-writer", Retain: &keep, Quota: "observe"}}
	scope := volumes.Scope{Cluster: f.cluster, Tenant: "tenant", ID: "registered-data", Generation: 3}
	rootRef := nodestorage.Reference{Cluster: f.cluster, Node: "node-b", Key: public(f.nb), ID: "disk", Generation: 2, Path: "/owned-test-disk"}
	directory := nodestorage.Directory{Filesystem: "ext4", FilesystemPath: "/", UUID: [16]byte{1}, HandleType: 1, Handle: bytes.Repeat([]byte{2}, 8), Inode: 2, DeviceMajor: 8, DeviceMinor: 1, Boot: [32]byte{3}, Namespace: [32]byte{4}, MountID: 5}
	root := nodestorage.RootFact{Schema: 1, Root: rootRef, Directory: directory}
	root.Signature = ed25519.Sign(f.nb, nodestorage.RootFactBytes(root))
	directory.FilesystemPath, directory.Inode, directory.Handle = "/data", 3, bytes.Repeat([]byte{3}, 8)
	fixed := nodestorage.FixedDirectory{Root: root, RootDirectory: root.Directory, Path: rootRef.Path + "/data", Directory: directory}
	selection := fixed.Selection().Digest()
	spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-b", NodeKey: public(f.nb), Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(selection[:])}
	ready := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 3, Owner: volumes.Owner{Node: "node-b", Key: public(f.nb), Native: volumes.FixedNativeName(scope)}, Fixed: &fixed}
	ready.Signature = ed25519.Sign(f.nb, volumes.NativeReadyBytes(ready))
	if err := ready.Verify(); err != nil {
		t.Fatal("invalid simulated original native fact", err)
	}
	core, err := volumes.NewFixed(f.c, "alice", scope, ready.Owner, 4)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.v, "tenant/php-mysql/mysql-data")
	f.v[scope.Key()] = core
	ctx := contextFor(t, f)
	ctx.FixedVolumes = map[string]volumes.NativeReady{scope.Key(): ready}
	ctx.Features["fixed-volumes"] = true
	return f, input, ctx, ready
}

func TestFixedAppBorrowsOriginalRegistrationThroughExistingBindingAndTaskRecipe(t *testing.T) {
	f, input, ctx, ready := fixedAppFixture(t)
	b, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range b.ReleaseOrder() {
		if step.Kind == "volume" || step.Key == volumes.NativeKey(ready.Spec) {
			t.Fatal("borrowed fixed data became app-owned", step.Key)
		}
	}
	raw, err := b.Encode()
	if err != nil || bytes.Contains(raw, []byte("/owned-test-disk")) {
		t.Fatal("host path leaked into app artifact", err)
	}
	decoded, err := DecodeBlueprint(raw)
	if err != nil || decoded.ValidateCurrent(f.c, ctx) != nil {
		t.Fatal("fixed plan roundtrip/current validation", err)
	}
	needs, err := b.Inputs("db", "database", 11, public(private(30)))
	if err != nil || len(needs.Volumes) != 1 || needs.Volumes[0].Key != ready.Spec.Scope.Key() || !needs.FixedVolumes[ready.Spec.Scope.Key()].Matches(ready) {
		t.Fatal("alias did not resolve tenant registration", err)
	}
	f.approveAll(needs)
	bound := f.reserve(needs).Bindings[0]
	if bound.Pins()[0].Scope != ready.Spec.Scope || !f.v[ready.Spec.Scope.Key()].Fixed() {
		t.Fatal("shared pin changed the original scope")
	}
	copy := bound.Needs()
	ref := copy.FixedVolumes[ready.Spec.Scope.Key()]
	ref.Native[0] ^= 1
	copy.FixedVolumes[ready.Spec.Scope.Key()] = ref
	if bound.Needs().FixedVolumes[ready.Spec.Scope.Key()] == ref {
		t.Fatal("caller mutated original Binding import")
	}
	encoded, err := bound.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := DecodeBinding(encoded); err != nil || restored.Digest() != bound.Digest() {
		t.Fatal("original Binding encoding", err)
	}
	netID := PoolID("tenant", "php-mysql", "app", "node-b")
	owner := engine.Owner(f.cluster, public(f.nb))
	bridge := network.BridgeSpec{Schema: 1, Network: netID, Owner: owner, MTU: 1280, Internal: true, Pools: []network.Pool{{ID: "pool", Network: netID, Owner: owner, Prefix: netip.MustParsePrefix("10.240.20.0/24"), Gateway: netip.MustParseAddr("10.240.20.1"), MTU: 1280}}}
	projection := projectionReference(bound)
	material := TaskMaterial{Binding: bound, Projection: &projection, Volumes: []volumes.NativeReady{ready}, Network: ObjectRef{ResourceKey("bridge", "tenant", "php-mysql", "app/node-b"), 10, 10}, Bridge: bridge}
	_, task, err := b.taskRecipe("db", material, owner)
	nativeDigest := needs.FixedVolumes[ready.Spec.Scope.Key()].Native
	if err != nil || len(task.Volumes) != 1 || task.Volumes[0].Scope != ready.Spec.Scope || task.Volumes[0].NativeKey != volumes.NativeKey(ready.Spec) || task.Volumes[0].NativeBinding != hex.EncodeToString(nativeDigest[:]) {
		t.Fatal("fixed native provenance lost in Task recipe", err)
	}
	for _, step := range b.Steps() {
		if step.Key == ResourceKey("task", "tenant", "php-mysql", "db") {
			var service ComposeService
			_ = json.Unmarshal(step.Goal, &service)
			if service.CheckVolumeNeeds(bound.Needs()) != nil {
				t.Fatal("Task declaration/Binding mismatch")
			}
		}
	}
	changed := ready
	changedFixed := *ready.Fixed
	changedFixed.Directory.Inode++
	changed.Fixed = &changedFixed
	changed.Signature = ed25519.Sign(f.nb, volumes.NativeReadyBytes(changed))
	material.Volumes = []volumes.NativeReady{changed}
	if _, _, err = b.taskRecipe("db", material, owner); err == nil {
		t.Fatal("same logical name adopted different physical fact")
	}
	ctx.FixedVolumes[ready.Spec.Scope.Key()] = changed
	if b.ValidateCurrent(f.c, ctx) == nil {
		t.Fatal("old plan accepted changed native fact")
	}
	next, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, before := range b.Steps() {
		if before.Kind == "task" && before.Key == ResourceKey("task", "tenant", "php-mysql", "db") {
			for _, after := range next.Steps() {
				if after.Key == before.Key && bytes.Equal(before.Goal, after.Goal) {
					t.Fatal("source change would Keep original Task generation")
				}
			}
		}
	}
}

func TestFixedAppRejectsMissingUnpermittedRetargetedAndMutableReferences(t *testing.T) {
	for _, fault := range []string{"missing", "unpermitted", "node", "uid", "alias-writer", "generation"} {
		t.Run(fault, func(t *testing.T) {
			f, input, ctx, ready := fixedAppFixture(t)
			switch fault {
			case "missing":
				delete(ctx.Volumes, ready.Spec.Scope.Key())
			case "unpermitted":
				ctx.FixedVolumes = nil
			case "node":
				service := input.Services["db"]
				service.MyDC.Node = "node-a"
				input.Services["db"] = service
			case "uid":
				v := input.Volumes["mysql-data"]
				v.MyDC.UID = 10001
				input.Volumes["mysql-data"] = v
			case "alias-writer":
				input.Volumes["duplicate"] = input.Volumes["mysql-data"]
				service := input.Services["db"]
				service.Volumes = append(Mounts(nil), service.Volumes...)
				service.Volumes[0].Source = "duplicate"
				service.Networks = map[string]Attachment{"app": {IPv4: "10.240.20.11"}}
				input.Services["second-writer"] = service
			case "generation":
				bad := ready
				bad.Generation++
				ctx.FixedVolumes[ready.Spec.Scope.Key()] = bad
			}
			if _, err := Compile(input, f.c, ctx); err == nil {
				t.Fatal("fixed reference fault silently became create/retarget")
			} else if fault == "alias-writer" && !strings.Contains(err.Error(), "VOLUME_WRITER_CONFLICT") {
				t.Fatal("alias writer test did not reach actual source conflict", err)
			}
		})
	}
}

func TestFixedAppReadOnlyAliasesShareOneOriginalVolumeWithoutWriterBypass(t *testing.T) {
	f, input, ctx, ready := fixedAppFixture(t)
	input.Volumes["duplicate"] = input.Volumes["mysql-data"]
	service := input.Services["db"]
	service.Secrets = nil
	service.MyDC.Sources = nil
	service.Volumes = append(Mounts(nil), service.Volumes...)
	service.Volumes[0].ReadOnly = true
	input.Services["db"] = service
	other := service
	other.Volumes = append(Mounts(nil), service.Volumes...)
	other.Volumes[0].Source = "duplicate"
	other.Networks = map[string]Attachment{"app": {IPv4: "10.240.20.11"}}
	input.Services["reader"] = other
	b, err := Compile(input, f.c, ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, err := b.Inputs("db", "reader-a", 11, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	z, err := b.Inputs("reader", "reader-b", 12, public(private(30)))
	if err != nil {
		t.Fatal(err)
	}
	reserved := f.reserve(a, z)
	if len(reserved.Bindings) != 2 || len(reserved.Volumes[ready.Spec.Scope.Key()].Consumers()) != 2 || reserved.Bindings[0].Pins()[0].Scope != reserved.Bindings[1].Pins()[0].Scope {
		t.Fatal("read-only aliases created independent Volume owners")
	}
}

func TestParsedAppNamedNetworkAndFixedVolumeCreateOnlyAppConsumers(t *testing.T) {
	f, _, ctx, ready := fixedAppFixture(t)
	document := "name: php-mysql\nservices:\n  db:\n    image: docker.io/library/mysql@sha256:" + strings.Repeat("a", 64) + "\n    command: [mysqld]\n    networks: {app: {ipv4_address: 10.240.20.10}}\n    volumes: [database:/data]\n    x-mydc: {node: node-b}\nnetworks:\n  app: {name: shared-lan}\nvolumes:\n  database: {external: true, name: registered-data}\n"
	input, err := ParseApp([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	ctx.Networks, err = ctx.Networks.Create(f.c, "alice", ctx.Networks.Revision(), tenancy.Network{Tenant: "tenant", ID: "shared-lan", Node: "node-b", Owner: public(f.nb), Pools: []tenancy.Subnet{{ID: "pool", Prefix: mustPrefix("10.240.20.0/24"), Gateway: mustAddr("10.240.20.1"), MTU: 1280}}})
	if err != nil {
		t.Fatal(err)
	}
	source := ResourceKey("bridge", "tenant", "shared-app", "lan/node-b")
	owner := engine.Owner(f.cluster, public(f.nb))
	bridge := network.BridgeSpec{Schema: 1, Network: "shared-lan", Owner: owner, MTU: 1280, Pools: []network.Pool{{ID: "pool", Network: "shared-lan", Owner: owner, Prefix: mustPrefix("10.240.20.0/24"), Gateway: mustAddr("10.240.20.1"), MTU: 1280}}}
	raw, _ := json.Marshal(bridge)
	ctx.Current = map[string]state.Object{source: {Present: true, Generation: 17, Revision: 31, Value: string(raw)}}
	ctx.Features["network-reference"] = true
	before := ctx.Volumes[ready.Spec.Scope.Key()].Revision()
	b, err := CompileApp(input, f.c, ctx)
	if err != nil || b.CheckAppInput() != nil {
		t.Fatal("actual app.yaml parse/compile contract", err)
	}
	needs, err := b.Inputs("db", "database", 9, public(private(30)))
	if err != nil || !needs.FixedVolumes[ready.Spec.Scope.Key()].Matches(ready) {
		t.Fatal("named registered source not preserved", err)
	}
	for _, step := range b.ReleaseOrder() {
		if step.Kind == "volume" || step.Kind == "bridge" || step.Key == source {
			t.Fatal("app took management ownership of borrowed resource")
		}
	}
	if ctx.Current[source].Generation != 17 || ctx.Volumes[ready.Spec.Scope.Key()].Revision() != before {
		t.Fatal("planning mutated management state")
	}
}
