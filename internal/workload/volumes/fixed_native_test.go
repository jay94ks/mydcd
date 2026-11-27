// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jay94ks/seafield/internal/nodestorage"
)

// Only the fact/codec contract is exercised here. Actual ext4/native mount
// observations belong to the S1 owned filesystem/Engine fixture.
func fixedReadyFixture(t *testing.T) (NativeReady, ed25519.PrivateKey) {
	t.Helper()
	f := fixedFixture(t)
	ref := nodestorage.Reference{Cluster: f.s.Scope().Cluster, Node: "node-a", Key: public(f.a), ID: "hdd", Generation: 1, Path: "/mnt/hdd"}
	dir := nodestorage.Directory{Filesystem: "ext4", FilesystemPath: "/", UUID: [16]byte{1}, HandleType: 1, Handle: bytes.Repeat([]byte{2}, 8), Inode: 2, DeviceMajor: 8, DeviceMinor: 1, Boot: [32]byte{3}, Namespace: [32]byte{4}, MountID: 5}
	root := nodestorage.RootFact{Schema: 1, Root: ref, Directory: dir}
	root.Signature = ed25519.Sign(f.a, nodestorage.RootFactBytes(root))
	dir.FilesystemPath, dir.Inode, dir.Handle = "/data", 3, bytes.Repeat([]byte{3}, 8)
	fixed := nodestorage.FixedDirectory{Root: root, RootDirectory: root.Directory, Path: "/mnt/hdd/data", Directory: dir}
	digest := fixed.Selection().Digest()
	spec := NativeSpec{Schema: 1, Scope: f.s.Scope(), Node: "node-a", NodeKey: public(f.a), Retain: true, Kind: "node-fixed", FixedDigest: hex.EncodeToString(digest[:])}
	ready := NativeReady{Schema: 1, Spec: spec, Generation: spec.Scope.Generation, Owner: Owner{Node: spec.Node, Key: spec.NodeKey, Native: FixedNativeName(spec.Scope)}, Fixed: &fixed}
	ready.Signature = ed25519.Sign(f.a, NativeReadyBytes(ready))
	if ready.Verify() != nil {
		t.Fatal("invalid simulated fixed fact")
	}
	return ready, f.a
}

func TestFixedNativeFactBindsWholeDirectoryAndSeparateManagedDriver(t *testing.T) {
	original, key := fixedReadyFixture(t)
	raw, _ := json.Marshal(original)
	for name, mutate := range map[string]func(*NativeReady){
		"leaf outside root":        func(r *NativeReady) { r.Fixed.Path = "/mnt/other/data" },
		"mount replacement":        func(r *NativeReady) { r.Fixed.RootDirectory.MountID++ },
		"fake Docker identity":     func(r *NativeReady) { r.Owner.Native = "sfc-unrelated" },
		"materialization retarget": func(r *NativeReady) { r.Spec.Materialization = "new" },
		"permission rewrite":       func(r *NativeReady) { r.Spec.UID = 10001 },
		"other native generation":  func(r *NativeReady) { r.Generation++ },
		"unbound leaf":             func(r *NativeReady) { r.Fixed = nil },
		"managed kind":             func(r *NativeReady) { r.Spec.Kind = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var r NativeReady
			if err := json.Unmarshal(raw, &r); err != nil {
				t.Fatal(err)
			}
			mutate(&r)
			r.Signature = ed25519.Sign(key, NativeReadyBytes(r))
			if r.Verify() == nil {
				t.Fatal("fixed binding accepted retarget/missing constraint")
			}
		})
	}
	for _, mutate := range []func(*NativeReady){
		func(r *NativeReady) { r.Fixed.Directory.Inode++ },
		func(r *NativeReady) { r.Fixed.Directory.Handle[0]++ },
	} {
		var changed NativeReady
		if err := json.Unmarshal(raw, &changed); err != nil {
			t.Fatal(err)
		}
		mutate(&changed)
		if changed.Verify() == nil {
			t.Fatal("unsigned original physical binding changed")
		}
	}
	if NativeKey(original.Spec) != FixedNativeKey(original.Spec.Scope) {
		t.Fatal("fixed native key lost explicit tenant scope")
	}
	specRaw, _ := json.Marshal(original.Spec)
	if _, err := decodeNative(string(specRaw)); err == nil {
		t.Fatal("managed local Docker driver accepted fixed host binding")
	}
	managed := nativeTestSpec(t)
	managedRaw, _ := json.Marshal(managed)
	if bytes.Contains(managedRaw, []byte(`"Kind"`)) || bytes.Contains(managedRaw, []byte(`"FixedDigest"`)) {
		t.Fatal("legacy managed bytes acquired empty optional fields")
	}
	managed.Kind, managed.FixedDigest = original.Spec.Kind, original.Spec.FixedDigest
	if managed.Validate() == nil {
		t.Fatal("managed app scope reinterpreted as tenant fixed")
	}
}
