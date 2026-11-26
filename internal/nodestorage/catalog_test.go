// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
)

type rootFixture struct {
	users      access.Catalog
	book       Catalog
	key        ed25519.PrivateKey
	definition Definition
}

func newRootFixture(t *testing.T) rootFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{31}, 32))
	public := [32]byte(key.Public().(ed25519.PublicKey))
	u, err := access.New(public)
	if err != nil {
		t.Fatal(err)
	}
	u, err = u.Enroll(public, access.User{ID: "admin", Username: "admin", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: public, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"first", "second"} {
		u, err = u.CreateTenant("admin", tenant, 0)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := u.Tenant(tenant)
		u, err = u.SetNodes("admin", tenant, r.Revision, []string{"node-a", "node-b"})
		if err != nil {
			t.Fatal(err)
		}
	}
	u, err = u.PutUser("admin", 0, access.User{ID: "manager", Username: "manager", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte{77}, Enabled: true}}})
	if err != nil {
		t.Fatal(err)
	}
	u, err = u.SetMembership("admin", 0, access.Membership{Tenant: "first", User: "manager", Role: access.Manager, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	return rootFixture{u, b, key, Definition{Node: "node-a", Key: public, ID: "hdd", Path: "/mnt/hdd", Tenants: []string{"first"}, MaxVolumes: 2}}
}
func directoryFact(seed byte) Directory {
	return Directory{Filesystem: "ext4", FilesystemPath: fmt.Sprintf("/dir-%d", seed), UUID: [16]byte{1}, HandleType: 1, Handle: bytes.Repeat([]byte{seed}, 8), Inode: uint64(seed), DeviceMajor: 8, DeviceMinor: 1, Boot: [32]byte{4}, Namespace: [32]byte{5}, MountID: 9}
}
func signedRoot(f rootFixture, r Root, seed byte) RootFact {
	p := RootFact{Schema: 1, Root: r.Reference(f.book.cluster), Directory: directoryFact(seed)}
	p.Signature = ed25519.Sign(f.key, RootFactBytes(p))
	return p
}
func rootBytes(t *testing.T, b Catalog) []byte {
	t.Helper()
	raw, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func observedRoot(t *testing.T) rootFixture {
	t.Helper()
	f := newRootFixture(t)
	var err error
	f.book, err = f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.book.Root("node-a", "hdd")
	f.book, err = f.book.Observe(signedRoot(f, r, 2), f.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestStorageRootRequiresNativeFactAndExplicitTenantACL(t *testing.T) {
	f := newRootFixture(t)
	before := rootBytes(t, f.book)
	if _, err := f.book.Add(f.users, "manager", 0, f.definition); err == nil {
		t.Fatal("tenant manager registered host root")
	}
	if !bytes.Equal(before, rootBytes(t, f.book)) {
		t.Fatal("rejection changed original")
	}
	b, err := f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := b.Root("node-a", "hdd")
	if _, err = b.CanUse(f.users, "manager", "first", "node-a", "hdd", r.Generation); err == nil {
		t.Fatal("metadata accepted as native availability")
	}
	f.book = b
	b, err = b.Observe(signedRoot(f, r, 2), f.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.CanUse(f.users, "manager", "first", "node-a", "hdd", r.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err = b.CanUse(f.users, "admin", "second", "node-a", "hdd", r.Generation); err == nil {
		t.Fatal("implicit root tenant permission")
	}
	r, _ = b.Root("node-a", "hdd")
	b, err = b.SetPolicy(f.users, "admin", "node-a", "hdd", r.Revision, nil, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.CanUse(f.users, "manager", "first", "node-a", "hdd", r.Generation); err == nil {
		t.Fatal("revoked root ACL still admitted use")
	}
}

func TestStorageRootRejectsOverlapsWrongProofAndShrink(t *testing.T) {
	f := observedRoot(t)
	r, _ := f.book.Root("node-a", "hdd")
	original := rootBytes(t, f.book)
	for _, p := range []string{"/", "/mnt/hdd", "/mnt/hdd/inside", "/mnt", "/mnt/../elsewhere"} {
		d := f.definition
		d.ID = "other"
		d.Path = p
		if _, err := f.book.Add(f.users, "admin", 0, d); err == nil {
			t.Fatal("overlap/unclean accepted", p)
		}
	}
	wrong := signedRoot(f, r, 2)
	wrong.Root.Generation++
	wrong.Signature = ed25519.Sign(f.key, RootFactBytes(wrong))
	if _, err := f.book.Observe(wrong, f.definition.Key); err == nil {
		t.Fatal("old/wrong registration fact accepted")
	}
	if _, err := f.book.SetPolicy(f.users, "admin", "node-a", "hdd", r.Revision, []string{"first"}, 1, 2); err == nil {
		t.Fatal("root shrank below registered/unknown references")
	}
	if !bytes.Equal(original, rootBytes(t, f.book)) {
		t.Fatal("negative input mutated original")
	}
	d := f.definition
	d.Node = "node-b"
	if _, err := f.book.Add(f.users, "admin", 0, d); err != nil {
		t.Fatal("separate node directory rejected", err)
	}
}

func TestStorageRootDrainCloseRemovalAndSameNameFloor(t *testing.T) {
	f := observedRoot(t)
	r, _ := f.book.Root("node-a", "hdd")
	old := r.Reference(f.book.cluster)
	var err error
	f.book, err = f.book.Drain(f.users, "admin", "node-a", "hdd", r.Revision)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.book.Root("node-a", "hdd")
	if _, err = f.book.CanUse(f.users, "admin", "first", "node-a", "hdd", r.Generation); err == nil {
		t.Fatal("Drain allowed new use")
	}
	if _, err = f.book.Remove(f.users, "admin", "node-a", "hdd", r.Revision, 0); err == nil {
		t.Fatal("zero/unknown observation treated as native closure")
	}
	closed := RootClosed{Schema: 1, Root: old, NoUsers: true, NoPending: true}
	closed.Signature = ed25519.Sign(f.key, RootClosedBytes(closed))
	f.book, err = f.book.ObserveClosed(closed, f.definition.Key)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.book.Root("node-a", "hdd")
	if _, err = f.book.Remove(f.users, "admin", "node-a", "hdd", r.Revision, 1); err == nil {
		t.Fatal("removed root with registered volume")
	}
	f.book, err = f.book.Remove(f.users, "admin", "node-a", "hdd", r.Revision, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.book, err = Decode(rootBytes(t, f.book))
	if err != nil {
		t.Fatal(err)
	}
	f.book, err = f.book.Add(f.users, "admin", 0, f.definition)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = f.book.Root("node-a", "hdd")
	if r.Generation <= old.Generation {
		t.Fatal("same-name generation reset")
	}
	if _, err = f.book.ObserveClosed(closed, f.definition.Key); err == nil {
		t.Fatal("old native closure applied to new root")
	}
}

func TestStorageIdentityDistinguishesMountLossBootAndInodeReuse(t *testing.T) {
	original := directoryFact(2)
	for _, name := range []string{"uuid", "handle-generation", "same-boot-mount", "same-boot-namespace", "cross-boot"} {
		t.Run(name, func(t *testing.T) {
			next := ownDirectory(original)
			switch name {
			case "uuid":
				next.UUID[0]++
			case "handle-generation":
				next.Handle[0]++
			case "same-boot-mount":
				next.MountID++
			case "same-boot-namespace":
				next.Namespace[0]++
			case "cross-boot":
				next.Boot[0]++
				next.Namespace[0]++
				next.MountID++
			}
			if next.MatchesOriginal(original) != (name == "cross-boot") {
				t.Fatal("wrong original data/mount decision", name)
			}
		})
	}
}

func TestStorageRootCodecAndOwnedSlices(t *testing.T) {
	f := observedRoot(t)
	before := rootBytes(t, f.book)
	r, _ := f.book.Root("node-a", "hdd")
	r.Definition.Tenants[0] = "second"
	r.Attestation.Directory.Handle[0]++
	if !bytes.Equal(before, rootBytes(t, f.book)) {
		t.Fatal("public view mutated original root")
	}
	if _, err := Decode(append(before, '\n')); err == nil {
		t.Fatal("noncanonical checkpoint accepted")
	}
	var d checkpoint
	if err := json.Unmarshal(before, &d); err != nil {
		t.Fatal(err)
	}
	d.Roots[0].Attestation.Signature[0]++
	raw, _ := json.Marshal(d)
	if _, err := Decode(raw); err == nil {
		t.Fatal("forged native identity accepted")
	}
}

func TestStorageCapacityDoesNotSumSameFilesystemTwice(t *testing.T) {
	f := observedRoot(t)
	first, _ := f.book.Root("node-a", "hdd")
	d := f.definition
	d.ID = "ssd"
	d.Path = "/mnt/ssd"
	var err error
	f.book, err = f.book.Add(f.users, "admin", 0, d)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := f.book.Root("node-a", "ssd")
	f.book, err = f.book.Observe(signedRoot(f, second, 3), d.Key)
	if err != nil {
		t.Fatal(err)
	}
	a := Space{Root: first.Reference(f.book.cluster), Directory: directoryFact(2), Total: 1000, Free: 700, Available: 600}
	b := Space{Root: second.Reference(f.book.cluster), Directory: directoryFact(3), Total: 1000, Free: 650, Available: 550}
	rows, err := f.book.Capacities([]Space{a, b})
	if err != nil || len(rows) != 1 || rows[0].Roots != 2 || rows[0].Total != 1000 || rows[0].Available != 550 {
		t.Fatal("filesystem free space duplicated", rows, err)
	}
	if _, err = f.book.Capacities([]Space{a, a}); err == nil {
		t.Fatal("duplicate sample accepted")
	}
	b.Directory.DeviceMinor++
	if _, err = f.book.Capacities([]Space{a, b}); err == nil {
		t.Fatal("same UUID on a different device merged")
	}
}

func TestStorageRootPhysicalBindAliasOverlapRefused(t *testing.T) {
	f := observedRoot(t)
	d := f.definition
	d.ID = "alias"
	d.Path = "/mnt/unrelated-alias"
	var err error
	f.book, err = f.book.Add(f.users, "admin", 0, d)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := f.book.Root(d.Node, d.ID)
	for _, p := range []string{"/dir-2", "/dir-2/subdir", "/"} {
		fact := signedRoot(f, r, 4)
		fact.Directory.FilesystemPath = p
		fact.Signature = ed25519.Sign(f.key, RootFactBytes(fact))
		if _, err = f.book.Observe(fact, d.Key); err == nil {
			t.Fatal("physical overlap hidden by different host path", p)
		}
	}
}

func TestStorageMountInfoPathEscapesAreStrict(t *testing.T) {
	p, err := mountPath(`/disk\040space/data`)
	if err != nil || p != "/disk space/data" {
		t.Fatal(p, err)
	}
	for _, bad := range []string{`/disk\999bad`, `/disk\04`, `relative`, `/disk/../data`} {
		if _, err = mountPath(bad); err == nil {
			t.Fatal("malformed mount path accepted", bad)
		}
	}
}

func TestStorageSpaceAggregationRejectsMixedNodeBootKeyAndCluster(t *testing.T) {
	f := observedRoot(t)
	r, _ := f.book.Root("node-a", "hdd")
	a := Space{Root: r.Reference(f.book.Cluster()), Directory: r.Attestation.Directory, Total: 1000, Free: 800, Available: 700}
	b := a
	b.Root.ID = "ssd"
	b.Directory = ownDirectory(a.Directory)
	b.Directory.FilesystemPath = "/independent"
	b.Directory.Handle = bytes.Repeat([]byte{8}, 8)
	b.Directory.Inode = 8
	b.Free, b.Available = 750, 650
	pools, err := AggregateSpaces([]Space{a, b})
	if err != nil || len(pools) != 1 || pools[0].Roots != 2 || pools[0].Free != 750 || pools[0].Available != 650 || pools[0].Total != 1000 {
		t.Fatal("same filesystem summed/root distinction lost", pools, err)
	}
	for name, change := range map[string]func(*Space){
		"other boot on other filesystem":      func(s *Space) { s.Directory.UUID = [16]byte{8}; s.Directory.Boot = [32]byte{7} },
		"other namespace on other filesystem": func(s *Space) { s.Directory.UUID = [16]byte{8}; s.Directory.Namespace = [32]byte{7} },
		"same node different key":             func(s *Space) { s.Root.Key = [32]byte{7} },
		"same key different node":             func(s *Space) { s.Root.Node = "node-b" },
		"other cluster":                       func(s *Space) { s.Root.Cluster = [32]byte{7} },
		"observation absent":                  func(s *Space) { s.Total, s.Free, s.Available = 0, 0, 0 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := b
			change(&bad)
			if _, err := AggregateSpaces([]Space{a, bad}); err == nil {
				t.Fatal("mixed/absent observation became capacity")
			}
		})
	}
}
