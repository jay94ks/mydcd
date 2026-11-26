// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func sourcePolicy() TenantPolicy {
	return TenantPolicy{Tenant: "tenant", Revision: 1, Enabled: true,
		Execution: ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100_000_000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  ResolverPolicy{AllowPackages: []string{"context", "example.invalid/safe", "example.invalid/safe/blocked", "github.com/jay94ks/mydcd/lifecycle/v1", "net/http", "net/url", "os", "unsafe"}, DenyPackages: []string{"example.invalid/safe/blocked/..."}, SourceCacheBytes: 1 << 20}}
}

func signedSource(seed byte, text string, modules []ModulePin) SourceFact {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	fact := SourceFact{Schema: 1, Cluster: [32]byte{1}, Owner: [32]byte(key.Public().(ed25519.PublicKey)), Tenant: "tenant", SDK: 1, Digest: sha256.Sum256([]byte(text)), Length: uint64(len(text)), Modules: modules}
	fact.Signature = ed25519.Sign(key, SourceFactBytes(fact))
	return fact
}

func TestCheckerSourceFactBindsLockAndSDKWithoutProviderSpecificCacheIdentity(t *testing.T) {
	const source = "package checker\n"
	f := signedSource(11, source, nil)
	otherProvider := signedSource(12, source, nil)
	if f.Verify() != nil || otherProvider.Verify() != nil || f.ContentDigest() != otherProvider.ContentDigest() || f.ContentDigest() != inlineContentDigest(source) {
		t.Fatal("inline/named or provider-independent content identity diverged")
	}
	pin := ModulePin{Path: "example.invalid/safe", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}
	locked := signedSource(11, source, []ModulePin{pin})
	if locked.Verify() != nil || locked.ContentDigest() == f.ContentDigest() {
		t.Fatal("dependency lock omitted from content identity")
	}
	copy := locked.Clone()
	copy.Modules[0].Version = "v1.0.1"
	copy.Signature[0] ^= 1
	if locked.Verify() != nil || copy.Verify() == nil || copy.ContentDigest() == locked.ContentDigest() {
		t.Fatal("source copy aliases signed modules/signature")
	}
	for _, corrupt := range []func(*SourceFact){
		func(f *SourceFact) { f.Tenant = "other" },
		func(f *SourceFact) { f.SDK = 2 },
		func(f *SourceFact) { f.Length++ },
		func(f *SourceFact) { f.Cluster[0]++ },
		func(f *SourceFact) { f.Digest[0]++ },
	} {
		copy := locked.Clone()
		corrupt(&copy)
		if copy.Verify() == nil {
			t.Fatal("fact mutation kept original signature valid")
		}
	}
}

func TestCheckerResolverDenialAndExactModuleLockCannotBeWidenedByAllow(t *testing.T) {
	p := sourcePolicy()
	if p.Validate() != nil || !p.AllowsPackage("context") || !p.AllowsPackage("net/url") || !p.AllowsPackage("example.invalid/safe") {
		t.Fatal("valid explicit package policy rejected")
	}
	for _, pkg := range []string{"unsafe", "os", "net/http", "net", "example.invalid/safe/blocked", "example.invalid/safe/blocked/child", "example.invalid/unlisted"} {
		if p.AllowsPackage(pkg) {
			t.Fatal("blacklist/hard boundary/default deny bypass", pkg)
		}
	}
	lock := ModulePin{Path: "example.invalid/safe", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}
	p.Resolver.Modules = []ModulePin{lock}
	f := signedSource(11, "package checker\n", []ModulePin{lock})
	if !p.AllowsSource(f) {
		t.Fatal("exact approved source lock rejected")
	}
	changed := lock
	changed.Digest[0]++
	if p.AllowsSource(signedSource(11, "package checker\n", []ModulePin{changed})) {
		t.Fatal("same version/different bytes bypassed lock")
	}
	changed = lock
	changed.Length = p.Resolver.SourceCacheBytes
	p.Resolver.Modules = []ModulePin{changed}
	if p.AllowsSource(signedSource(11, "package checker\n", []ModulePin{changed})) {
		t.Fatal("source plus dependency exceeded tenant cache budget")
	}
	if p.AllowsSource(signedSource(11, "package checker\n", []ModulePin{{Path: "os", Version: "v1.0.0", Digest: [32]byte{3}, Length: 1}})) {
		t.Fatal("module shadowed stdlib")
	}
}

func TestCheckerPolicyExplicitInterpretedOnlyAndOwnsLocks(t *testing.T) {
	p := sourcePolicy()
	p.Build.Toolchain = "go1.27.3"
	if p.Validate() == nil {
		t.Fatal("implicit host builder without assigned nodes")
	}
	p.Build = BuildPolicy{}
	p.Resolver.Modules = []ModulePin{{Path: "example.invalid/safe", Version: "v1.0.0", Digest: [32]byte{2}, Length: 1024}}
	copy := p.Clone()
	copy.Execution.Capabilities[0] = "exec"
	copy.Resolver.Modules[0].Digest[0]++
	copy.Resolver.AllowPackages[0] = "forged"
	if p.Validate() != nil || p.Execution.Capabilities[0] != "file" || p.Resolver.Modules[0].Digest[0] != 2 || !p.AllowsPackage("context") {
		t.Fatal("policy mutation reached original")
	}
	p.Enabled = false
	if p.AllowsPackage("context") || p.AllowsSource(signedSource(11, "package checker\n", nil)) {
		t.Fatal("disabled policy admitted new source/import")
	}
}

func TestCheckerUploadFactIsOptionalSignedAndIndependentOfContentIdentity(t *testing.T) {
	original := signedSource(11, "package checker\n", nil)
	raw, _ := json.Marshal(original)
	if bytes.Contains(raw, []byte(`"Upload"`)) {
		t.Fatal("legacy signed bytes acquired optional field")
	}
	token := [32]byte{51}
	tracked := original.Clone()
	tracked.Upload = &token
	if tracked.Verify() == nil {
		t.Fatal("unsigned publication token accepted")
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	tracked.Signature = ed25519.Sign(private, SourceFactBytes(tracked))
	clear(private)
	if tracked.Verify() != nil || tracked.ContentDigest() != original.ContentDigest() {
		t.Fatal("upload identity changed immutable bytes")
	}
	copy := tracked.Clone()
	copy.Upload[0]++
	if tracked.Verify() != nil || copy.Verify() == nil {
		t.Fatal("clone aliased signed upload token")
	}
}
