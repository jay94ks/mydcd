// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"path"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func scriptSource(extra, body string) []byte {
	return []byte("package checker\nimport (\"context\"; lifecycle \"github.com/jay94ks/seafield/lifecycle/v1\";" + extra + ")\nfunc Check(ctx context.Context, in lifecycle.Request, probe lifecycle.Probe) (lifecycle.Result, error) {\n" + body + "\n}\n")
}

const passBody = `return lifecycle.Result{Schema: 1, Status: lifecycle.Pass, Reason: "ready"}, nil`

func moduleArchive(t *testing.T, module string, files map[string][]byte) ModuleArchive {
	return moduleArchiveMethod(t, module, files, zip.Store)
}

func moduleArchiveMethod(t *testing.T, module string, files map[string][]byte, method uint16) ModuleArchive {
	t.Helper()
	var data bytes.Buffer
	w := zip.NewWriter(&data)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		file, err := w.CreateHeader(&zip.FileHeader{Name: module + "@v1.0.0/" + name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw := data.Bytes()
	return ModuleArchive{Pin: ModulePin{Path: module, Version: "v1.0.0", Digest: sha256.Sum256(raw), Length: uint64(len(raw))}, ZIP: raw}
}

func resolverInput(root []byte, archives []ModuleArchive, allow ...string) (TenantPolicy, SourceDescriptor, ResolverTarget) {
	p := sourcePolicy()
	p.Resolver.AllowPackages = append([]string{"context", checkerSDK}, allow...)
	slices.Sort(p.Resolver.AllowPackages)
	p.Resolver.AllowPackages = slices.Compact(p.Resolver.AllowPackages)
	p.Resolver.DenyPackages = nil
	p.Resolver.SourceCacheBytes = 16 << 20
	d := SourceDescriptor{Tenant: p.Tenant, SDK: 1, Digest: sha256.Sum256(root), Length: uint64(len(root))}
	for _, a := range archives {
		d.Modules = append(d.Modules, a.Pin)
	}
	p.Resolver.Modules = slices.Clone(d.Modules)
	return p, d, ResolverTarget{GOOS: "linux", GOARCH: runtime.GOARCH, Toolchain: runtime.Version()}
}

func TestCheckerResolverFreezesSelectedSourcesAndNeverReadsHostGOPATH(t *testing.T) {
	archive := moduleArchive(t, "example.invalid/safe", map[string][]byte{
		"go.mod":          []byte("module example.invalid/safe\ngo 1.21\n"),
		"safe_linux.go":   []byte("package safe\nconst Ready = true\n"),
		"safe_windows.go": []byte("package safe\nimport \"os\"\nvar _ = os.Exit\n"),
		"safe_test.go":    []byte("package safe\nimport \"unsafe\"\n"),
		"ignored.go":      []byte("//go:build ignore\n\npackage safe\nimport \"syscall\"\n"),
	})
	root := scriptSource(`"example.invalid/safe";`, `if !safe.Ready { return lifecycle.Result{}, nil }; `+passBody)
	p, d, target := resolverInput(root, []ModuleArchive{archive}, "example.invalid/safe")
	source, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{archive}, target)
	if err != nil {
		t.Fatal(err)
	}
	files := source.SourceFiles()
	if len(files) != 2 || source.PolicyRevision() != p.Revision || source.MaterializedBytes() <= uint64(len(root)+len(archive.ZIP)) {
		t.Fatal("selection or materialized budget missing")
	}
	for name := range files {
		if strings.Contains(name, "windows") || strings.Contains(name, "ignored") || strings.Contains(name, "_test") {
			t.Fatal("other build variant escaped into executable view")
		}
		files[name][0] ^= 1
	}
	copy := source.Descriptor()
	copy.Modules[0].Digest[0]++
	p.Resolver.AllowPackages[0] = "forged"
	root[0] ^= 1
	archive.ZIP[0] ^= 1
	if source.Descriptor().ContentDigest() != d.ContentDigest() {
		t.Fatal("source metadata aliases caller")
	}
	for name, data := range source.SourceFiles() {
		if bytes.Equal(data, files[name]) {
			t.Fatal("compiler snapshot aliases immutable interpreter source")
		}
	}
	for _, forbidden := range []string{"/etc/passwd", "../src", "checker/src/os", "checker/src/does-not-exist"} {
		if _, err := source.files.Open(forbidden); err == nil {
			t.Fatal("host/import fallback", forbidden)
		}
	}
	// This is a real product FS, not fstest.MapFS: Yaegi uses directory Stat
	// and ReadDir as well as file reads. Check close and sequential reads too.
	dir, err := source.files.Open(path.Join(resolverGoPath, "src", checkerImport))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := dir.(fs.ReadDirFile).ReadDir(1)
	if err != nil || len(entries) != 1 || entries[0].Name() != "checker.go" {
		t.Fatal(entries, err)
	}
	dir.Close()
	if _, err := dir.Stat(); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed source handle remained live")
	}
}

func TestCheckerResolverInspectsTransitiveImportsAndInitBeforeEitherBackend(t *testing.T) {
	root := scriptSource(`"example.invalid/safe";`, `if !safe.Ready { return lifecycle.Result{}, nil }; `+passBody)
	safe := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\nimport \"example.invalid/transitive\"\nvar Ready = transitive.Ready\n")})
	for _, tc := range []struct {
		name, source string
		allow        bool
		wantOK       bool
	}{
		{"approved", "package transitive\nvar Ready = true\nfunc init() { Ready = false }", true, true},
		{"unlisted-transitive", "package transitive\nvar Ready = true", false, false},
		{"init-host-file", "package transitive\nimport \"os\"\nvar Ready = true\nfunc init() { os.Remove(\"/tmp/must-never-run\") }", true, false},
		{"init-cgo", "package transitive\nimport \"C\"\nvar Ready = true", true, false},
		{"linkname", "package transitive\n//go:linkname Ready runtime.somewhere\nvar Ready = true", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transitive := moduleArchive(t, "example.invalid/transitive", map[string][]byte{"transitive.go": []byte(tc.source)})
			archives := []ModuleArchive{safe, transitive}
			allow := []string{"example.invalid/safe", "os", "unsafe"}
			if tc.allow {
				allow = append(allow, "example.invalid/transitive")
			}
			p, d, target := resolverInput(root, archives, allow...)
			resolved, err := ResolveSource(context.Background(), p, d, root, archives, target)
			if (err == nil) != tc.wantOK || !tc.wantOK && resolved != nil {
				t.Fatal("transitive policy/init inspection", err)
			}
		})
	}
}

func TestCheckerResolverRejectsArchiveAliasesBombsAndUnpinnedVersions(t *testing.T) {
	root := scriptSource(`"example.invalid/safe";`, passBody)
	for _, tc := range []struct {
		name  string
		files map[string][]byte
	}{
		{"traversal", map[string][]byte{"../escape.go": []byte("package safe")}},
		{"case-collision", map[string][]byte{"safe.go": []byte("package safe"), "Safe.go": []byte("package safe")}},
		{"vendor", map[string][]byte{"vendor/other/x.go": []byte("package other"), "safe.go": []byte("package safe")}},
		{"replaced-module", map[string][]byte{"go.mod": []byte("module example.invalid/safe\nreplace example.invalid/hidden => /tmp/host\n"), "safe.go": []byte("package safe")}},
		{"wrong-module", map[string][]byte{"go.mod": []byte("module example.invalid/different\n"), "safe.go": []byte("package safe")}},
		{"native-object", map[string][]byte{"native.syso": {1, 2, 3}, "safe.go": []byte("package safe")}},
		{"import-cycle", map[string][]byte{"safe.go": []byte("package safe\nimport \"example.invalid/safe\"\n")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := moduleArchive(t, "example.invalid/safe", tc.files)
			p, d, target := resolverInput(root, []ModuleArchive{a}, "example.invalid/safe")
			if source, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{a}, target); err == nil || source != nil {
				t.Fatal("accepted unsafe archive")
			}
		})
	}
	a := moduleArchive(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n"), "LICENSE": bytes.Repeat([]byte("x"), MaxScriptBytes)})
	p, d, target := resolverInput(root, []ModuleArchive{a}, "example.invalid/safe")
	p.Resolver.SourceCacheBytes = uint64(len(root) + len(a.ZIP)) // expansion also consumes the budget
	if !p.AllowsDescriptor(d) {
		t.Fatal("budget counterexample must pass metadata admission")
	}
	if _, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{a}, target); err == nil {
		t.Fatal("uncompressed cache bytes unaccounted")
	}
	compressed := moduleArchiveMethod(t, "example.invalid/safe", map[string][]byte{"safe.go": []byte("package safe\n"), "LICENSE": bytes.Repeat([]byte("x"), 2*MaxScriptBytes)}, zip.Deflate)
	cp, cd, ct := resolverInput(root, []ModuleArchive{compressed}, "example.invalid/safe")
	cp.Resolver.SourceCacheBytes = MaxScriptBytes
	if !cp.AllowsDescriptor(cd) {
		t.Fatal("compressed counterexample must pass metadata admission")
	}
	if _, err := ResolveSource(context.Background(), cp, cd, root, []ModuleArchive{compressed}, ct); err == nil {
		t.Fatal("compressed ZIP bypassed expanded byte budget")
	}
	p.Resolver.SourceCacheBytes = 16 << 20
	a.ZIP[len(a.ZIP)/2] ^= 1
	if _, err := ResolveSource(context.Background(), p, d, root, []ModuleArchive{a}, target); err == nil {
		t.Fatal("ZIP content not pinned")
	}
	for _, version := range []string{"v2.0.0", "v1", "v1.0.0+untrusted", "latest"} {
		pin := d.Modules[0]
		pin.Version = version
		if pin.valid() {
			t.Fatal("accepted noncanonical/incompatible module version", version)
		}
	}
	upper := moduleArchive(t, "example.invalid/A", map[string][]byte{"safe.go": []byte("package safe\n")})
	lower := moduleArchive(t, "example.invalid/a", map[string][]byte{"safe.go": []byte("package safe\n")})
	aliased := scriptSource(`upper "example.invalid/A"; lower "example.invalid/a";`, passBody)
	ap, ad, at := resolverInput(aliased, []ModuleArchive{upper, lower}, "example.invalid/A", "example.invalid/a")
	if _, err := ResolveSource(context.Background(), ap, ad, aliased, []ModuleArchive{upper, lower}, at); err == nil {
		t.Fatal("cross-module case collision escaped compiler/interpreter namespace check")
	}
}

func TestCheckerResolverKeepsPrivateBridgeAndContractOutsideTenantOverride(t *testing.T) {
	for _, tc := range []struct {
		name     string
		source   []byte
		packages []string
	}{
		{"blank-import", scriptSource(`_ "example.invalid/safe";`, passBody), []string{"example.invalid/safe"}},
		{"dot-import", scriptSource(`. "strings";`, passBody), []string{"strings"}},
		{"private-bridge", scriptSource(`"sfc.internal/lifecyclebridge";`, passBody), []string{checkerBridge}},
		{"product-module", scriptSource(`"github.com/jay94ks/seafield/extra";`, passBody), []string{productModule + "/extra"}},
		{"unknown-standard", scriptSource(`"reflect";`, passBody), []string{"reflect"}},
		{"wrong-entry-type", bytes.ReplaceAll(scriptSource("", passBody), []byte("probe lifecycle.Probe"), []byte("probe any")), nil},
		{"wrong-package", bytes.ReplaceAll(scriptSource("", passBody), []byte("package checker"), []byte("package main")), nil},
		{"line-directive", append([]byte("//line other.go:1\n"), scriptSource("", passBody)...), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archives []ModuleArchive
			switch tc.name {
			case "private-bridge":
				archives = []ModuleArchive{moduleArchive(t, checkerBridge, map[string][]byte{"bridge.go": []byte("package bridge\nconst Available = true\n")})}
			case "product-module":
				archives = []ModuleArchive{moduleArchive(t, productModule+"/extra", map[string][]byte{"extra.go": []byte("package extra\n")})}
			}
			p, d, target := resolverInput(tc.source, archives, tc.packages...)
			if _, err := ResolveSource(context.Background(), p, d, tc.source, archives, target); err == nil {
				t.Fatal("source boundary bypass")
			}
		})
	}
	root := scriptSource("", passBody)
	p, d, target := resolverInput(root, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ResolveSource(ctx, p, d, root, nil, target); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
