// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/version"
	"path"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

const compileMainPath = "checker/src/github.com/jay94ks/seafield/checkercli/main.go"
const MaxCompileInputBytes = 64 << 20
const MaxCompileFiles = 8192
const MaxCompileManifestBytes = 4 << 20
const MaxCompiledArtifactBytes = 64 << 20 // one authenticated artifact body

var compileFlags = []string{"build", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid="}

type CompileRecipe struct {
	Schema                         uint8
	Tenant                         string
	Source                         [32]byte
	Image, Toolchain, GOOS, GOARCH string
	Flags                          []string
	SDK, Wrapper, Tree             [32]byte
}

func (r CompileRecipe) Key() [32]byte {
	raw, _ := json.Marshal(r)
	return sha256.Sum256(append([]byte("sfc-checker-compile-recipe-1\x00"), raw...))
}

// Validate preserves historical signed recipes without substituting the live
// SDK/wrapper. New compilation additionally checks the actual trusted sources.
func (r CompileRecipe) Validate() error {
	if r.Schema != 1 || !name(r.Tenant) || len(r.Image) > 512 || len(r.Toolchain) > 128 || r.Source == ([32]byte{}) || r.SDK == ([32]byte{}) || r.Wrapper == ([32]byte{}) || r.Tree == ([32]byte{}) || !version.IsValid(r.Toolchain) || !strings.HasPrefix(r.Toolchain, "go1.") || r.GOOS != "linux" || r.GOARCH != "amd64" && r.GOARCH != "arm64" || !slices.Equal(r.Flags, compileFlags) {
		return ErrSource
	}
	image, err := access.PinImage(r.Image)
	if err != nil || image.Reference != r.Image {
		return ErrSource
	}
	return nil
}

type CompileArtifact struct {
	Key, Digest         [32]byte
	Length              uint64
	Status, Reason      string
	DiagnosticTruncated bool `json:",omitempty"`
}
type CompileReport struct {
	Schema      uint8
	Job, Tenant string
	Items       []CompileArtifact
}

func (r CompileReport) Validate(b CompileBatch) error {
	if r.Schema != 1 || r.Job != b.Job || r.Tenant != b.Tenant || len(r.Items) != len(b.Items) || len(r.Items) == 0 || len(r.Items) > MaxScripts {
		return ErrSource
	}
	total := uint64(0)
	for i, item := range r.Items {
		if item.Key != b.Items[i].Key {
			return ErrSource
		}
		switch item.Status {
		case "built":
			if item.Reason != "compiled" || item.Digest == ([32]byte{}) || item.Length == 0 || item.Length > b.ArtifactBytes || item.Length > MaxCompiledArtifactBytes || total > b.OutputBytes || item.Length > b.OutputBytes-total {
				return ErrSource
			}
			total += item.Length
		case "failed":
			if item.Digest != ([32]byte{}) || item.Length != 0 || item.Reason != "compile-error" && item.Reason != "artifact-invalid" {
				return ErrSource
			}
		default:
			return ErrSource
		}
	}
	return nil
}

type CompileFile struct {
	Path   string
	Digest [32]byte
	Length uint64
}
type CompileItem struct {
	Key    [32]byte
	Recipe CompileRecipe
	Source SourceDescriptor
	Files  []CompileFile
}

type CompileBatch struct {
	Schema                                     uint8
	Job, Tenant                                string
	DeadlineUnixMilli                          int64
	Toolchain, GOOS, GOARCH                    string
	WorkspaceBytes, ArtifactBytes, OutputBytes uint64
	Items                                      []CompileItem
}

// Compilation is constructed only from the actual sealed resolver view. Its
// materialized contents include the exact live contract/SDK/bridge, not copies
// of a separately maintained algorithm or a host module-cache fallback.
type Compilation struct {
	item  CompileItem
	files map[string][]byte
}

func (c *Compilation) Item() CompileItem {
	item := c.item
	item.Recipe = c.Recipe()
	item.Source = item.Source.Clone()
	item.Files = slices.Clone(item.Files)
	return item
}

func (c *Compilation) Key() [32]byte { return c.item.Key }
func (c *Compilation) Recipe() CompileRecipe {
	r := c.item.Recipe
	r.Flags = slices.Clone(r.Flags)
	return r
}

func compileWrapper(expected CompiledExpectation) []byte {
	return []byte(fmt.Sprintf(`package main

import (
 "context"
 "net"
 "os"
 checker "sfc.local/checker"
 core "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func main() {
 if len(os.Args) != 4 || os.Args[1] != "run" || os.Args[2] != "--contract" || os.Args[3] != "1" { os.Exit(2) }
 probeFile := os.NewFile(3, "checker-probe")
 result := os.NewFile(4, "checker-result")
 if probeFile == nil || result == nil { os.Exit(2) }
 conn, err := net.FileConn(probeFile)
 _ = probeFile.Close()
 if err != nil { os.Exit(2) }
 code := core.RunCompiled(context.Background(), core.CompiledExpectation{
  Tenant: %q, SourceDigest: %q, Toolchain: %q, GOOS: %q, GOARCH: %q,
 }, checker.Check, os.Stdin, conn, result)
 _ = conn.Close()
 _ = result.Close()
 os.Exit(code)
}
`, expected.Tenant, expected.SourceDigest, expected.Toolchain, expected.GOOS, expected.GOARCH))
}

func fileManifest(files map[string][]byte) ([]CompileFile, [32]byte) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	list := make([]CompileFile, 0, len(paths))
	for _, p := range paths {
		list = append(list, CompileFile{Path: p, Digest: sha256.Sum256(files[p]), Length: uint64(len(files[p]))})
	}
	raw, _ := json.Marshal(list)
	return list, sha256.Sum256(append([]byte("sfc-checker-compile-tree-1\x00"), raw...))
}

// PrepareCompilation builds source's compile item for the compiler image
// (repo@sha256:…) the policy's reference resolved to for this deploy.
func PrepareCompilation(source *ResolvedSource, image string) (*Compilation, error) {
	if source == nil || !source.policy.Build.AllowsCompiler(image) || source.files == nil || source.policy.Validate() != nil || !source.policy.Enabled || len(source.policy.Build.Nodes) == 0 || source.target.Toolchain != source.policy.Build.Toolchain || !slices.Contains(source.policy.Build.Targets, source.target.GOOS+"/"+source.target.GOARCH) || !source.policy.AllowsDescriptor(source.descriptor) {
		return nil, ErrSource
	}
	files := source.SourceFiles()
	trusted := trustedCompileSources()
	_, sdk := fileManifest(trusted)
	for p, data := range trusted {
		if _, exists := files[p]; exists {
			return nil, ErrSource
		}
		files[p] = data
	}
	content := source.descriptor.ContentDigest()
	wrapper := compileWrapper(CompiledExpectation{Tenant: source.descriptor.Tenant, SourceDigest: hex.EncodeToString(content[:]), Toolchain: source.target.Toolchain, GOOS: source.target.GOOS, GOARCH: source.target.GOARCH})
	if _, exists := files[compileMainPath]; exists {
		return nil, ErrSource
	}
	files[compileMainPath] = wrapper
	manifest, tree := fileManifest(files)
	item := CompileItem{Recipe: CompileRecipe{Schema: 1, Tenant: source.descriptor.Tenant, Source: content,
		Image: image, Toolchain: source.target.Toolchain, GOOS: source.target.GOOS, GOARCH: source.target.GOARCH,
		SDK: sdk, Wrapper: sha256.Sum256(wrapper), Tree: tree}, Source: source.descriptor.Clone(), Files: manifest}
	item.Recipe.Flags = slices.Clone(compileFlags)
	item.Key = item.Recipe.Key()
	if !validCompileItem(item) {
		return nil, ErrSource
	}
	return &Compilation{item: item, files: files}, nil
}

func validCompileItem(item CompileItem) bool {
	r := item.Recipe
	if r.Schema != 1 || !name(r.Tenant) || r.Source != item.Source.ContentDigest() || item.Source.Validate() != nil || r.Tenant != item.Source.Tenant || r.GOOS != "linux" || r.GOARCH != "amd64" && r.GOARCH != "arm64" || !strings.HasPrefix(r.Toolchain, "go1.") || !slices.Equal(r.Flags, compileFlags) || item.Key != r.Key() || len(item.Files) == 0 || len(item.Files) > MaxCompileFiles {
		return false
	}
	image, err := access.PinImage(r.Image)
	if err != nil || image.Reference != r.Image {
		return false
	}
	_, sdk := fileManifest(trustedCompileSources())
	wrapper := compileWrapper(CompiledExpectation{Tenant: r.Tenant, SourceDigest: hex.EncodeToString(r.Source[:]), Toolchain: r.Toolchain, GOOS: r.GOOS, GOARCH: r.GOARCH})
	if r.SDK != sdk || r.Wrapper != sha256.Sum256(wrapper) {
		return false
	}
	previous := ""
	total := uint64(0)
	present := map[string]CompileFile{}
	for _, f := range item.Files {
		if f.Path <= previous || !strings.HasPrefix(f.Path, "checker/src/") || path.IsAbs(f.Path) || path.Clean(f.Path) != f.Path || !strings.HasSuffix(f.Path, ".go") || strings.ContainsAny(f.Path, "\\\x00\r\n") || len(f.Path) > 1024 || f.Digest == ([32]byte{}) || f.Length == 0 || f.Length > maxGoFileBytes || total > MaxCompileInputBytes-f.Length {
			return false
		}
		previous, total = f.Path, total+f.Length
		present[f.Path] = f
	}
	for p, data := range trustedCompileSources() {
		f, ok := present[p]
		if !ok || f.Digest != sha256.Sum256(data) || f.Length != uint64(len(data)) {
			return false
		}
	}
	main, ok := present[compileMainPath]
	if !ok || main.Digest != r.Wrapper || main.Length != uint64(len(wrapper)) {
		return false
	}
	root, ok := present[path.Join(resolverGoPath, "src", checkerImport, "checker.go")]
	if !ok || root.Digest != item.Source.Digest || root.Length != item.Source.Length {
		return false
	}
	raw, _ := json.Marshal(item.Files)
	return r.Tree == sha256.Sum256(append([]byte("sfc-checker-compile-tree-1\x00"), raw...))
}

// NewCompileBatch is one compiler run: every input names the same compiler
// image, which the policy allows.
func NewCompileBatch(job string, deadline int64, policy TenantPolicy, image string, inputs []*Compilation) (CompileBatch, error) {
	if !digest(job) || !policy.Build.AllowsCompiler(image) || deadline <= 0 || policy.Validate() != nil || !policy.Enabled || len(policy.Build.Nodes) == 0 || len(inputs) == 0 || len(inputs) > MaxScripts {
		return CompileBatch{}, ErrSource
	}
	b := CompileBatch{Schema: 1, Job: job, Tenant: policy.Tenant, DeadlineUnixMilli: deadline, Toolchain: policy.Build.Toolchain,
		WorkspaceBytes: policy.Build.WorkspaceBytes, ArtifactBytes: min(policy.Build.ArtifactBytes, MaxCompiledArtifactBytes), OutputBytes: min(policy.CompiledCacheBytes, policy.Build.WorkspaceBytes)}
	seen := map[[32]byte]bool{}
	for _, input := range inputs {
		if input == nil || !validCompileItem(input.item) || input.item.Recipe.Tenant != b.Tenant || input.item.Recipe.Image != image || input.item.Recipe.Toolchain != b.Toolchain || !policy.AllowsDescriptor(input.item.Source) {
			return CompileBatch{}, ErrSource
		}
		r := input.item.Recipe
		if !slices.Contains(policy.Build.Targets, r.GOOS+"/"+r.GOARCH) {
			return CompileBatch{}, ErrSource
		}
		if b.GOOS == "" {
			b.GOOS, b.GOARCH = r.GOOS, r.GOARCH
		}
		if r.GOOS != b.GOOS || r.GOARCH != b.GOARCH {
			return CompileBatch{}, ErrSource
		}
		if !seen[input.item.Key] {
			seen[input.item.Key] = true
			b.Items = append(b.Items, input.Item())
		}
	}
	slices.SortFunc(b.Items, func(a, c CompileItem) int { return bytes.Compare(a.Key[:], c.Key[:]) })
	if err := b.Validate(); err != nil {
		return CompileBatch{}, err
	}
	return b, nil
}

func (b CompileBatch) Validate() error {
	if b.Schema != 1 || !digest(b.Job) || !name(b.Tenant) || b.DeadlineUnixMilli <= 0 || b.GOOS != "linux" || b.GOARCH != "amd64" && b.GOARCH != "arm64" || b.WorkspaceBytes == 0 || b.WorkspaceBytes > 1<<40 || b.ArtifactBytes == 0 || b.ArtifactBytes > MaxCompiledArtifactBytes || b.ArtifactBytes > b.WorkspaceBytes || b.OutputBytes < b.ArtifactBytes || b.OutputBytes > b.WorkspaceBytes || len(b.Items) == 0 || len(b.Items) > MaxScripts {
		return ErrSource
	}
	var previous [32]byte
	count := 0
	total := uint64(0)
	for i, item := range b.Items {
		if !validCompileItem(item) || item.Recipe.Tenant != b.Tenant || item.Recipe.Toolchain != b.Toolchain || item.Recipe.GOOS != b.GOOS || item.Recipe.GOARCH != b.GOARCH || item.Recipe.Image != b.Items[0].Recipe.Image || i > 0 && bytes.Compare(previous[:], item.Key[:]) >= 0 {
			return ErrSource
		}
		previous = item.Key
		count += len(item.Files)
		if count > MaxCompileFiles {
			return ErrSource
		}
		for _, f := range item.Files {
			if total > b.WorkspaceBytes || f.Length > b.WorkspaceBytes-total || total > MaxCompileInputBytes-f.Length {
				return ErrSource
			}
			total += f.Length
		}
	}
	raw, err := json.Marshal(b)
	if err != nil || len(raw) > MaxCompileManifestBytes {
		return ErrSource
	}
	return nil
}
