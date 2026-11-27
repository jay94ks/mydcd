// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/version"
	"io"
	"io/fs"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
	modzip "golang.org/x/mod/zip"
)

const (
	checkerImport   = "sfc.local/checker"
	productModule   = "github.com/jay94ks/seafield"
	checkerSDK      = productModule + "/lifecycle/v1"
	checkerBridge   = "sfc.internal/lifecyclebridge"
	resolverGoPath  = "checker"
	maxResolveBytes = 64 << 20
	maxResolveFiles = 8192
	maxGoFileBytes  = 1 << 20
)

var ErrSource = errors.New("lifecycle source resolution failed")

// ResolverTarget fixes selection before either backend sees source. No host
// build tags, cgo, environment or module cache participates in selection.
type ResolverTarget struct{ GOOS, GOARCH, Toolchain string }

func (t ResolverTarget) valid() bool {
	return t.GOOS == "linux" && (t.GOARCH == "amd64" || t.GOARCH == "arm64") && version.IsValid(t.Toolchain) && strings.HasPrefix(t.Toolchain, "go1.") && version.Compare(version.Lang(t.Toolchain), version.Lang(runtime.Version())) <= 0
}

// ModuleArchive is a caller-supplied exact Go module ZIP. Resolution never
// downloads bytes or resolves a new version. Its Digest is SHA-256 of the ZIP,
// not a Go h1 directory checksum.
type ModuleArchive struct {
	Pin ModulePin
	ZIP []byte
}

// ResolvedSource contains only selected, inspected sources. It establishes
// import/lock integrity, not Go type correctness, current permission, a durable
// artifact or a running sandbox. Both backends consume this immutable view.
type ResolvedSource struct {
	descriptor SourceDescriptor
	policy     TenantPolicy
	target     ResolverTarget
	files      *sourceFiles
	standard   []string
	bytes      uint64
}

func (s *ResolvedSource) Descriptor() SourceDescriptor { return s.descriptor.Clone() }
func (s *ResolvedSource) Target() ResolverTarget       { return s.target }
func (s *ResolvedSource) PolicyRevision() uint64       { return s.policy.Revision }
func (s *ResolvedSource) MaterializedBytes() uint64    { return s.bytes }
func (s *ResolvedSource) SourceFiles() map[string][]byte {
	out := make(map[string][]byte, len(s.files.files))
	for name, data := range s.files.files {
		out[name] = bytes.Clone(data)
	}
	return out
}

// ResolveSource is a bounded parser/import boundary. Its actual node adapter
// must run it under the same resource/isolation policy as user compilation.
func ResolveSource(ctx context.Context, policy TenantPolicy, descriptor SourceDescriptor, root []byte, archives []ModuleArchive, target ResolverTarget) (*ResolvedSource, error) {
	if ctx == nil || !target.valid() || !policy.AllowsDescriptor(descriptor) || uint64(len(root)) != descriptor.Length || sha256.Sum256(root) != descriptor.Digest || !utf8.Valid(root) || bytes.IndexByte(root, 0) >= 0 || len(archives) != len(descriptor.Modules) {
		return nil, ErrSource
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r := &sourceResolver{ctx: ctx, policy: policy.Clone(), descriptor: descriptor.Clone(), target: target,
		all: map[string][]byte{}, selected: map[string][]byte{}, visited: map[string]uint8{}, standard: map[string]bool{}, budget: descriptor.Length}
	if r.budget > maxResolveBytes {
		return nil, ErrSource
	}
	for i, archive := range archives {
		if archive.Pin != descriptor.Modules[i] || archive.Pin.Length != uint64(len(archive.ZIP)) || sha256.Sum256(archive.ZIP) != archive.Pin.Digest || !r.charge(archive.Pin.Length) {
			return nil, ErrSource
		}
		if err := r.archive(archive); err != nil {
			return nil, err
		}
	}
	rootName := path.Join(resolverGoPath, "src", checkerImport, "checker.go")
	if len(r.all) >= maxResolveFiles {
		return nil, ErrSource
	}
	r.all[rootName] = bytes.Clone(root)
	r.view = newSourceFiles(r.all)
	r.build = build.Context{GOOS: target.GOOS, GOARCH: target.GOARCH, Compiler: "gc", CgoEnabled: false,
		JoinPath: path.Join, OpenFile: func(name string) (io.ReadCloser, error) { return r.view.Open(name) }}
	minor, err := strconv.Atoi(strings.TrimPrefix(version.Lang(target.Toolchain), "go1."))
	if err != nil || minor < 1 || minor > 1024 {
		return nil, ErrSource
	}
	for v := 1; v <= minor; v++ {
		r.build.ReleaseTags = append(r.build.ReleaseTags, "go1."+strconv.Itoa(v))
	}
	if target.GOARCH == "amd64" {
		r.build.ToolTags = []string{"amd64.v1"}
	} else {
		r.build.ToolTags = []string{"arm64.v8.0"}
	}
	if err := r.visit(checkerImport, ""); err != nil {
		return nil, err
	}
	// Also reject collisions across different locked modules, not only files
	// inside one ZIP. The compiler and Yaegi must see the same namespace.
	selectedFiles := make([]modzip.File, 0, len(r.selected))
	for name, data := range r.selected {
		selectedFiles = append(selectedFiles, moduleFile{name: name, data: data})
	}
	checked, err := modzip.CheckFiles(selectedFiles)
	if err != nil || checked.Err() != nil || len(checked.Omitted) != 0 {
		return nil, ErrSource
	}
	standard := make([]string, 0, len(r.standard))
	for pkg := range r.standard {
		standard = append(standard, pkg)
	}
	slices.Sort(standard)
	return &ResolvedSource{descriptor: descriptor.Clone(), policy: policy.Clone(), target: target,
		files: newSourceFiles(r.selected), standard: standard, bytes: r.budget}, nil
}

type sourceResolver struct {
	ctx           context.Context
	policy        TenantPolicy
	descriptor    SourceDescriptor
	target        ResolverTarget
	all, selected map[string][]byte
	view          *sourceFiles
	build         build.Context
	visited       map[string]uint8
	standard      map[string]bool
	budget        uint64
}

func (r *sourceResolver) charge(n uint64) bool {
	limit := min(uint64(maxResolveBytes), r.policy.Resolver.SourceCacheBytes)
	if r.budget > limit || n > limit-r.budget {
		return false
	}
	r.budget += n
	return true
}

type moduleFile struct {
	name string
	data []byte
}

func (m moduleFile) Path() string { return m.name }
func (m moduleFile) Lstat() (fs.FileInfo, error) {
	return sourceInfo{name: path.Base(m.name), size: int64(len(m.data))}, nil
}
func (m moduleFile) Open() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(m.data)), nil }

func (r *sourceResolver) archive(a ModuleArchive) error {
	limit := min(uint64(maxResolveBytes), r.policy.Resolver.SourceCacheBytes)
	if r.budget > limit {
		return ErrSource
	}
	// The caller already charged ZIP bytes. Pass the remaining expansion
	// budget plus this ZIP to the shared staging/resolution inspector.
	image, err := inspectModuleArchive(r.ctx, a, limit-r.budget+a.Pin.Length)
	if err != nil {
		return err
	}
	if !r.charge(image.expanded) || !r.moduleDefinition(image.definition) {
		return ErrSource
	}
	for relative, data := range image.files {
		name := path.Join(resolverGoPath, "src", a.Pin.Path, relative)
		for _, other := range r.descriptor.Modules {
			if other.Path != a.Pin.Path && strings.HasPrefix(other.Path, a.Pin.Path+"/") && strings.HasPrefix(name, path.Join(resolverGoPath, "src", other.Path)+"/") {
				return ErrSource
			}
		}
		if _, exists := r.all[name]; exists || len(r.all) >= maxResolveFiles {
			return ErrSource
		}
		r.all[name] = data
	}
	return nil
}

func (r *sourceResolver) moduleDefinition(definition *modfile.File) bool {
	if definition == nil {
		return true
	} // pre-module archives remain fully locked
	if definition.Go != nil && version.Compare("go"+definition.Go.Version, r.target.Toolchain) > 0 {
		return false
	}
	for _, req := range definition.Require {
		for _, locked := range r.descriptor.Modules {
			if locked.Path == req.Mod.Path && semver.Compare(locked.Version, req.Mod.Version) < 0 {
				return false
			}
		}
	}
	return true
}

func internalImport(importer, imported string) bool {
	parts := strings.Split(imported, "/")
	for i, part := range parts {
		if part == "vendor" {
			return false
		}
		if part == "internal" {
			parent := strings.Join(parts[:i], "/")
			if parent == "" || importer != parent && !strings.HasPrefix(importer, parent+"/") {
				return false
			}
		}
	}
	return true
}

// reservedSourcePath reports import or module paths a checker may not supply.
// The product module is reserved too: only its checker SDK is importable, and
// a locked module must not shadow the product packages placed in the view.
func reservedSourcePath(pkg string) bool {
	for _, root := range []string{"sfc.internal", "sfc.local", productModule} {
		if pkg == root || strings.HasPrefix(pkg, root+"/") {
			return true
		}
	}
	return false
}

func (r *sourceResolver) visit(pkg, importer string) error {
	if err := r.ctx.Err(); err != nil {
		return err
	}
	if pkg != checkerImport {
		if pkg != checkerSDK && reservedSourcePath(pkg) {
			return ErrSource
		}
		if !r.policy.AllowsPackage(pkg) || !internalImport(importer, pkg) {
			return ErrSource
		}
		if pkg == checkerSDK {
			return nil
		}
		if supportedStandardPackage(pkg) {
			r.standard[pkg] = true
			return nil
		}
		if !strings.Contains(strings.Split(pkg, "/")[0], ".") {
			return ErrSource
		}
		locked := false
		for _, m := range r.descriptor.Modules {
			if pkg == m.Path || strings.HasPrefix(pkg, m.Path+"/") {
				locked = true
				break
			}
		}
		if !locked {
			return ErrSource
		}
	} else if importer != "" {
		return ErrSource
	} // reserved root is not a dependency
	if r.visited[pkg] == 1 {
		return ErrSource
	}
	if r.visited[pkg] == 2 {
		return nil
	}
	r.visited[pkg] = 1
	dir := path.Join(resolverGoPath, "src", pkg)
	entries, err := fs.ReadDir(r.view, dir)
	if err != nil {
		return ErrSource
	}
	packageName, count, checkCount := "", 0, 0
	for _, entry := range entries {
		if err := r.ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		ext := path.Ext(name)
		source := ext == ".go"
		native := slices.Contains([]string{".s", ".S", ".c", ".cc", ".cpp", ".cxx", ".m", ".h", ".f", ".F", ".syso", ".swig", ".swigcxx"}, ext)
		if !source && !native {
			continue
		}
		match, err := r.build.MatchFile(dir, name)
		if err != nil {
			return ErrSource
		}
		if !match {
			continue
		}
		if native {
			return ErrSource
		}
		full := path.Join(dir, name)
		data := r.all[full]
		if len(data) > maxGoFileBytes {
			return ErrSource
		}
		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, name, data, parser.ParseComments|parser.AllErrors|parser.SkipObjectResolution)
		if err != nil {
			return parserDiagnostic(err)
		}
		if !sourceDirectives(node) || node.Name.Name == "main" || packageName != "" && node.Name.Name != packageName {
			return sourceDiagnostic(fset.Position(node.Name.Pos()), "package name or source directive is not allowed")
		}
		packageName, count = node.Name.Name, count+1
		if pkg == checkerImport {
			if packageName != "checker" {
				return sourceDiagnostic(fset.Position(node.Name.Pos()), "source must use package checker")
			}
			for _, decl := range node.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "Check" {
					if !checkSignature(fn, node.Imports) {
						return sourceDiagnostic(fset.Position(fn.Name.Pos()), "Check must have the lifecycle SDK signature")
					}
					checkCount++
				}
			}
		}
		for _, spec := range node.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil || !importPath(imported, false) || spec.Name != nil && (spec.Name.Name == "." || spec.Name.Name == "_") {
				return importDiagnostic(fset.Position(spec.Pos()), imported)
			}
			if err := r.visit(imported, pkg); err != nil {
				var diagnostic sourceDiagnosticError
				if errors.As(err, &diagnostic) {
					return err
				}
				return importDiagnostic(fset.Position(spec.Pos()), imported)
			}
		}
		r.selected[full] = data
	}
	if count == 0 || pkg == checkerImport && checkCount != 1 {
		return sourceDiagnostic(token.Position{Line: 1, Column: 1}, "package checker must declare exactly one Check function")
	}
	r.visited[pkg] = 2
	return nil
}

func sourceDirectives(file *ast.File) bool {
	for _, group := range file.Comments {
		for _, c := range group.List {
			text := c.Text
			if strings.HasPrefix(text, "//go:build ") || strings.HasPrefix(text, "// +build ") {
				continue
			}
			if strings.HasPrefix(text, "//go:") || strings.HasPrefix(text, "//line ") || strings.HasPrefix(text, "/*line ") || strings.HasPrefix(text, "//yaegi:") {
				return false
			}
		}
	}
	return true
}

func checkSignature(fn *ast.FuncDecl, imports []*ast.ImportSpec) bool {
	if fn.Type.TypeParams != nil || fn.Type.Params == nil || fn.Type.Results == nil || len(fn.Type.Params.List) != 3 || len(fn.Type.Results.List) != 2 {
		return false
	}
	aliases := map[string]string{}
	for _, spec := range imports {
		p, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return false
		}
		alias := path.Base(p)
		if p == checkerSDK {
			alias = "lifecycle"
		}
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		aliases[alias] = p
	}
	selector := func(field *ast.Field, pkg, typ string) bool {
		if len(field.Names) > 1 {
			return false
		}
		s, ok := field.Type.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := s.X.(*ast.Ident)
		return ok && aliases[id.Name] == pkg && s.Sel.Name == typ
	}
	p, out := fn.Type.Params.List, fn.Type.Results.List
	e, ok := out[1].Type.(*ast.Ident)
	return selector(p[0], "context", "Context") && selector(p[1], checkerSDK, "Request") && selector(p[2], checkerSDK, "Probe") && selector(out[0], checkerSDK, "Result") && len(out[1].Names) <= 1 && ok && e.Name == "error"
}

// These are trusted native packages in both modes. All external source imports
// (including init code) still require an exact tenant allow and supplied lock.
func supportedStandardPackage(pkg string) bool {
	return slices.Contains([]string{"bytes", "context", "encoding/base64", "encoding/hex", "encoding/json", "errors", "fmt", "math", "math/bits", "net/url", "path", "sort", "strconv", "strings", "time", "unicode", "unicode/utf8"}, pkg)
}
