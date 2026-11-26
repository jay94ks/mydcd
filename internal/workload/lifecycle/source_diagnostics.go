// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"go/version"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxSourceDiagnostics = 32

type SourceDiagnostic struct {
	Line, Column int
	Message      string
}

func (d SourceDiagnostic) Valid() bool {
	return d.Line >= 0 && d.Column >= 0 && (d.Line == 0) == (d.Column == 0) && len(d.Message) > 0 && len(d.Message) <= 1024 && utf8.ValidString(d.Message) && !strings.ContainsAny(d.Message, "\x00\r\n")
}

type sourceDiagnosticError struct{ diagnostic SourceDiagnostic }

func (e sourceDiagnosticError) Error() string { return "lifecycle source rejected" }
func (e sourceDiagnosticError) Unwrap() error { return ErrSource }
func sourceDiagnostic(position token.Position, message string) error {
	if len(message) > 1024 {
		message = message[:1024]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	message = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, message)
	line, column := position.Line, position.Column
	if line < 1 || column < 1 {
		line, column = 0, 0
	}
	return sourceDiagnosticError{SourceDiagnostic{line, column, message}}
}
func sourceDiagnostics(err error) []SourceDiagnostic {
	var diagnostic sourceDiagnosticError
	if errors.As(err, &diagnostic) {
		return []SourceDiagnostic{diagnostic.diagnostic}
	}
	return []SourceDiagnostic{{Message: "source does not satisfy the selected resolver policy or module lock"}}
}

// ValidateSource never stages a fact or executes user initialization/functions.
// It consumes exact cached ZIPs and the same ResolveSource graph as execution.
func (m *SourceStore) ValidateSource(ctx context.Context, d SourceDescriptor, data []byte, p TenantPolicy) ([]SourceDiagnostic, error) {
	if m == nil || m.editor == nil || ctx == nil || d.Validate() != nil || !p.AllowsDescriptor(d) {
		return nil, ErrSource
	}
	select {
	case m.editor <- struct{}{}:
		defer func() { <-m.editor }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	archives := make([]ModuleArchive, 0, len(d.Modules))
	defer func() {
		for _, archive := range archives {
			clear(archive.ZIP)
		}
	}()
	for _, pin := range d.Modules {
		_, raw, err := m.ModuleArtifact(ctx, d.Tenant, pin)
		if err != nil {
			return nil, err
		}
		archives = append(archives, ModuleArchive{Pin: pin, ZIP: raw})
	}
	source, err := ResolveSource(ctx, p, d, data, archives, ResolverTarget{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Toolchain: runtime.Version()})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return sourceDiagnostics(err), nil
	}
	return CheckSourceTypes(ctx, source)
}

// CheckSourceTypes uses the compiled-in SDK/Yaegi whitelist type metadata.
// Neither a Go toolchain/GOROOT nor module downloads are needed on the node.
func CheckSourceTypes(ctx context.Context, source *ResolvedSource) (diagnostics []SourceDiagnostic, err error) {
	if ctx == nil || source == nil || source.files == nil {
		return nil, ErrSource
	}
	defer func() {
		if recover() != nil {
			diagnostics = nil
			err = ErrSource
		}
	}()
	importer := newSourceTypeImporter(ctx, source)
	_, err = importer.Import(checkerImport)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(importer.diagnostics) > 0 {
		return importer.diagnostics, nil
	}
	if err != nil {
		return []SourceDiagnostic{{Message: "type checking failed for the selected source graph"}}, nil
	}
	return nil, nil
}

type sourceTypeImporter struct {
	ctx         context.Context
	source      *ResolvedSource
	fset        *token.FileSet
	native      *nativeTypeImporter
	packages    map[string]*types.Package
	loading     map[string]bool
	diagnostics []SourceDiagnostic
}

func newSourceTypeImporter(ctx context.Context, source *ResolvedSource) *sourceTypeImporter {
	return &sourceTypeImporter{ctx: ctx, source: source, fset: token.NewFileSet(), native: newNativeTypeImporter(), packages: map[string]*types.Package{}, loading: map[string]bool{}}
}
func (i *sourceTypeImporter) Import(pkg string) (*types.Package, error) {
	if err := i.ctx.Err(); err != nil {
		return nil, err
	}
	if known := i.packages[pkg]; known != nil {
		return known, nil
	}
	if pkg == checkerSDK || supportedStandardPackage(pkg) {
		return i.native.Import(pkg)
	}
	if i.loading[pkg] {
		return nil, ErrSource
	}
	i.loading[pkg] = true
	defer delete(i.loading, pkg)
	var names []string
	prefix := path.Join(resolverGoPath, "src", pkg) + "/"
	for name := range i.source.files.files {
		if strings.HasPrefix(name, prefix) && !strings.Contains(strings.TrimPrefix(name, prefix), "/") && strings.HasSuffix(name, ".go") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	if len(names) == 0 {
		return nil, ErrSource
	}
	files := make([]*ast.File, 0, len(names))
	for _, name := range names {
		file, err := parser.ParseFile(i.fset, name, i.source.files.files[name], parser.AllErrors|parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	config := types.Config{Importer: i, GoVersion: version.Lang(i.source.target.Toolchain), Sizes: types.SizesFor("gc", i.source.target.GOARCH), Error: func(err error) {
		if len(i.diagnostics) >= MaxSourceDiagnostics {
			return
		}
		if typed, ok := err.(types.Error); ok {
			diagnostic := sourceDiagnostics(sourceDiagnostic(i.fset.Position(typed.Pos), typed.Msg))[0]
			i.diagnostics = append(i.diagnostics, diagnostic)
		}
	}}
	result, err := config.Check(pkg, i.fset, files, nil)
	if err != nil {
		return nil, err
	}
	if pkg == checkerImport {
		sdk, err := i.native.Import(checkerSDK)
		if err != nil {
			return nil, err
		}
		check := result.Scope().Lookup("Check")
		// The syntax gate also checks this declaration, but a source-level
		// error alias must not replace the builtin error in the SDK signature.
		if check == nil || !types.Identical(check.Type(), sdk.Scope().Lookup("Checker").Type().Underlying()) {
			pos := token.NoPos
			if check != nil {
				pos = check.Pos()
			}
			i.diagnostics = append(i.diagnostics, sourceDiagnostics(sourceDiagnostic(i.fset.Position(pos), "Check must have the lifecycle SDK signature"))[0])
			return nil, ErrSource
		}
	}
	i.packages[pkg] = result
	return result, nil
}

func parserDiagnostic(err error) error {
	var list scanner.ErrorList
	if errors.As(err, &list) && len(list) > 0 {
		return sourceDiagnostic(list[0].Pos, list[0].Msg)
	}
	return sourceDiagnostic(token.Position{}, "invalid Go syntax")
}
func importDiagnostic(position token.Position, imported string) error {
	return sourceDiagnostic(position, "import is not allowed or not available in the locked module graph: "+strconv.Quote(imported))
}
