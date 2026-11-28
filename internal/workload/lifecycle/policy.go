// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/json"
	"go/version"
	"math"
	"path"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
)

type BuildPolicy struct {
	Nodes, Targets                []string
	Image, Toolchain              string
	MaxJobs                       int
	NanoCPU, MemoryBytes          int64
	WorkspaceBytes, ArtifactBytes uint64
	TimeoutMS                     int64
}

type ExecutionPolicy struct {
	MaxConcurrent           int
	TimeoutMS               int64
	NanoCPU, MemoryBytes    int64
	MaxPIDs                 int64
	OutputBytes, ProbeBytes int
	Capabilities            []string
}

type ResolverPolicy struct {
	AllowPackages, DenyPackages []string
	Modules                     []ModulePin
	SourceCacheBytes            uint64
}

type TenantPolicy struct {
	Tenant             string
	Revision           uint64
	Enabled            bool
	Build              BuildPolicy
	Execution          ExecutionPolicy
	Resolver           ResolverPolicy
	CompiledCacheBytes uint64
}

func sortedNames(values []string, limit int) bool {
	if len(values) > limit {
		return false
	}
	for i, v := range values {
		if !name(v) || i > 0 && values[i-1] >= v {
			return false
		}
	}
	return true
}

func importPath(p string, pattern bool) bool {
	if pattern {
		p = strings.TrimSuffix(p, "/...")
	}
	return text(p, 256) && p != "." && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, ".") && path.Clean(p) == p && !strings.ContainsAny(p, "\\ @:*?#")
}

func packageRules(values []string, pattern bool) bool {
	if len(values) > 256 {
		return false
	}
	for i, p := range values {
		if !importPath(p, pattern) || i > 0 && values[i-1] >= p {
			return false
		}
	}
	return true
}

func (p TenantPolicy) Validate() error {
	// A query exposes one policy or one SourceFact per bounded SFCP page.
	// Keep the same metadata budget at admission, including all module locks.
	if raw, err := json.Marshal(p); err != nil || len(raw) > 24<<10 {
		return ErrContract
	}
	e, b, r := p.Execution, p.Build, p.Resolver
	if !name(p.Tenant) || p.Revision == 0 || e.MaxConcurrent < 1 || e.MaxConcurrent > 128 || e.TimeoutMS < 1 || e.NanoCPU < 1 || e.MemoryBytes < 16<<20 || e.MaxPIDs < 1 || e.MaxPIDs > 1024 || e.OutputBytes < 1 || e.OutputBytes > 1<<20 || e.ProbeBytes < 1 || e.ProbeBytes > 1<<20 || !sortedNames(e.Capabilities, 5) || len(e.Capabilities) == 0 || !packageRules(r.AllowPackages, false) || !packageRules(r.DenyPackages, true) || r.SourceCacheBytes < MaxScriptBytes || r.SourceCacheBytes > math.MaxInt64 || p.CompiledCacheBytes > math.MaxInt64 || len(r.Modules) > 64 {
		return ErrContract
	}
	for _, c := range e.Capabilities {
		if c != "connect" && c != "dependency" && c != "exec" && c != "file" && c != "healthz" {
			return ErrContract
		}
	}
	for i, m := range r.Modules {
		if !m.valid() || i > 0 && r.Modules[i-1].Path >= m.Path {
			return ErrContract
		}
	}
	if len(b.Nodes) == 0 {
		if b.Image != "" || b.Toolchain != "" || len(b.Targets) != 0 || b.MaxJobs != 0 || b.NanoCPU != 0 || b.MemoryBytes != 0 || b.WorkspaceBytes != 0 || b.ArtifactBytes != 0 || b.TimeoutMS != 0 {
			return ErrContract
		}
		return nil // explicitly interpreted-only policy, no inferred builder
	}
	if !sortedNames(b.Nodes, 128) || len(b.Targets) == 0 || len(b.Targets) > 2 || !version.IsValid(b.Toolchain) || !strings.HasPrefix(b.Toolchain, "go1.") || b.MaxJobs < 1 || b.MaxJobs > 128 || b.NanoCPU < 1 || b.MemoryBytes < 32<<20 || b.WorkspaceBytes == 0 || b.WorkspaceBytes > math.MaxInt64 || b.ArtifactBytes == 0 || b.ArtifactBytes > b.WorkspaceBytes || b.TimeoutMS < 1 || p.CompiledCacheBytes < b.ArtifactBytes {
		return ErrContract
	}
	// A tag or a digest: a tag is resolved once per deploy, never pinned here.
	if _, err := access.ParseImage(b.Image); err != nil {
		return ErrContract
	}
	for i, target := range b.Targets {
		if target != "linux/amd64" && target != "linux/arm64" || i > 0 && b.Targets[i-1] >= target {
			return ErrContract
		}
	}
	return nil
}

// AllowsCompiler reports whether image (repo@sha256:…) may run this policy's
// compilers: the policy's own reference, resolved for one deploy to a digest
// of the same repository. A digest policy allows only itself.
func (b BuildPolicy) AllowsCompiler(image string) bool {
	policy, err := access.ParseImage(b.Image)
	if err != nil {
		return false
	}
	pinned, err := access.PinImage(image)
	if err != nil || pinned.Reference != image || pinned.Registry != policy.Registry || pinned.Repository != policy.Repository {
		return false
	}
	return !policy.Pinned() || pinned.Reference == policy.Reference
}

// CompilerTag is the policy's compiler image when it names a tag, normalized;
// "" for a digest policy or no build policy.
func (b BuildPolicy) CompilerTag() string {
	policy, err := access.ParseImage(b.Image)
	if err != nil || policy.Pinned() {
		return ""
	}
	return policy.Reference
}

func (p TenantPolicy) Clone() TenantPolicy {
	p.Build.Nodes = slices.Clone(p.Build.Nodes)
	p.Build.Targets = slices.Clone(p.Build.Targets)
	p.Execution.Capabilities = slices.Clone(p.Execution.Capabilities)
	p.Resolver.AllowPackages = slices.Clone(p.Resolver.AllowPackages)
	p.Resolver.DenyPackages = slices.Clone(p.Resolver.DenyPackages)
	p.Resolver.Modules = slices.Clone(p.Resolver.Modules)
	return p
}

func (p TenantPolicy) AllowsPackage(pkg string) bool {
	if p.Validate() != nil || !p.Enabled || !importPath(pkg, false) {
		return false
	}
	for _, denied := range []string{"unsafe", "syscall", "plugin", "os", "net/http", "net/rpc", "net/smtp", "runtime/cgo"} {
		if pkg == denied || strings.HasPrefix(pkg, denied+"/") {
			return false
		}
	}
	if pkg == "net" {
		return false
	}
	for _, denied := range p.Resolver.DenyPackages {
		prefix, subtree := strings.CutSuffix(denied, "/...")
		if pkg == denied || subtree && (pkg == prefix || strings.HasPrefix(pkg, prefix+"/")) {
			return false
		}
	}
	return slices.Contains(p.Resolver.AllowPackages, pkg)
}

func (p TenantPolicy) AllowsSource(f SourceFact) bool {
	return f.Verify() == nil && p.AllowsDescriptor(f.Descriptor())
}

func (p TenantPolicy) AllowsDescriptor(f SourceDescriptor) bool {
	if !p.Enabled || p.Validate() != nil || f.Validate() != nil || f.Tenant != p.Tenant {
		return false
	}
	total := f.Length
	for _, m := range f.Modules {
		if !slices.Contains(p.Resolver.Modules, m) || total > p.Resolver.SourceCacheBytes || m.Length > p.Resolver.SourceCacheBytes-total {
			return false
		}
		total += m.Length
	}
	return total <= p.Resolver.SourceCacheBytes
}
