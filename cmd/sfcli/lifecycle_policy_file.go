// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/cli"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// lifecyclePolicyFile is lifecycle-policy.yaml: the tenant's limits for
// building and running lifecycle scripts. Sizes are written like 512MiB,
// times like 30s, CPU in cores (0.5). A limit left out (or 0) is unset;
// the server says which ones the policy needs.
type lifecyclePolicyFile struct {
	Version int  `yaml:"version"`
	Enabled bool `yaml:"enabled"`
	// Build is left out for a policy that only interprets scripts; with
	// nodes it compiles them there and every build limit is needed.
	Build struct {
		Nodes     []string `yaml:"nodes,omitempty"`
		Targets   []string `yaml:"targets,omitempty"`
		Image     string   `yaml:"image,omitempty"`
		Toolchain string   `yaml:"toolchain,omitempty"`
		MaxJobs   int      `yaml:"max_jobs,omitempty"`
		CPU       float64  `yaml:"cpu,omitempty"`
		Memory    string   `yaml:"memory,omitempty"`
		Workspace string   `yaml:"workspace,omitempty"`
		Artifact  string   `yaml:"artifact,omitempty"`
		Timeout   string   `yaml:"timeout,omitempty"`
	} `yaml:"build,omitempty"`
	Execution struct {
		MaxConcurrent int      `yaml:"max_concurrent"`
		Timeout       string   `yaml:"timeout"`
		CPU           float64  `yaml:"cpu"`
		Memory        string   `yaml:"memory"`
		MaxPIDs       int64    `yaml:"max_pids"`
		Output        string   `yaml:"output"`
		Probe         string   `yaml:"probe"`
		Capabilities  []string `yaml:"capabilities,omitempty"`
	} `yaml:"execution"`
	Resolver struct {
		Allow       []string     `yaml:"allow_packages,omitempty"`
		Deny        []string     `yaml:"deny_packages,omitempty"`
		Modules     []moduleLock `yaml:"modules,omitempty"`
		SourceCache string       `yaml:"source_cache"`
	} `yaml:"resolver"`
	CompiledCache string `yaml:"compiled_cache,omitempty"`
}

type policyReader struct{ err error }

func (r *policyReader) size(name, text string) uint64 {
	if r.err != nil || text == "" {
		return 0
	}
	v, err := cli.ParseSize(text)
	if err != nil {
		r.err = fmt.Errorf("%s: %w", name, err)
	}
	return uint64(v)
}

func (r *policyReader) millis(name, text string) int64 {
	if r.err != nil {
		return 0
	}
	if text == "" {
		return 0
	}
	v, err := time.ParseDuration(text)
	if err != nil || v < 0 {
		r.err = fmt.Errorf("%s must be a time such as 30s", name)
	}
	return v.Milliseconds()
}

func (r *policyReader) cpu(name string, cores float64) int64 {
	if r.err == nil && (cores < 0 || cores > 1024 || math.IsNaN(cores)) {
		r.err = fmt.Errorf("%s must be a number of cores such as 0.5", name)
	}
	return int64(math.Round(cores * 1e9))
}

// policy converts the file for tenant; the server checks the limits.
func (f lifecyclePolicyFile) policy(tenant string) (checker.TenantPolicy, error) {
	if f.Version != 1 {
		return checker.TenantPolicy{}, errors.New("the first line must be 'version: 1'")
	}
	var r policyReader
	p := checker.TenantPolicy{Tenant: tenant, Enabled: f.Enabled}
	b := f.Build
	p.Build = checker.BuildPolicy{Nodes: b.Nodes, Targets: b.Targets, Image: b.Image, Toolchain: b.Toolchain, MaxJobs: b.MaxJobs, NanoCPU: r.cpu("build.cpu", b.CPU), MemoryBytes: int64(r.size("build.memory", b.Memory)), WorkspaceBytes: r.size("build.workspace", b.Workspace), ArtifactBytes: r.size("build.artifact", b.Artifact), TimeoutMS: r.millis("build.timeout", b.Timeout)}
	e := f.Execution
	p.Execution = checker.ExecutionPolicy{MaxConcurrent: e.MaxConcurrent, TimeoutMS: r.millis("execution.timeout", e.Timeout), NanoCPU: r.cpu("execution.cpu", e.CPU), MemoryBytes: int64(r.size("execution.memory", e.Memory)), MaxPIDs: e.MaxPIDs, OutputBytes: int(r.size("execution.output", e.Output)), ProbeBytes: int(r.size("execution.probe", e.Probe)), Capabilities: e.Capabilities}
	p.Resolver = checker.ResolverPolicy{AllowPackages: f.Resolver.Allow, DenyPackages: f.Resolver.Deny, SourceCacheBytes: r.size("resolver.source_cache", f.Resolver.SourceCache)}
	for _, l := range f.Resolver.Modules {
		raw, err := hex.DecodeString(l.SHA256)
		if err != nil || len(raw) != 32 {
			return p, fmt.Errorf("resolver.modules: %s needs sha256 as 64 hex characters", l.Path)
		}
		pin := checker.ModulePin{Path: l.Path, Version: l.Version, Length: l.Size}
		copy(pin.Digest[:], raw)
		p.Resolver.Modules = append(p.Resolver.Modules, pin)
	}
	p.CompiledCacheBytes = r.size("compiled_cache", f.CompiledCache)
	if r.err != nil {
		return p, r.err
	}
	// The server gives the policy its revision; check the rest here.
	check := p
	check.Revision = 1
	if err := check.Validate(); err != nil {
		return p, fmt.Errorf("the policy is not valid: %w", err)
	}
	return p, nil
}

// writeLifecyclePolicy prints a stored policy as lifecycle-policy.yaml.
func writeLifecyclePolicy(w io.Writer, p checker.TenantPolicy) error {
	var f lifecyclePolicyFile
	f.Version, f.Enabled = 1, p.Enabled
	ms := func(v int64) string { return (time.Duration(v) * time.Millisecond).String() }
	size := func(v uint64) string { return cli.Size(v).String() }
	if b := p.Build; len(b.Nodes) != 0 {
		f.Build.Nodes, f.Build.Targets, f.Build.Image, f.Build.Toolchain, f.Build.MaxJobs = b.Nodes, b.Targets, b.Image, b.Toolchain, b.MaxJobs
		f.Build.CPU, f.Build.Memory, f.Build.Workspace, f.Build.Artifact, f.Build.Timeout = float64(b.NanoCPU)/1e9, size(uint64(b.MemoryBytes)), size(b.WorkspaceBytes), size(b.ArtifactBytes), ms(b.TimeoutMS)
	}
	e := p.Execution
	f.Execution.MaxConcurrent, f.Execution.Timeout, f.Execution.CPU, f.Execution.Memory = e.MaxConcurrent, ms(e.TimeoutMS), float64(e.NanoCPU)/1e9, size(uint64(e.MemoryBytes))
	f.Execution.MaxPIDs, f.Execution.Output, f.Execution.Probe, f.Execution.Capabilities = e.MaxPIDs, size(uint64(e.OutputBytes)), size(uint64(e.ProbeBytes)), e.Capabilities
	f.Resolver.Allow, f.Resolver.Deny, f.Resolver.SourceCache = p.Resolver.AllowPackages, p.Resolver.DenyPackages, size(p.Resolver.SourceCacheBytes)
	for _, m := range p.Resolver.Modules {
		f.Resolver.Modules = append(f.Resolver.Modules, moduleLock{Path: m.Path, Version: m.Version, SHA256: hex.EncodeToString(m.Digest[:]), Size: m.Length})
	}
	if p.CompiledCacheBytes != 0 {
		f.CompiledCache = size(p.CompiledCacheBytes)
	}
	fmt.Fprintf(w, "# tenant %s, revision %d\n", p.Tenant, p.Revision)
	e2 := yaml.NewEncoder(w)
	e2.SetIndent(2)
	if err := e2.Encode(f); err != nil {
		return err
	}
	return e2.Close()
}
