// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"context"
	"strings"
)

// PrepareBuild reconstructs the accepted batch from verified local source and
// exact module locks using the SAME resolver/SDK/compiler source producer.
// It fetches nothing, changes no policy/job, and authorizes no native effect.
func (m *SourceStore) PrepareBuild(ctx context.Context, b BuildIntent, p TenantPolicy, facts []SourceFact) (CompileBatch, []*Compilation, error) {
	if ctx == nil || b.Validate() != nil || b.Cluster != m.identity.Cluster || p.Validate() != nil || p.Tenant != b.Tenant || p.Revision != b.Selection.PolicyRevision || len(facts) != len(b.Inputs) {
		return CompileBatch{}, nil, ErrSource
	}
	sources := make(map[[32]byte]SourceFact, len(facts))
	for _, f := range facts {
		if f.Verify() != nil || f.Cluster != b.Cluster || f.Tenant != b.Tenant || !p.AllowsSource(f) {
			return CompileBatch{}, nil, ErrSource
		}
		key := f.ContentDigest()
		if _, ok := sources[key]; ok {
			return CompileBatch{}, nil, ErrSource
		}
		sources[key] = f.Clone()
	}
	goos, goarch, _ := strings.Cut(b.Target, "/")
	target := ResolverTarget{GOOS: goos, GOARCH: goarch, Toolchain: p.Build.Toolchain}
	inputs := make([]*Compilation, 0, len(b.Inputs))
	var total uint64
	files := 0
	for _, input := range b.Inputs {
		fact, ok := sources[input.Content]
		if !ok {
			return CompileBatch{}, nil, ErrReference
		}
		source, err := m.Resolve(ctx, fact.Descriptor(), p, target)
		if err != nil {
			return CompileBatch{}, nil, err
		}
		compiled, err := PrepareCompilation(source)
		if err != nil {
			return CompileBatch{}, nil, err
		}
		if compiled.item.Key != input.Recipe {
			return CompileBatch{}, nil, ErrSource
		}
		files += len(compiled.item.Files)
		if files > MaxCompileFiles {
			return CompileBatch{}, nil, ErrSource
		}
		for _, file := range compiled.item.Files {
			limit := min(uint64(MaxCompileInputBytes), p.Build.WorkspaceBytes)
			if total > limit || file.Length > limit-total {
				return CompileBatch{}, nil, ErrSource
			}
			total += file.Length
		}
		inputs = append(inputs, compiled)
	}
	batch, err := NewCompileBatch(b.ID, b.DeadlineUnixMilli, p, inputs)
	if err != nil {
		return CompileBatch{}, nil, err
	}
	if err := b.ValidateCompilation(p, batch); err != nil {
		return CompileBatch{}, nil, err
	}
	return batch, inputs, nil
}
