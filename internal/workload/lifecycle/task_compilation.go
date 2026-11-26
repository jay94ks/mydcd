// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"context"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
)

// A sealed plan must cover every compiled content in the exact Task, and no
// interpreted/foreign content. A subset cannot authorize native activation.
func (p TaskCompilePlan) ValidateProgram(program TaskProgram) error {
	if program.Validate(program.Cluster) != nil {
		return ErrPreparation
	}
	expected := map[[32]byte]bool{}
	for alias, script := range program.Scripts {
		if script.Compile {
			expected[program.Sources[alias].ContentDigest()] = true
		}
	}
	if len(expected) == 0 || len(p.Recipes) != len(expected) {
		return ErrPreparation
	}
	image, err := access.PinImage(program.Policy.Build.Image)
	if err != nil {
		return ErrPreparation
	}
	seen := map[[32]byte]bool{}
	for _, r := range p.Recipes {
		if r.Validate() != nil || r.Tenant != program.Tenant || !expected[r.Source] || seen[r.Source] || r.Image != image.Reference || r.Toolchain != program.Policy.Build.Toolchain || !slices.Contains(program.Policy.Build.Targets, r.GOOS+"/"+r.GOARCH) {
			return ErrPreparation
		}
		seen[r.Source] = true
	}
	return nil
}

// TaskCompilations uses the actual sealed source producer for each distinct
// compile=true input. It does not build, allocate a job, or claim cache/Ready.
func (m *SourceStore) TaskCompilations(ctx context.Context, p TaskProgram, current TenantPolicy, target ResolverTarget) ([]*Compilation, error) {
	if p.Validate(m.identity.Cluster) != nil || current.Validate() != nil || current.Tenant != p.Tenant || !current.Enabled {
		return nil, ErrSource
	}
	aliases := make([]string, 0, len(p.Scripts))
	for alias, s := range p.Scripts {
		if s.Compile {
			aliases = append(aliases, alias)
		}
	}
	slices.Sort(aliases)
	seen := map[[32]byte]bool{}
	var inputs []*Compilation
	var total uint64
	files := 0
	for _, alias := range aliases {
		fact := p.Sources[alias]
		content := fact.ContentDigest()
		if seen[content] {
			continue
		}
		seen[content] = true
		source, err := m.Resolve(ctx, fact.Descriptor(), current, target)
		if err != nil {
			return nil, err
		}
		input, err := PrepareCompilation(source)
		if err != nil {
			return nil, err
		}
		files += len(input.item.Files)
		if files > MaxCompileFiles {
			return nil, ErrSource
		}
		for _, file := range input.item.Files {
			limit := min(uint64(MaxCompileInputBytes), current.Build.WorkspaceBytes)
			if total > limit || file.Length > limit-total {
				return nil, ErrSource
			}
			total += file.Length
		}
		inputs = append(inputs, input)
	}
	slices.SortFunc(inputs, func(a, b *Compilation) int { return bytes.Compare(a.item.Recipe.Source[:], b.item.Recipe.Source[:]) })
	return inputs, nil
}

// CompileSelection preserves the exact named/inline aliases of only the
// missing compiled contents. It never widens an interpreted alias to a build.
func (p TaskProgram) CompileSelection(missing []BuildInput) (Selection, error) {
	if p.Validate(p.Cluster) != nil || len(missing) == 0 || len(missing) > MaxScripts {
		return Selection{}, ErrReference
	}
	want := map[[32]byte]bool{}
	for _, input := range missing {
		if input.Content == ([32]byte{}) || input.Recipe == ([32]byte{}) || want[input.Content] {
			return Selection{}, ErrReference
		}
		want[input.Content] = true
	}
	refs := map[NamedReference]bool{}
	facts := map[[32]byte]SourceFact{}
	found := map[[32]byte]bool{}
	for alias, script := range p.Scripts {
		fact := p.Sources[alias]
		content := fact.ContentDigest()
		if !script.Compile || !want[content] {
			continue
		}
		found[content] = true
		if script.Ref != nil {
			refs[*script.Ref] = true
		} else {
			facts[content] = fact.Clone()
		}
	}
	if len(found) != len(want) {
		return Selection{}, ErrReference
	}
	s := Selection{PolicyRevision: p.Policy.Revision}
	for ref := range refs {
		s.Scripts = append(s.Scripts, ref)
	}
	for _, fact := range facts {
		s.Sources = append(s.Sources, fact)
	}
	slices.SortFunc(s.Scripts, func(a, b NamedReference) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		if a.Revision < b.Revision {
			return -1
		}
		if a.Revision > b.Revision {
			return 1
		}
		return 0
	})
	slices.SortFunc(s.Sources, func(a, b SourceFact) int {
		x, y := a.ContentDigest(), b.ContentDigest()
		return bytes.Compare(x[:], y[:])
	})
	return s, s.Validate()
}

// CachedTaskCompilePlan consumes only existing local source/compiled bytes.
// It never allocates a compiler job or extends any preparation deadline.
func (m *SourceStore) CachedTaskCompilePlan(ctx context.Context, p TaskProgram, current TenantPolicy, target ResolverTarget) (TaskCompilePlan, error) {
	inputs, err := m.TaskCompilations(ctx, p, current, target)
	if err != nil {
		return TaskCompilePlan{}, err
	}
	plan := TaskCompilePlan{}
	for _, input := range inputs {
		recipe := input.Item().Recipe
		fact, data, err := m.CompiledArtifact(ctx, p.Tenant, recipe.Key())
		clear(data)
		if err != nil {
			return TaskCompilePlan{}, err
		}
		if fact.Build.Recipe.Key() != recipe.Key() {
			return TaskCompilePlan{}, ErrPreparation
		}
		plan.Recipes = append(plan.Recipes, recipe)
	}
	if err := plan.ValidateProgram(p); err != nil {
		return TaskCompilePlan{}, err
	}
	return plan, nil
}
