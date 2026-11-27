// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// FrozenProgram contains the accepted normalization and signed source facts,
// not source bytes, a cache hit or permission to start a native checker. The
// declaration remains in the application artifact and is checked on restore.
type FrozenProgram struct {
	Schema  uint8
	Cluster [32]byte
	Tenant  string
	Policy  TenantPolicy
	Program ResolvedProgram
	Sources map[string]SourceFact // declaration alias -> exact immutable source
}

func (f FrozenProgram) Clone() FrozenProgram {
	f.Policy = f.Policy.Clone()
	f.Program = ownResolvedProgram(f.Program)
	f.Sources = ownSourceAliases(f.Sources)
	return f
}

func ownSourceAliases(in map[string]SourceFact) map[string]SourceFact {
	if in == nil {
		return nil
	}
	out := make(map[string]SourceFact, len(in))
	for alias, fact := range in {
		out[alias] = fact.Clone()
	}
	return out
}

func ownResolvedProgram(in ResolvedProgram) ResolvedProgram {
	// All fields are bounded JSON value types. This also owns nested typed
	// probe parameters and named reference pointers at this storage boundary.
	raw, _ := json.Marshal(in)
	var out ResolvedProgram
	_ = json.Unmarshal(raw, &out)
	return out
}

func (f FrozenProgram) Digest() [32]byte {
	raw, _ := json.Marshal(f)
	return sha256.Sum256(append([]byte("sfc-checker-program-1\x00"), raw...))
}

// FreezeProgram selects only the CURRENT active named versions and policy.
// Inline facts come from actual staging outside the deterministic planner.
// There is no fabricated signature, provider or latest/version fallback.
func FreezeProgram(tenant string, p Program, catalog Catalog, inline map[string]SourceFact, defaults Timing) (FrozenProgram, error) {
	policy, ok := catalog.Policy(tenant, 0)
	if !ok || !policy.Enabled {
		return FrozenProgram{}, ErrReference
	}
	if err := checkScripts(p.Scripts); err != nil {
		return FrozenProgram{}, err
	}
	facts := make(map[string]SourceFact, len(p.Scripts))
	used := 0
	for alias, script := range p.Scripts {
		if script.Ref == nil {
			fact, ok := inline[alias]
			if !ok {
				return FrozenProgram{}, ErrReference
			}
			used++
			facts[alias] = fact.Clone()
		} else {
			v, ok := catalog.version(tenant, *script.Ref)
			if !ok || !v.Active || v.Deleted {
				return FrozenProgram{}, ErrReference
			}
			facts[alias] = v.Source.Clone()
		}
		if facts[alias].Cluster != catalog.Cluster() {
			return FrozenProgram{}, ErrReference
		}
	}
	if used != len(inline) {
		return FrozenProgram{}, ErrReference
	}
	return freezeAcceptedProgram(catalog.Cluster(), tenant, p, policy, facts, defaults)
}

// freezeAcceptedProgram checks original structural provenance. It deliberately
// does not manufacture a current catalog/Active bit for historical sources.
func freezeAcceptedProgram(cluster [32]byte, tenant string, p Program, policy TenantPolicy, facts map[string]SourceFact, defaults Timing) (FrozenProgram, error) {
	if cluster == ([32]byte{}) || !name(tenant) || policy.Tenant != tenant || policy.Validate() != nil || !policy.Enabled || len(facts) != len(p.Scripts) {
		return FrozenProgram{}, ErrContract
	}
	if err := checkScripts(p.Scripts); err != nil {
		return FrozenProgram{}, err
	}
	resolved, err := resolveProgramChecks(p, defaults, policy.Execution.TimeoutMS)
	if err != nil {
		return FrozenProgram{}, err
	}
	resolved.Scripts = make(map[string]ScriptSelection, len(p.Scripts))
	for alias, script := range p.Scripts {
		fact, ok := facts[alias]
		if !ok || fact.Cluster != cluster || !policy.AllowsSource(fact) {
			return FrozenProgram{}, ErrReference
		}
		selected := ScriptSelection{Compile: p.Compile}
		if script.Compile != nil {
			selected.Compile = *script.Compile
		}
		if selected.Compile && len(policy.Build.Nodes) == 0 {
			return FrozenProgram{}, ErrReference
		}
		if script.Ref != nil {
			r := *script.Ref
			selected.Ref = &r
		} else if fact.Digest != sha256.Sum256([]byte(script.Source)) || fact.Length != uint64(len(script.Source)) || !slices.Equal(fact.Modules, script.Modules) {
			return FrozenProgram{}, ErrReference
		}
		// The content key binds the actual staged full dependency lock, including
		// inline scripts. Raw source stays in the declaration, not a second copy.
		content := fact.ContentDigest()
		selected.Digest = hex.EncodeToString(content[:])
		resolved.Scripts[alias] = selected
	}
	return FrozenProgram{Schema: 1, Cluster: cluster, Tenant: tenant, Policy: policy.Clone(), Program: resolved, Sources: ownSourceAliases(facts)}, nil
}

// Validate checks this ORIGINAL program against its declaration without
// consulting today's policy or resurrecting retired named versions. Adapters
// must check current authority separately for acceptance and every native use.
func (f FrozenProgram) Validate(p Program, cluster [32]byte, defaults Timing) error {
	if f.Schema != 1 || f.Cluster != cluster || cluster == ([32]byte{}) {
		return ErrContract
	}
	for _, fact := range f.Sources {
		if fact.Cluster != cluster {
			return ErrReference
		}
	}
	expected, err := freezeAcceptedProgram(cluster, f.Tenant, p, f.Policy, f.Sources, defaults)
	if err != nil {
		return err
	}
	actualRaw, err := json.Marshal(f)
	expectedRaw, expectedErr := json.Marshal(expected)
	if err != nil || expectedErr != nil || !bytes.Equal(actualRaw, expectedRaw) {
		return ErrContract
	}
	return nil
}

// ValidateCatalog ties historical named facts and the original policy revision
// to the actual stored catalog. Retirement/disable do not rewrite provenance.
func (f FrozenProgram) ValidateCatalog(c Catalog) error {
	if f.Schema != 1 {
		return ErrReference
	}
	return validateProgramCatalog(f.Cluster, f.Tenant, f.Policy, f.Program.Scripts, f.Sources, c)
}

func validateProgramCatalog(cluster [32]byte, tenant string, original TenantPolicy, scripts map[string]ScriptSelection, sources map[string]SourceFact, c Catalog) error {
	if cluster != c.Cluster() {
		return ErrReference
	}
	policy, ok := c.Policy(tenant, original.Revision)
	if !ok {
		return ErrReference
	}
	a, _ := json.Marshal(policy)
	b, _ := json.Marshal(original)
	if !bytes.Equal(a, b) {
		return ErrReference
	}
	for alias, selected := range scripts {
		fact, ok := sources[alias]
		if !ok || fact.Cluster != c.Cluster() {
			return ErrReference
		}
		if selected.Ref != nil {
			version, ok := c.version(tenant, *selected.Ref)
			if !ok || !sameSourceFact(fact, version.Source) {
				return ErrReference
			}
		}
	}
	return nil
}

func selectProgramSources(checks []ResolvedCheck, scripts map[string]ScriptSelection, sources map[string]SourceFact, policyRevision uint64) (*Selection, error) {
	aliases := map[string]bool{}
	for _, check := range checks {
		if check.Script != "" {
			aliases[check.Script] = true
		}
	}
	if len(aliases) == 0 {
		return nil, nil
	}
	selection := Selection{PolicyRevision: policyRevision}
	refs := map[NamedReference]bool{}
	facts := map[[32]byte]SourceFact{}
	for alias := range aliases {
		script, ok := scripts[alias]
		fact, found := sources[alias]
		if !ok || !found || fact.Verify() != nil {
			return nil, ErrReference
		}
		content := fact.ContentDigest()
		if script.Digest != hex.EncodeToString(content[:]) {
			return nil, ErrReference
		}
		if script.Ref != nil {
			refs[*script.Ref] = true
		} else {
			if old, exists := facts[content]; exists && !sameSourceFact(old, fact) {
				return nil, ErrReference
			}
			facts[content] = fact
		}
	}
	for ref := range refs {
		selection.Scripts = append(selection.Scripts, ref)
	}
	slices.SortFunc(selection.Scripts, func(a, b NamedReference) int {
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
	for _, fact := range facts {
		selection.Sources = append(selection.Sources, fact.Clone())
	}
	slices.SortFunc(selection.Sources, func(a, b SourceFact) int {
		x, y := a.ContentDigest(), b.ContentDigest()
		return bytes.Compare(x[:], y[:])
	})
	if err := selection.Validate(); err != nil {
		return nil, err
	}
	return &selection, nil
}

func sameSourceFact(a, b SourceFact) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
