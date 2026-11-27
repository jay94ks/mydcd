// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/hex"
	"slices"
	"unicode/utf8"

	contract "github.com/jay94ks/seafield/lifecycle/v1"
)

const (
	MaxScripts      = 128
	MaxScriptBytes  = 256 << 10
	MaxProgramBytes = 1 << 20
)

type NamedReference struct {
	Name     string `yaml:"name"`
	Revision uint64 `yaml:"revision"`
}

// ValidScriptName shares the catalog grammar with typed CLI selection. Node
// IDs use a different grammar and must not narrow an existing script's name.
func ValidScriptName(s string) bool { return name(s) }

type Script struct {
	Source  string          `yaml:"source,omitempty"`
	Ref     *NamedReference `yaml:"ref,omitempty"`
	Compile *bool           `yaml:"compile,omitempty"`
	Modules []ModulePin     `yaml:"modules,omitempty" json:",omitempty"`
}

// NamedSource is the current tenant catalog projection, not a fetched source
// or permission receipt. The policy adapter must authorize the original caller.
type NamedSource struct {
	Tenant string
	Ref    NamedReference
	Digest string
	SDK    uint8
	Active bool
}

type ScriptSelection struct {
	Source  string
	Ref     *NamedReference
	Digest  string
	Compile bool
}

// checkScripts checks declarations without inventing facts for unresolved
// named references. Catalog availability remains ResolveScripts' responsibility.
func checkScripts(scripts map[string]Script) error {
	if len(scripts) > MaxScripts {
		return ErrContract
	}
	total := 0
	for alias, script := range scripts {
		if !name(alias) || (script.Source != "") == (script.Ref != nil) || len(script.Source) > MaxScriptBytes || !utf8.ValidString(script.Source) {
			return ErrContract
		}
		if script.Ref != nil && (!name(script.Ref.Name) || script.Ref.Revision == 0) {
			return ErrReference
		}
		if len(script.Modules) > 64 || script.Ref != nil && len(script.Modules) != 0 {
			return ErrContract
		}
		for i, pin := range script.Modules {
			if !pin.valid() || pin.Length > MaxModuleBytes || i > 0 && script.Modules[i-1].Path >= pin.Path {
				return ErrContract
			}
		}
		total += len(script.Source)
		if total > MaxProgramBytes {
			return ErrContract
		}
	}
	return nil
}

// ResolveScripts freezes source selection and compile precedence. It does not
// fetch bytes, authorize a builder, prepare a runner or claim native readiness.
// Named references always include the exact revision; no latest/name fallback.
func ResolveScripts(tenant string, optimizer bool, scripts map[string]Script, named []NamedSource) (map[string]ScriptSelection, error) {
	if !name(tenant) || len(named) > 4096 {
		return nil, ErrContract
	}
	if err := checkScripts(scripts); err != nil {
		return nil, err
	}
	refs := map[NamedReference]NamedSource{}
	for _, source := range named {
		if source.Tenant != tenant || !name(source.Ref.Name) || source.Ref.Revision == 0 || !digest(source.Digest) || source.SDK != contract.Schema {
			return nil, ErrReference
		}
		if _, ok := refs[source.Ref]; ok {
			return nil, ErrReference
		}
		refs[source.Ref] = source
	}
	result := make(map[string]ScriptSelection, len(scripts))
	for alias, script := range scripts {
		selected := ScriptSelection{Source: script.Source, Compile: optimizer}
		if script.Compile != nil {
			selected.Compile = *script.Compile
		}
		if script.Ref != nil {
			current, ok := refs[*script.Ref]
			if !ok || !current.Active {
				return nil, ErrReference
			}
			r := *script.Ref
			selected.Ref, selected.Digest = &r, current.Digest
		} else {
			h := scriptContentDigest(script.Source, script.Modules)
			selected.Digest = hex.EncodeToString(h[:])
		}
		result[alias] = selected
	}
	return result, nil
}

// Descriptor freezes an inline declaration's root and explicit full lock.
// Named scripts use the catalog's signed descriptor and cannot override it.
func (s Script) Descriptor(tenant string) (SourceDescriptor, error) {
	if s.Ref != nil || checkScripts(map[string]Script{"inline": s}) != nil {
		return SourceDescriptor{}, ErrContract
	}
	d := SourceDescriptor{Tenant: tenant, Digest: inlineRootDigest(s.Source), Length: uint64(len(s.Source)), SDK: contract.Schema, Modules: slices.Clone(s.Modules)}
	if err := d.Validate(); err != nil {
		return SourceDescriptor{}, err
	}
	return d, nil
}
