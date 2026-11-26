// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestCheckerSourceUsesExactTenantRevisionAndCompileOverride(t *testing.T) {
	no, yes := false, true
	ref := NamedReference{Name: "ready-file", Revision: 3}
	named := []NamedSource{{Tenant: "tenant", Ref: ref, Digest: hashText("ready-file-source"), SDK: 1, Active: true}}
	scripts := map[string]Script{
		"inline": {Source: "package checker\n"},
		"named":  {Ref: &ref, Compile: &no},
		"force":  {Source: "package checker\n", Compile: &yes},
	}
	selected, err := ResolveScripts("tenant", true, scripts, named)
	if err != nil || !selected["inline"].Compile || selected["named"].Compile || selected["named"].Ref.Revision != 3 || selected["named"].Digest != hashText("ready-file-source") || !selected["force"].Compile {
		t.Fatal("compile precedence or frozen reference", selected, err)
	}
	ref.Revision++
	no = true
	if selected["named"].Ref.Revision != 3 || selected["named"].Compile {
		t.Fatal("caller mutated original selection")
	}
	selected, err = ResolveScripts("tenant", false, map[string]Script{"inline": {Source: "package checker\n"}, "force": {Source: "package checker\n", Compile: &yes}}, nil)
	if err != nil || selected["inline"].Compile || !selected["force"].Compile {
		t.Fatal("false default and true override", err)
	}
}

func TestCheckerInlineModulesAreExplicitImmutableAndCannotOverrideNamed(t *testing.T) {
	module := ModulePin{Path: "example.invalid/checker", Version: "v1.0.0", Digest: [32]byte{3}, Length: 1024}
	script := Script{Source: "package checker\n", Modules: []ModulePin{module}}
	d, err := script.Descriptor("tenant")
	if err != nil || len(d.Modules) != 1 {
		t.Fatal("declared lock descriptor", err)
	}
	resolved, err := ResolveScripts("tenant", false, map[string]Script{"inline": script}, nil)
	content := d.ContentDigest()
	if err != nil || resolved["inline"].Digest != hex.EncodeToString(content[:]) || content == inlineContentDigest(script.Source) {
		t.Fatal("declared lock omitted from inline selection", err)
	}
	script.Modules[0].Digest[0]++
	if d.Modules[0].Digest != module.Digest {
		t.Fatal("descriptor aliases raw declaration")
	}
	for _, invalid := range []Script{
		{Ref: &NamedReference{Name: "named", Revision: 1}, Modules: []ModulePin{module}},
		{Source: script.Source, Modules: []ModulePin{module, module}},
		{Source: script.Source, Modules: []ModulePin{{Path: module.Path, Version: module.Version, Digest: module.Digest, Length: MaxModuleBytes + 1}}},
	} {
		if _, err := invalid.Descriptor("tenant"); err == nil {
			t.Fatal("ambiguous or unsupported inline lock")
		}
	}
}

func TestCheckerNamedSourceNeverFallsBackToOtherTenantRevisionOrMode(t *testing.T) {
	ref := NamedReference{Name: "ready-file", Revision: 3}
	good := NamedSource{Tenant: "tenant", Ref: ref, Digest: hashText("ready-file-source"), SDK: 1, Active: true}
	for _, named := range [][]NamedSource{
		nil,
		{{Tenant: "other", Ref: ref, Digest: good.Digest, SDK: 1, Active: true}},
		{{Tenant: "tenant", Ref: NamedReference{Name: ref.Name, Revision: 4}, Digest: good.Digest, SDK: 1, Active: true}},
		{{Tenant: "tenant", Ref: ref, Digest: good.Digest, SDK: 1, Active: false}},
		{{Tenant: "tenant", Ref: ref, Digest: good.Digest, SDK: 2, Active: true}},
		{good, good},
	} {
		original := map[string]Script{"ref": {Ref: &ref}}
		before := ref
		if got, err := ResolveScripts("tenant", true, original, named); err == nil || got != nil || !reflect.DeepEqual(ref, before) {
			t.Fatal("missing/revoked reference adopted or mutated", got, err)
		}
	}
	for _, script := range []Script{{}, {Source: "package checker", Ref: &ref}} {
		if _, err := ResolveScripts("tenant", true, map[string]Script{"invalid": script}, []NamedSource{good}); err == nil {
			t.Fatal("ambiguous source/ref accepted")
		}
	}
}
