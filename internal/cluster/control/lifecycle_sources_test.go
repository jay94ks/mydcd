// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func TestLifecycleEditorProviderAndExactHistoricalSourceUseCurrentAuthority(t *testing.T) {
	f := newCheckerFixture(t)
	f.apply("manager", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	fact := checkerFact(f, f.node, "package checker\n")
	limited := f.sessions["manager"]
	limited.Scopes = []access.Scope{{Tenant: "tenant", Actions: []access.Action{access.Read}}}
	limited.Signature = ed25519.Sign(f.node, access.SessionBytes(limited))
	selected, err := f.p.LifecycleProviderFor(f.s, f.sessions["manager"], 2, fact.Descriptor(), "", fact.Owner, false)
	if err != nil || selected.Node != "node-a" || selected.Owner != fact.Owner {
		t.Fatal(selected, err)
	}
	if _, err = f.p.LifecycleProviderFor(f.s, limited, 2, fact.Descriptor(), "node-a", fact.Owner, false); err == nil {
		t.Fatal("viewer staged source")
	}
	f.apply("manager", "put-lifecycle-script", 0, LifecycleScriptPut{Tenant: "tenant", Name: "editor", Source: fact}, state.Applied)
	q := LifecycleSourceQuery{Name: "editor", Revision: 1}
	read, err := f.p.LifecycleSourceVersion(f.s, f.sessions["manager"], 2, "tenant", q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.LifecycleSourceReadPermit(f.s, fact.Owner, read, 2); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*LifecycleSourceRead){func(r *LifecycleSourceRead) { r.Tenant = "other" }, func(r *LifecycleSourceRead) { r.Source.Digest[0] ^= 1 }, func(r *LifecycleSourceRead) { r.Query.Revision++ }, func(r *LifecycleSourceRead) { r.Epoch++ }} {
		copy := read
		change(&copy)
		if _, err = f.p.LifecycleSourceReadPermit(f.s, fact.Owner, copy, 2); err == nil {
			t.Fatal("foreign historical source proof")
		}
	}
	if _, err = f.p.LifecycleSourceVersion(f.s, limited, 2, "tenant", q); err == nil {
		t.Fatal("viewer read private source")
	}
	disabled := checkerPolicy()
	disabled.Enabled = false
	f.apply("manager", "set-lifecycle-policy", 1, disabled, state.Applied)
	if _, err = f.p.LifecycleProviderFor(f.s, f.sessions["manager"], 2, fact.Descriptor(), "node-a", fact.Owner, false); err == nil {
		t.Fatal("disabled policy admitted a new source")
	}
	if _, err = f.p.LifecycleProviderFor(f.s, f.sessions["manager"], 2, fact.Descriptor(), "node-a", fact.Owner, true); err != nil {
		t.Fatal("disabled policy hid original fact recovery", err)
	}
	if _, err = f.p.LifecycleSourceVersion(f.s, f.sessions["manager"], 2, "tenant", q); err != nil {
		t.Fatal("disabled policy hid a registered original", err)
	}
	f.apply("manager", "retire-lifecycle-script", 1, LifecycleScriptSelection{Tenant: "tenant", Name: "editor", Revision: 1}, state.Applied)
	if _, err = f.p.LifecycleSourceVersion(f.s, f.sessions["manager"], 2, "tenant", q); err != nil {
		t.Fatal("retired nondeleted version lost", err)
	}
	f.apply("manager", "delete-lifecycle-script", 2, LifecycleScriptSelection{Tenant: "tenant", Name: "editor", Revision: 1}, state.Applied)
	if _, err = f.p.LifecycleSourceVersion(f.s, f.sessions["manager"], 2, "tenant", q); !errors.Is(err, ErrLifecycleSourceMissing) {
		t.Fatal("deleted version advertised", err)
	}
}
