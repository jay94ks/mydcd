// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

// Uses the real identity/source reducers and restore codecs. Configuration
// observations are modeled by rotateRQ9CoreOwner; this is no TLS/native proof.
func TestLifecycleRetainedVersionAfterRotationUsesCurrentProviderAndSigner(t *testing.T) {
	f := newBackupCore(t)
	f.session.Scopes[0].Actions = append(f.session.Scopes[0].Actions, access.ManageServices)
	f.session.Signature = ed25519.Sign(f.node, access.SessionBytes(f.session))
	f.apply("lifecycle-policy", "set-lifecycle-policy", 0, checkerPolicy(), state.Applied)
	text := []byte("package checker\n")
	fact := checker.SourceFact{Schema: 1, Cluster: f.p.Cluster, Owner: f.p.TrustRoot, Tenant: "tenant", SDK: 1, Digest: sha256.Sum256(text), Length: uint64(len(text))}
	fact.Signature = ed25519.Sign(f.node, checker.SourceFactBytes(fact))
	f.apply("lifecycle-original", "put-lifecycle-script", 0, LifecycleScriptPut{Tenant: "tenant", Name: "original", Source: fact}, state.Applied)
	oldRead, err := f.p.LifecycleSourceVersion(f.s, f.session, 2, "tenant", LifecycleSourceQuery{Name: "original", Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	next := rotateRQ9CoreOwner(t, f)
	current := [32]byte(next.Public().(ed25519.PublicKey))
	raw, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = state.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	read, err := f.p.LifecycleSourceVersion(f.s, f.session, 3, "tenant", oldRead.Query)
	if err != nil || read.Source.Owner != fact.Owner || !bytes.Equal(read.Source.Signature, fact.Signature) {
		t.Fatal("retained source changed", err)
	}
	if _, err = f.p.LifecycleSourceReadPermit(f.s, current, read, 3); err != nil {
		t.Fatal("current signer cannot read original", err)
	}
	if _, err = f.p.LifecycleSourceReadPermit(f.s, fact.Owner, read, 3); err == nil {
		t.Fatal("historic key authenticated")
	}
	selected, err := f.p.LifecycleProviderFor(f.s, f.session, 3, fact.Descriptor(), "node-a", fact.Owner, false)
	if err != nil || selected.Owner != current {
		t.Fatal("new editor chose historic signer", selected, err)
	}
	// An old valid fact can be read as its exact registered version, but cannot
	// be published as a new version after its signing identity has retired.
	f.apply("lifecycle-old-republish", "put-lifecycle-script", 1, LifecycleScriptPut{Tenant: "tenant", Name: "original", Source: fact}, state.Forbidden)
	changed := read
	changed.Source.Owner = current
	if _, err = f.p.LifecycleSourceReadPermit(f.s, current, changed, 3); err == nil {
		t.Fatal("substituted current owner for original proof")
	}
	disabled := checkerPolicy()
	disabled.Enabled = false
	f.apply("lifecycle-disabled", "set-lifecycle-policy", 1, disabled, state.Applied)
	if _, err = f.p.LifecycleProviderFor(f.s, f.session, 3, fact.Descriptor(), "node-a", current, false); err == nil {
		t.Fatal("disabled editor admitted new work")
	}
	if _, err = f.p.LifecycleSourceVersion(f.s, f.session, 3, "tenant", oldRead.Query); err != nil {
		t.Fatal("policy change erased retained version", err)
	}
}
