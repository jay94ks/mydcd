// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/storage"
)

func engineIdentityProof(t *testing.T, cluster [32]byte, node, operation string, old, next *identity.Identity, index uint64) lifecycle.IdentityTransition {
	t.Helper()
	p := lifecycle.IdentityProof{Schema: 1, Cluster: cluster, Node: node, Operation: operation, Old: old.Public, New: next.Public, Prepared: [32]byte{1}}
	p.OldSignature = ed25519.Sign(old.Private, lifecycle.IdentityProofBytes(p))
	p.NewSignature = ed25519.Sign(next.Private, lifecycle.IdentityProofBytes(p))
	return lifecycle.IdentityTransition{Proof: p, Index: index, Revision: index}
}

func engineIdentityKey(t *testing.T) *identity.Identity {
	t.Helper()
	key, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(key.Private) })
	return key
}

func engineIdentityMesh(t *testing.T, key *identity.Identity, cluster [32]byte) *mydcp.Transport {
	t.Helper()
	mesh, err := mydcp.NewTransport(key, cluster, func(mydcp.Identity) (mydcp.Peer, bool) { return mydcp.Peer{}, false })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mesh.Close() })
	if err = mesh.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	return mesh
}

func TestEngineIdentityBindingValidatesCompleteCurrentLineageAndOwnsProofs(t *testing.T) {
	cluster := [32]byte{80}
	old, middle, next := engineIdentityKey(t), engineIdentityKey(t), engineIdentityKey(t)
	rows := []lifecycle.IdentityTransition{engineIdentityProof(t, cluster, "node", "rotate-one", old, middle, 10), engineIdentityProof(t, cluster, "node", "rotate-two", middle, next, 20)}
	o := Options{ID: "node", Cluster: cluster, Admin: "admin", Manifest: [32]byte{3}, Mesh: engineIdentityMesh(t, next, cluster), IdentityTransitions: rows}
	owned, err := ownEngineIdentity(o)
	if err != nil || !bytes.Equal(engineBinding(owned), engineBindingKey(o, mydcp.Identity(old.Public))) {
		t.Fatal("valid lineage did not preserve first binding", err)
	}
	rows[0].Proof.OldSignature[0]++
	rows[1].Proof.NewSignature[0]++
	rows[0].Proof.Old[0]++
	if !owned.IdentityTransitions[0].Proof.Valid() || !owned.IdentityTransitions[1].Proof.Valid() {
		t.Fatal("caller mutation aliases retained proof")
	}
}

func TestEngineIdentityBindingRejectsForgedIncompleteAndRegressingLineage(t *testing.T) {
	cluster := [32]byte{81}
	old, middle, next := engineIdentityKey(t), engineIdentityKey(t), engineIdentityKey(t)
	rows := []lifecycle.IdentityTransition{engineIdentityProof(t, cluster, "node", "rotate-one", old, middle, 10), engineIdentityProof(t, cluster, "node", "rotate-two", middle, next, 20)}
	base := Options{ID: "node", Cluster: cluster, Mesh: engineIdentityMesh(t, next, cluster), IdentityTransitions: rows}
	for name, change := range map[string]func(*Options){
		"old-signature": func(o *Options) { o.IdentityTransitions[0].Proof.OldSignature[0]++ },
		"new-signature": func(o *Options) { o.IdentityTransitions[1].Proof.NewSignature[0]++ },
		"node":          func(o *Options) { o.ID = "foreign" },
		"cluster":       func(o *Options) { o.Cluster[0]++ },
		"gap": func(o *Options) {
			o.IdentityTransitions[1] = engineIdentityProof(t, cluster, "node", "gap", old, next, 20)
		},
		"index":    func(o *Options) { o.IdentityTransitions[1].Index = 10 },
		"revision": func(o *Options) { o.IdentityTransitions[1].Revision = 10 },
		"cycle": func(o *Options) {
			o.IdentityTransitions[1] = engineIdentityProof(t, cluster, "node", "cycle", middle, old, 20)
		},
		"incomplete": func(o *Options) { o.IdentityTransitions = o.IdentityTransitions[:1] },
		"old-mesh":   func(o *Options) { o.Mesh = engineIdentityMesh(t, old, cluster) },
		"too-many": func(o *Options) {
			o.IdentityTransitions = append(o.IdentityTransitions, make([]lifecycle.IdentityTransition, 31)...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			o.IdentityTransitions = lifecycle.OwnIdentityTransitions(rows)
			change(&o)
			if _, err := ownEngineIdentity(o); err == nil {
				t.Fatal("invalid lineage selected a root identity")
			}
		})
	}
}

func TestEngineIdentityBindingReopensOriginalDBAndPreservesReceipt(t *testing.T) {
	f := newControlBoundary(t)
	command := f.enroll()
	original := f.call(command)
	before, err := f.engine.db.Get("binding")
	if err != nil {
		t.Fatal(err)
	}
	root := f.options.Root
	for i := 0; i < 2; i++ {
		old := f.node
		peer, _ := f.lookup(mydcp.Identity(old.Public))
		f.close()
		next := engineIdentityKey(t)
		f.options.IdentityTransitions = append(f.options.IdentityTransitions, engineIdentityProof(t, f.policy.Cluster, "node", []string{"rotation-one", "rotation-two"}[i], old, next, uint64(10+i)))
		f.mu.Lock()
		delete(f.peers, mydcp.Identity(old.Public))
		peer.Key = mydcp.Identity(next.Public)
		f.peers[peer.Key] = peer
		f.mu.Unlock()
		f.node = next
		f.start()
		after, err := f.engine.db.Get("binding")
		if err != nil || !bytes.Equal(before, after) || f.options.Root != root || f.call(command).Result != original.Result {
			t.Fatal("rotation rewrote binding/root/original receipt", err)
		}
	}
}

func TestEngineIdentityBindingRequiresExistingExactPolicyBinding(t *testing.T) {
	f := newControlBoundary(t)
	f.enroll()
	before, err := f.engine.db.Get("binding")
	if err != nil {
		t.Fatal(err)
	}
	f.close()
	next := engineIdentityKey(t)
	unrelated := engineIdentityKey(t)
	base := f.options
	base.Mesh = engineIdentityMesh(t, next, f.policy.Cluster)
	base.IdentityTransitions = []lifecycle.IdentityTransition{engineIdentityProof(t, base.Cluster, base.ID, "rotation", f.node, next, 10)}
	for name, change := range map[string]func(*Options){
		"missing-lineage": func(o *Options) { o.IdentityTransitions = nil },
		"different-original": func(o *Options) {
			o.IdentityTransitions = []lifecycle.IdentityTransition{engineIdentityProof(t, base.Cluster, base.ID, "unrelated-rotation", unrelated, next, 10)}
		},
		"missing-binding": func(o *Options) { o.Root = t.TempDir() },
		"admin":           func(o *Options) { o.Admin = next.Actor() },
		"manifest":        func(o *Options) { o.Manifest[0]++ },
		"module":          func(o *Options) { o.ModuleID[0]++ },
		"configuration":   func(o *Options) { o.TrackConfiguration = !o.TrackConfiguration },
		"mutation":        func(o *Options) { o.AdmitModule = f.policy.AdmitModule; o.AdmitMutation = f.policy.AdmitAppMutation },
		"patch":           func(o *Options) { o.AdmitModule = f.policy.AdmitModule; o.AdmitModulePatch = f.policy.AdmitAppPatch },
	} {
		t.Run(name, func(t *testing.T) {
			o := base
			change(&o)
			e, err := Open(o)
			if e != nil {
				_ = e.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "binding") && !strings.Contains(err.Error(), "identity/cluster mismatch") {
				t.Fatal("different/missing original binding admitted or wrong refusal", err)
			}
		})
	}
	db, err := storage.Open(filepath.Join(base.Root, "control", "fsm.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	after, err := db.Get("binding")
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refused reopen rewrote permanent binding", err)
	}
	// No-lineage Options keep exactly the old static identity/policy bytes.
	legacy := base
	legacy.IdentityTransitions = nil
	if !bytes.Equal(engineBinding(legacy), engineBindingKey(legacy, base.Mesh.LocalKey())) {
		t.Fatal("legacy empty-chain binding bytes changed")
	}
}
