// SPDX-License-Identifier: Apache-2.0

package app

import (
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Simulated signed facts/current request. Exercises the production metadata
// check, not quorum, physical availability or actual member stream delivery.
func TestCheckerCacheObservationMatchesOnlyOriginalProviderUseAndRecipe(t *testing.T) {
	source, fact, _, _ := checkerArtifactMetadataFixture(t)
	q := control.CheckerArtifactRequest{Schema: 1, Tenant: source.Tenant, UseID: "original-app", Use: [32]byte{7}, Content: source.ContentDigest(), Consumer: [32]byte{8}, MinimumIndex: 2, Lookup: &control.CheckerCacheLookup{Provider: fact.Owner, Recipe: fact.Build.Recipe}}
	v := checkerCacheObservation{Schema: 1, Cluster: source.Cluster, Provider: fact.Owner, Use: q.Use, Content: q.Content, Recipe: fact.Build.Recipe.Key(), Index: 2, Found: true, Fact: &fact, CanBuild: true}
	if checkerCacheObservationAllowed(v, q, source.Cluster) != nil {
		t.Fatal("exact signed cache observation")
	}
	for label, change := range map[string]func(*checkerCacheObservation){
		"schema":         func(v *checkerCacheObservation) { v.Schema = 2 },
		"cluster":        func(v *checkerCacheObservation) { v.Cluster[0]++ },
		"provider":       func(v *checkerCacheObservation) { v.Provider[0]++ },
		"use":            func(v *checkerCacheObservation) { v.Use[0]++ },
		"content":        func(v *checkerCacheObservation) { v.Content[0]++ },
		"recipe":         func(v *checkerCacheObservation) { v.Recipe[0]++ },
		"stale-index":    func(v *checkerCacheObservation) { v.Index = 1 },
		"missing-fact":   func(v *checkerCacheObservation) { v.Fact = nil },
		"fact-as-miss":   func(v *checkerCacheObservation) { v.Found = false },
		"unsigned-cache": func(v *checkerCacheObservation) { f := v.Fact.Clone(); f.Signature[0]++; v.Fact = &f },
	} {
		t.Run(label, func(t *testing.T) {
			changed := v
			change(&changed)
			if checkerCacheObservationAllowed(changed, q, source.Cluster) == nil {
				t.Fatal("changed cache observation accepted")
			}
		})
	}
	missing := v
	missing.Found = false
	missing.Fact = nil
	if checkerCacheObservationAllowed(missing, q, source.Cluster) != nil {
		t.Fatal("well-formed explicit negative metadata")
	}
	missing.Index = 0
	if checkerCacheObservationAllowed(missing, q, source.Cluster) == nil {
		t.Fatal("response absence used as miss")
	}
	other := q
	other.Lookup = nil
	if checkerCacheObservationAllowed(v, other, source.Cluster) == nil {
		t.Fatal("root request widened to cache lookup")
	}
}
