// SPDX-License-Identifier: Apache-2.0

package imagesource

import (
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func TestSourceMatchesOnlyExactAuthorityAndRepositoryScope(t *testing.T) {
	image, err := access.PinImage("ghcr.io/team/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	source := Source{Tenant: "tenant", ID: "ghcr", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	var last int
	for _, pattern := range []string{"**", "team/**", "team/app"} {
		source.Repository = pattern
		score, ok := source.Match(image)
		if !ok || score <= last {
			t.Fatal("non-deterministic specificity", pattern, score, ok)
		}
		last = score
	}
	for _, pattern := range []string{"other/**", "tea/**", "team", "team/app/child", "team/ap"} {
		source.Repository = pattern
		if _, ok := source.Match(image); ok {
			t.Fatal("wrong repository", pattern)
		}
	}
	source.Repository = "**"
	for _, authority := range []string{"other.example", "ghcr.io:443", "ghcr.io.attacker.example"} {
		source.Authority = authority
		if _, ok := source.Match(image); ok {
			t.Fatal("credential crossed registry authority", authority)
		}
	}
}

func TestSourceContainsOnlyScopedReferencesAndOwnsCopies(t *testing.T) {
	base := Source{Tenant: "tenant", ID: "private", Authority: "registry.example", Repository: "team/**", Enabled: true, Auth: "token", Credential: &Credential{Realm: "tenant", ID: "login", UsernameKey: "username", PasswordKey: "token"}, CA: &CertificateAuthority{Realm: "tenant", ID: "roots", Key: "ca.pem"}}
	if base.Validate() != nil {
		t.Fatal("valid reference rejected")
	}
	copy := Own(base)
	if !Equal(base, copy) {
		t.Fatal("copy differs")
	}
	copy.Credential.PasswordKey = "other"
	copy.CA.Key = "other"
	if Equal(base, copy) || base.Credential.PasswordKey != "token" || base.CA.Key != "ca.pem" {
		t.Fatal("credential/CA reference alias")
	}
	for _, mutate := range []func(*Source){
		func(s *Source) { s.Credential.Realm = "foreign" },
		func(s *Source) { s.CA.Realm = "foreign" },
		func(s *Source) { s.Credential.PasswordKey = ".." },
		func(s *Source) { s.Credential.UsernameKey = s.Credential.PasswordKey },
		func(s *Source) { s.Authority = "https://registry.example" },
		func(s *Source) { s.Authority = "index.docker.io" },
		func(s *Source) { s.Repository = "team/*/app" },
		func(s *Source) { s.Repository = "../team" },
		func(s *Source) { s.Auth = "none" },
		func(s *Source) { s.Auth = "ecr" },
	} {
		s := Own(base)
		mutate(&s)
		if s.Validate() == nil {
			t.Fatalf("invalid public definition accepted: %#v", s)
		}
	}
}

func TestClusterSourceIsOwnedByClusterRealmAndLosesToWorkspaceSource(t *testing.T) {
	image, err := access.PinImage("ghcr.io/team/app@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	cluster := Source{ID: "ghcr", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "token", Credential: &Credential{ID: "login", UsernameKey: "username", PasswordKey: "token"}}
	if cluster.Validate() != nil || !cluster.Cluster() || cluster.Key() != "/ghcr" {
		t.Fatal("cluster-owned source rejected", cluster.Validate())
	}
	foreign := Own(cluster)
	foreign.Credential.Realm = "tenant"
	if foreign.Validate() == nil {
		t.Fatal("cluster source referenced a workspace realm")
	}
	defs := []Definition{{Spec: cluster}}
	got, err := Lookup(defs, "tenant", image)
	if err != nil || got == nil || got.Spec.ID != "ghcr" {
		t.Fatal("workspace without its own source did not use the cluster source", got, err)
	}
	if got, err = Lookup(defs, "", image); err != nil || got == nil || got.Spec.ID != "ghcr" {
		t.Fatal("cluster lookup", got, err)
	}
	// A workspace's own match wins even when it is broader than the cluster's.
	own := Source{Tenant: "tenant", ID: "mine", Authority: "ghcr.io", Repository: "**", Enabled: true, Auth: "none"}
	narrow := Own(cluster)
	narrow.Repository = "team/app"
	defs = []Definition{{Spec: narrow}, {Spec: own}}
	if got, err = Lookup(defs, "tenant", image); err != nil || got == nil || got.Spec.ID != "mine" {
		t.Fatal("cluster source beat the workspace source", got, err)
	}
	if got, err = Lookup(defs, "other", image); err != nil || got == nil || got.Spec.ID != "ghcr" {
		t.Fatal("another workspace saw a foreign source", got, err)
	}
	// A revoked workspace source still blocks: it never falls back to the cluster.
	defs = []Definition{{Spec: narrow}, {Spec: own, Deleted: true}}
	if _, err = Select(defs, "tenant", image); err == nil {
		t.Fatal("revoked workspace source fell back to the cluster source")
	}
}
