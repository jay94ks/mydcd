// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/deployment"
)

func TestBuildRegistrySubjectDoesNotBorrowSessionOrTaskAndPreservesTokenCeiling(t *testing.T) {
	g, key := tokenGrantFixture()
	subject := BuildSubject{Tenant: g.Tenant, Job: "build-one", Snapshot: [32]byte{2}, Node: [32]byte(key.Public().(ed25519.PublicKey))}
	g.Subject = Subject{Build: &subject}
	g.Actions = []string{"pull", "push"}
	login, err := IssueLogin(g, key)
	if err != nil {
		t.Fatal(err)
	}
	secret := login.Bytes()
	defer clear(secret)
	parsed, err := ParseLogin(string(secret), 101)
	if err != nil || parsed.Subject.Build == nil || *parsed.Subject.Build != subject || parsed.Subject.Session != nil || parsed.Subject.Task != nil {
		t.Fatal(parsed.Subject, err)
	}
	if !parsed.Allows("team/app", "push") || parsed.Allows("other/app", "push") || parsed.Allows("**", "catalog") {
		t.Fatal("build repository ceiling broadened")
	}
	// Registry-owner access tokens have a different issuer from the builder.
	registryKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32)))
	token, err := IssueAccess(parsed, registryKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseAccess(token.Token, 101); err != nil || *got.Subject.Build != subject || got.Issuer == subject.Node {
		t.Fatal("access issuer replaced execution provenance", err)
	}
	for _, edit := range []func(*Grant){
		func(g *Grant) { g.Subject.Session = &access.Session{Schema: 1, Cluster: g.Cluster, ExpiresAt: 200} },
		func(g *Grant) { g.Subject.Task = &TaskSubject{Task: deployment.ObjectRef{Key: "invented"}} },
		func(g *Grant) { g.Repository = "**"; g.Actions = []string{"catalog"} },
		func(g *Grant) { s := subject; s.Snapshot = [32]byte{}; g.Subject.Build = &s },
	} {
		bad := g
		edit(&bad)
		if _, err := IssueLogin(bad, key); err == nil {
			t.Fatal("mixed/invalid build token accepted")
		}
	}
	image := g.Authority + "/team/app@sha256:" + strings.Repeat("a", 64)
	subject.Image = image
	g.Subject = Subject{Build: &subject}
	g.Actions = []string{"pull"}
	if _, err := IssueLogin(g, key); err != nil {
		t.Fatal(err)
	}
	g.Actions = []string{"pull", "push"}
	if _, err := IssueLogin(g, key); err == nil {
		t.Fatal("base-image read became push authority")
	}
}
