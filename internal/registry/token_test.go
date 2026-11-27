// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/jay94ks/seafield/internal/deployment"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/access"
)

func tokenGrantFixture() (Grant, ed25519.PrivateKey) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{71}, 32))
	return Grant{Cluster: [32]byte{1}, Tenant: "tenant", Registry: "private", Authority: "registry.example.test:5443", Repository: "team/app", Actions: []string{"pull"}, IssuedAt: 100, ExpiresAt: 160, Subject: Subject{Session: &access.Session{Schema: 1, Cluster: [32]byte{1}, User: "alice", Credential: "key", AccountRevision: 1, ExpiresAt: 200}}}, private
}

// Cryptographic scope/domain cases; the fake session is deliberately not a
// current account proof. Runtime's catalog verifier must check it separately.
func TestRegistryLoginAndAccessDomainsCannotSubstituteForEachOther(t *testing.T) {
	g, key := tokenGrantFixture()
	login, err := IssueLogin(g, key)
	if err != nil {
		t.Fatal(err)
	}
	secret := login.Bytes()
	defer clear(secret)
	parsed, err := ParseLogin(string(secret), 101)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Allows("team/app", "pull") || parsed.Allows("team/app", "push") || parsed.Allows("other/app", "pull") {
		t.Fatal("repo/action ceiling widened")
	}
	if _, err = ParseAccess(string(secret), 101); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("login used as HTTP access", err)
	}
	access, err := IssueAccess(parsed, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseLogin(access.Token, 101); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("access token used at login endpoint", err)
	}
	if _, err = ParseAccess(access.Token, 160); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired bearer", err)
	}
	if _, err = ParseAccess(access.Token, 99); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("future bearer", err)
	}
	bad := []byte(access.Token)
	bad[len(bad)/2] ^= 1
	if _, err = ParseAccess(string(bad), 101); err == nil {
		t.Fatal("tampered grant")
	}
	if fmt.Sprint(login) != "[redacted registry credential]" {
		t.Fatal("credential formatter leaks")
	}
	for _, change := range []func(*Grant){func(g *Grant) { g.Repository = "" }, func(g *Grant) { g.Actions = []string{"push", "pull"} }, func(g *Grant) { g.ExpiresAt = 401 }, func(g *Grant) { g.Subject.Session = nil }} {
		next := g
		change(&next)
		if _, err = IssueLogin(next, key); err == nil {
			t.Fatal("invalid grant issued")
		}
	}
}

func TestRegistryTokenScopeParsingRejectsAmbiguousOrMultipleAudiences(t *testing.T) {
	repo, actions, err := RequestedScope("repository:team/app:push,pull")
	if err != nil || repo != "team/app" || len(actions) != 2 || actions[0] != "pull" || actions[1] != "push" {
		t.Fatal(repo, actions, err)
	}
	for _, raw := range []string{"repository:**:pull", "repository:team/app:pull,pull", "repository:team/app:delete", "repository:team/app:pull repository:other:push", "repository:../app:pull", "registry:catalog:pull"} {
		if _, _, err = RequestedScope(raw); err == nil {
			t.Fatal("unsafe scope", raw)
		}
	}
}

// The product's Task grant carries no user session. The FSM separately checks
// the original accepted grant and current policy at issuance and each request.
func TestRegistryTaskCredentialCannotBecomeUserPushOrForeignImage(t *testing.T) {
	g, key := tokenGrantFixture()
	task := TaskSubject{Task: deployment.ObjectRef{Key: "workload/task/tenant/app/web", Revision: 7, Generation: 3}, Binding: [32]byte{2}, Node: [32]byte(key.Public().(ed25519.PublicKey)), Image: "registry.example.test:5443/team/app@sha256:" + strings.Repeat("a", 64)}
	g.Subject = Subject{Task: &task}
	login, err := IssueLogin(g, key)
	if err != nil {
		t.Fatal(err)
	}
	raw := login.Bytes()
	defer clear(raw)
	parsed, err := ParseLogin(string(raw), 101)
	if err != nil || parsed.Subject.Session != nil || *parsed.Subject.Task != task {
		t.Fatal("original Task provenance lost", err)
	}
	for name, mutate := range map[string]func(*Grant){
		"session-and-task":   func(g *Grant) { g.Subject.Session = &access.Session{Schema: 1, Cluster: g.Cluster, ExpiresAt: 200} },
		"push":               func(g *Grant) { g.Actions = []string{"push"} },
		"catalog":            func(g *Grant) { g.Repository = "**"; g.Actions = []string{"catalog"} },
		"foreign-repository": func(g *Grant) { g.Repository = "another/app" },
		"wildcard":           func(g *Grant) { g.Repository = "**" },
		"foreign-authority":  func(g *Grant) { g.Authority = "other.example.test:5443" },
	} {
		t.Run(name, func(t *testing.T) {
			next := g
			mutate(&next)
			if _, err := IssueLogin(next, key); err == nil {
				t.Fatal("Task ceiling widened")
			}
		})
	}
	root := parsed
	root.Repository = ""
	root.Actions = []string{"login"}
	access, err := IssueAccess(root, key)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := ParseAccess(access.Token, 101)
	if err != nil || !accepted.Allows("", "login") || accepted.Allows("team/app", "pull") {
		t.Fatal("root exchange acquired repository access", err)
	}
}
