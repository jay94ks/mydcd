// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"testing"
)

func TestContextDefinitionKeepsPublicArgumentsAndVaultMountsSeparate(t *testing.T) {
	scope, _ := testScope(1, [32]byte{1})
	context := ContextSpec{Tenant: scope.Tenant, ID: scope.Context, Kind: "upload", Root: scope.Root, Dockerfile: "Dockerfile", Repository: "team/app", Tags: []string{"version-{version}"}, Platforms: []string{"linux/amd64"}, Arguments: map[string]string{"MODE": "release"}, Secrets: []SecretMount{{ID: "key", Realm: "tenant", Secret: "signing", Key: "private_key"}}}
	if err := context.Validate(); err != nil {
		t.Fatal(err)
	}
	global := context.Own()
	global.Secrets[0].Realm = ""
	if global.Validate() != nil {
		t.Fatal("cluster Vault reference rejected before its ACL check")
	}
	own := context.Own()
	own.Arguments["MODE"] = "changed"
	own.Secrets[0].Secret = "other"
	if context.Arguments["MODE"] != "release" || context.Secrets[0].Secret != "signing" {
		t.Fatal("mutable caller aliases public definition")
	}
	bad := context.Own()
	bad.Arguments["BUILDKIT_SYNTAX"] = "external/frontend"
	if bad.Validate() == nil {
		t.Fatal("builder frontend override accepted")
	}
	bad = context.Own()
	bad.Repository = "other.invalid/team/app:tag"
	if bad.Validate() == nil {
		t.Fatal("output bypasses selected managed registry")
	}
	bad = context.Own()
	bad.Secrets = append(bad.Secrets, bad.Secrets[0])
	if bad.Validate() == nil {
		t.Fatal("secret mount identity collision")
	}
	bad = context.Own()
	bad.Kind = "git"
	bad.Git = &GitContext{Repository: "https://username:password@example.test/repo.git", Ref: "main", Path: "."}
	if bad.Validate() == nil {
		t.Fatal("Git credentials entered public source")
	}
	bad.Git = &GitContext{Repository: "https://example.test/repo.git", Ref: "main", Path: ".", CredentialProfile: "repo-access"}
	if bad.Validate() != nil {
		t.Fatal("registered Git profile rejected")
	}
}
