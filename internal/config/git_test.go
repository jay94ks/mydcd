// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstalledGitProfileRejectsCredentialURLAndNonHTTPS(t *testing.T) {
	p := GitCredential{Tenant: "default", Profile: "git-read", Repository: "https://git.mydc.test/team/app.git", Username: "reader", PasswordFile: "/installed/git/password"}
	if err := p.Validate(); err != nil {
		t.Fatal("default is a valid remote tenant name, not a profile link selection", err)
	}
	for _, repository := range []string{"http://git.mydc.test/app.git", "file:///private/app.git", "https://user:password@git.mydc.test/app.git", "https://git.mydc.test/app.git?", "https://git.mydc.test/app.git?token=private", "https://git.mydc.test/app.git#main"} {
		bad := p
		bad.Repository = repository
		if bad.Validate() == nil {
			t.Fatal("unsafe installed repository accepted", repository)
		}
	}
}

func TestNodeGitProfilesResolveOnlyInstalledRelativePaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "node.yaml")
	raw := []byte(`version: 1
node:
  id: local
  state_dir: state
  identity_dir: keys
  listen: 127.0.0.1:7443
modules:
  network: {enabled: false}
  workload: {enabled: false}
  ingress: {enabled: false}
git_credentials:
  - tenant: default
    profile: git-read
    repository: https://git.mydc.test/team/app.git
    username: reader
    password_file: private/token
    ca_file: installed/ca.pem
`)
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadNode(file)
	if err != nil || len(c.GitCredentials) != 1 {
		t.Fatal("installed source profile config", err)
	}
	p := c.GitCredentials[0]
	if p.PasswordFile != filepath.Join(root, "private/token") || p.CAFile != filepath.Join(root, "installed/ca.pem") || p.Repository != "https://git.mydc.test/team/app.git" {
		t.Fatal("installed relative paths or exact repository changed", p)
	}
	// Loading config must not require opening the secret/provider/network.
	if _, err := os.Stat(p.PasswordFile); !os.IsNotExist(err) {
		t.Fatal("config unexpectedly provisioned a credential", err)
	}
}
