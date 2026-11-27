// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/deployment"
)

func TestInstalledGitCredentialKeepsTenantRepositoryAndPrivateFileBoundary(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "git-token")
	if err := os.WriteFile(file, []byte("private-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := config.GitCredential{Tenant: "tenant", Profile: "reader", Repository: "https://git.sfc.test/team/app.git", Username: "git-reader", PasswordFile: file}
	access, err := installedGitAccess(p)
	if err != nil || !bytes.Equal(access.Password, []byte("private-token")) {
		t.Fatal("installed original credential", err)
	}
	clear(access.Password)
	clear(access.Username)
	if err = os.Chmod(file, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = installedGitAccess(p); err == nil {
		t.Fatal("public password file accepted")
	}
	if err = os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err = os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	linked := p
	linked.PasswordFile = link
	if _, err = installedGitAccess(linked); err == nil {
		t.Fatal("password symlink accepted")
	}
	c := config.Node{GitCredentials: []config.GitCredential{p}}
	r := &Runtime{}
	if err = r.openGit(c); err != nil {
		t.Fatal(err)
	}
	var policy deployment.DeliveryDeclaration
	policy.Enabled, policy.Source.Kind, policy.Source.Repository, policy.Source.Credential = true, "git", p.Repository, p.Profile
	// Refuse at installation mapping, before any remote request or fallback.
	if _, err = r.fetchGit(context.Background(), "other", policy, deployment.DeliveryFetch{}); err != deployment.ErrSource {
		t.Fatal("foreign tenant profile", err)
	}
	policy.Source.Repository = "https://git.sfc.test/another/app.git"
	if _, err = r.fetchGit(context.Background(), "tenant", policy, deployment.DeliveryFetch{}); err != deployment.ErrSource {
		t.Fatal("credential widened to another repository", err)
	}
	c.GitCredentials = append(c.GitCredentials, p)
	if err = r.openGit(c); err == nil {
		t.Fatal("duplicate tenant profile accepted")
	}
	public, err := json.Marshal(p)
	if err != nil || bytes.Contains(public, []byte("private-token")) {
		t.Fatal("private material entered installed metadata", err)
	}
}
