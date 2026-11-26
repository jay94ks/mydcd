// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cli"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// TestImageCommandsAgainstManagedNode runs whole registry, image and build
// commands (flags, session, reads, refusals) against a managed node.
func TestImageCommandsAgainstManagedNode(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(admin.Private) })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	m := newManagedNode(t, ctx, root, "node", admin)
	m.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	if r := m.Change("t1", "create-tenant", 0, control.TenantID{ID: "shop"}); r.Code != state.Applied {
		t.Fatal("create tenant", r)
	}
	s := managedSession(t, m, home)
	t.Setenv("MYDC_NONINTERACTIVE", "1")
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, diag bytes.Buffer
		g := &globals{session: s}
		code := cli.Execute(newRoot(g), append([]string{"--tenant", "shop"}, args...), cli.Env{Context: ctx, In: strings.NewReader(""), Out: &out, Err: &diag})
		return code, strings.TrimSpace(out.String()), diag.String()
	}
	for _, args := range [][]string{
		{"registry", "list", "-o", "json"},
		{"build", "list", "-o", "json"},
		{"build", "context", "list", "-o", "json"},
		{"build", "cache", "list", "-o", "json"},
	} {
		if code, out, diag := run(args...); code != 0 || out != "[]" {
			t.Fatalf("%v: code %d out %q err %q", args, code, out, diag)
		}
	}
	if code, _, diag := run("build", "policy", "show"); code != 1 || !strings.Contains(diag, "no build policy") {
		t.Fatalf("policy show without a policy: %d %q", code, diag)
	}
	file := filepath.Join(root, "build-context.yaml")
	if err = os.WriteFile(file, []byte("version: 1\nkind: upload\nnode: node\nrepository: shop/web\ntags: [latest]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := run("build", "context", "create", "web", "-f", file); code != 1 || !strings.Contains(diag, "no build policy") {
		t.Fatalf("context create without a policy: %d %q", code, diag)
	}
	if code, _, diag := run("build", "context", "show", "web"); code != 1 || !strings.Contains(diag, "no build context") {
		t.Fatalf("missing context: %d %q", code, diag)
	}
	if code, _, diag := run("build", "show", "nope"); code != 1 || !strings.Contains(diag, "no build") {
		t.Fatalf("missing build: %d %q", code, diag)
	}
	if err = os.WriteFile(file, []byte("version: 1\nkind: upload\nnodes: node\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, diag := run("build", "context", "create", "web", "-f", file); code != 1 || !strings.Contains(diag, "nodes") {
		t.Fatalf("unknown field accepted: %d %q", code, diag)
	}
	for _, args := range [][]string{
		{"build", "run"},
		{"build", "context", "cat", "web", "../x"},
		{"build", "draft", "mv", "web", "a"},
		{"build", "context", "create", "web"},
		{"registry", "show"},
		{"image", "delete", "reg"},
	} {
		if code, _, diag := run(args...); code != 2 {
			t.Fatalf("%v: code %d, want usage error; err %q", args, code, diag)
		}
	}
}

func TestBuildContextFileRoundTrip(t *testing.T) {
	sp := imagebuild.ContextSpec{Tenant: "shop", ID: "web", Kind: "git", Root: nodestorage.Reference{Node: "node-a"}, Dockerfile: "Dockerfile",
		Arguments: map[string]string{"A": "b"}, Secrets: []imagebuild.SecretMount{{ID: "npm", Realm: "shop", Secret: "npm-token", Key: "token"}},
		Repository: "shop/web", Tags: []string{"latest"}, Platforms: []string{"linux/amd64"},
		Git: &imagebuild.GitContext{Repository: "https://git.example/web.git", Ref: "main", CredentialProfile: "git-read", Automatic: true}}
	raw, err := yaml.Marshal(contextFileOf(sp))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"kind: git", "node: node-a", "credential_profile: git-read", "secret: npm-token"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %q in\n%s", want, raw)
		}
	}
	path := filepath.Join(t.TempDir(), "c.yaml")
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var back buildContextFile
	if err = readYAMLFile(path, 64<<10, &back); err != nil || back.Git == nil || back.Git.Ref != "main" || len(back.Secrets) != 1 || back.Secrets[0].Key != "token" {
		t.Fatalf("read back: %+v %v", back, err)
	}
}

func TestJobStateAndCacheID(t *testing.T) {
	for phase, want := range map[string]cli.State{"queued": cli.Accepted, "running": cli.Accepted, "succeeded": cli.Done, "cancelled": cli.Done, "failed": cli.Failed} {
		if st, _ := buildJobState(control.ImageBuildJobView{Phase: phase}); st != want {
			t.Fatal(phase, st)
		}
	}
	if _, line := buildJobState(control.ImageBuildJobView{Phase: "running", Cancel: true}); line != "running (cancelling)" {
		t.Fatal(line)
	}
	if _, err := parseCacheID(strings.Repeat("ab", 32)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("AB", 32), strings.Repeat("0", 64), "abc"} {
		if _, err := parseCacheID(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
}

// A context name keeps its kind and storage after delete. Creating it again
// replaces only a live record and refuses a changed kind or storage at once.
func TestContextToReplaceKeepsKindAndStorage(t *testing.T) {
	disk := nodestorage.Reference{Node: "node-a", ID: "disk1", Generation: 1}
	sp := imagebuild.ContextSpec{Tenant: "shop", ID: "web", Kind: "upload", Root: disk}
	if cur, err := contextToReplace(nil, sp); cur != nil || err != nil {
		t.Fatal("new name", cur, err)
	}
	live := &control.ImageBuildContextView{Spec: sp, Revision: 4}
	if cur, err := contextToReplace(live, sp); cur != live || err != nil {
		t.Fatal("live context", cur, err)
	}
	deleted := &control.ImageBuildContextView{Spec: sp, Revision: 5, Deleted: true}
	if cur, err := contextToReplace(deleted, sp); cur != nil || err != nil {
		t.Fatal("deleted context", cur, err)
	}
	moved := sp
	moved.Root.ID = "build1"
	git := sp
	git.Kind = "git"
	for _, next := range []imagebuild.ContextSpec{moved, git} {
		if _, err := contextToReplace(deleted, next); err == nil || !strings.Contains(err.Error(), "new context name") {
			t.Fatal("changed kind or storage accepted", next.Kind, next.Root.ID, err)
		}
	}
}

func TestKeptBuildsOfOneVersion(t *testing.T) {
	jobs := []control.ImageBuildJobView{
		{ID: "b2", Context: "web", Number: 1},
		{ID: "b1", Context: "web", Number: 1},
		{ID: "gone", Context: "web", Number: 1, Deleted: true},
		{ID: "other", Context: "web", Number: 2},
		{ID: "api", Context: "api", Number: 1},
	}
	if got := keptBuilds(jobs, "web", 1); !slices.Equal(got, []string{"b1", "b2"}) {
		t.Fatal(got)
	}
	if got := keptBuilds(jobs, "web", 3); len(got) != 0 {
		t.Fatal(got)
	}
}
