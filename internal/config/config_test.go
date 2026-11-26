// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/nodeapp"
)

func TestRealBoundaryConfigFilesAndSelection(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	system := filepath.Join(root, "etc")
	explicit := filepath.Join(root, "explicit")
	for _, dir := range []string{filepath.Join(home, ".mydc"), system, explicit} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, text string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	systemFile := filepath.Join(system, "client.yaml")
	homeFile := filepath.Join(home, ".mydc", "client.yaml")
	write(systemFile, "system")
	if path, err := ResolveClient("", "", home, system); err != nil || path != systemFile {
		t.Fatal(path, err)
	}
	write(homeFile, "home")
	if path, err := ResolveClient("", "", home, system); err != nil || path != homeFile {
		t.Fatal(path, err)
	}
	missing := filepath.Join(explicit, "missing.yaml")
	if path, err := ResolveClient(missing, "", home, system); err != nil || path != missing {
		t.Fatal("explicit fallback", path, err)
	}
	if _, err := LoadClient(missing); err == nil {
		t.Fatal("missing explicit file accepted")
	}
	if _, err := ResolveClient(missing, explicit, home, system); err == nil {
		t.Fatal("two explicit choices")
	}
	if path, err := ResolveClient("", explicit, home, system); err != nil || path != filepath.Join(explicit, "client.yaml") {
		t.Fatal(path, err)
	}
	text := "version: 1\nnode:\n  id: n1\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: false, ignored_when_disabled: invalid}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	path := filepath.Join(root, "node.yaml")
	write(path, text)
	c, err := LoadNode(path)
	if err != nil || c.Node.StateDir != filepath.Join(root, "state") {
		t.Fatal(c, err)
	}
	if _, err = os.Stat(c.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("loader opened runtime resources", err)
	}
	for _, bad := range []string{strings.Replace(text, "version: 1", "version: 1\nversion: 1", 1), strings.Replace(text, "enabled: false", "enabled: no", 1), text + "unknown: 1\n", text + "---\nversion: 1\n", strings.Replace(text, "enabled: false", "enabled: &flag false", 1) + "alias: *flag\n", strings.Replace(text, "40001", "0", -1)} {
		write(path, bad)
		if _, err := LoadNode(path); err == nil {
			t.Fatal("invalid YAML/schema accepted", bad)
		}
	}
}

func TestRealBoundaryActiveModuleSelectionAndNoSideEffects(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	text := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: true, docker_socket: 'unix:///var/run/docker.sock'}\n  workload: {enabled: true}\n  ingress: {enabled: false}\n"
	write := func(b string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(b), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(text)
	c, err := LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	var n NetworkLocal
	if err = c.Modules["network"].Decode(&n); err != nil || !n.Enabled || n.DockerSocket != "unix:///var/run/docker.sock" {
		t.Fatal("typed module body", n, err)
	}
	for _, bad := range []string{
		strings.Replace(text, "unix:///var/run/docker.sock", "tcp://127.0.0.1:2375", 1),
		strings.Replace(text, "docker_socket:", "unknown_socket:", 1),
		strings.Replace(text, "network: {enabled: true", "network: {enabled: false", 1),
		strings.Replace(text, "workload: {enabled: true}", "workload: {enabled: true, unknown: 1}", 1),
		strings.Replace(text, "workload: {enabled: true}", "workload: {enabled: true, lifecycle_sandbox: {binary: /usr/bin/bwrap}}", 1),
	} {
		write(bad)
		if _, err = LoadNode(path); err == nil {
			t.Fatal("active module error accepted", bad)
		}
	}
	for _, dir := range []string{c.Node.StateDir, c.Node.IdentityDir} {
		if _, err = os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("config check created runtime data", dir, err)
		}
	}
}

func TestNodeAppWebNeedsNetworkAndResolvesTheSealKeyFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	base := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: %s, docker_socket: 'unix:///var/run/docker.sock'}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	load := func(network, extra string) (Node, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf(base, network)+extra), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadNode(path)
	}
	c, err := load("true", "node_apps:\n  web: {enabled: true, seal_key_file: web-seal.key}\n")
	if err != nil || c.NodeApps.Web.SealKeyFile != filepath.Join(root, "web-seal.key") || len(c.NodeApps.Enabled()) != 1 || c.NodeApps.Enabled()[0] != "web" {
		t.Fatal(c.NodeApps, err)
	}
	if c.NodeApps.Web.UID != nodeapp.DefaultUID {
		t.Fatal("default uid", c.NodeApps.Web.UID)
	}
	if c, err = load("true", "node_apps:\n  web: {enabled: true, uid: 20002}\n"); err != nil || c.NodeApps.Web.UID != 20002 {
		t.Fatal("uid", c.NodeApps, err)
	}
	if _, err = load("true", "node_apps:\n  web: {enabled: true, uid: 4294967295}\n"); err == nil {
		t.Fatal("out-of-range uid accepted")
	}
	if _, err = load("false", "node_apps:\n  web: {enabled: true}\n"); err == nil {
		t.Fatal("web without network accepted")
	}
	if c, err = load("false", "node_apps:\n  web: {enabled: false}\n"); err != nil || c.NodeApps.Enabled() != nil {
		t.Fatal("disabled web", err)
	}
	if _, err = load("true", "node_apps:\n  other: {enabled: true}\n"); err == nil {
		t.Fatal("unknown node app accepted")
	}
}
