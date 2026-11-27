// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/clusterapp"
)

func TestRealBoundaryConfigFilesAndSelection(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	system := filepath.Join(root, "etc")
	explicit := filepath.Join(root, "explicit")
	for _, dir := range []string{filepath.Join(home, ".sfc"), system, explicit} {
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
	homeFile := filepath.Join(home, ".sfc", "client.yaml")
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
	text := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: true}\n  workload: {enabled: true}\n  ingress: {enabled: false}\n"
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
	if err = c.Modules["network"].Decode(&n); err != nil || !n.Enabled || c.EngineEndpoint() != DefaultEngineAPI {
		t.Fatal("typed module body", n, err)
	}
	for _, bad := range []string{
		strings.Replace(text, "network: {enabled: true}", "network: {enabled: true, unknown_socket: x}", 1),
		strings.Replace(text, "network: {enabled: true}", "network: {enabled: true, docker_socket: x}", 1),
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

func TestClusterAppWebNeedsNetworkAndResolvesTheSealKeyFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	base := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: %s}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	load := func(network, extra string) (Node, error) {
		t.Helper()
		if err := os.WriteFile(path, []byte(fmt.Sprintf(base, network)+extra), 0600); err != nil {
			t.Fatal(err)
		}
		return LoadNode(path)
	}
	c, err := load("true", "cluster_apps:\n  web: {enabled: true, seal_key_file: web-seal.key}\n")
	if err != nil || c.ClusterApps.Web.SealKeyFile != filepath.Join(root, "web-seal.key") || len(c.ClusterApps.Enabled()) != 1 || c.ClusterApps.Enabled()[0] != "web" {
		t.Fatal(c.ClusterApps, err)
	}
	if c.ClusterApps.Web.UID != clusterapp.DefaultUID {
		t.Fatal("default uid", c.ClusterApps.Web.UID)
	}
	if c, err = load("true", "cluster_apps:\n  web: {enabled: true, uid: 20002}\n"); err != nil || c.ClusterApps.Web.UID != 20002 {
		t.Fatal("uid", c.ClusterApps, err)
	}
	if _, err = load("true", "cluster_apps:\n  web: {enabled: true, uid: 4294967295}\n"); err == nil {
		t.Fatal("out-of-range uid accepted")
	}
	if c, err = load("true", "cluster_apps:\n  web: {enabled: true, port: 8443}\n"); err != nil || c.ClusterApps.Web.Port != 8443 {
		t.Fatal("port", c.ClusterApps, err)
	}
	if _, err = load("true", "cluster_apps:\n  web: {enabled: true, port: 40001}\n"); err == nil {
		t.Fatal("port taken by node.listen accepted")
	}
	if _, err = load("false", "cluster_apps:\n  web: {enabled: true}\n"); err == nil {
		t.Fatal("web without network accepted")
	}
	if c, err = load("false", "cluster_apps:\n  web: {enabled: false}\n"); err != nil || c.ClusterApps.Enabled() != nil {
		t.Fatal("disabled web", err)
	}
	if _, err = load("true", "cluster_apps:\n  other: {enabled: true}\n"); err == nil {
		t.Fatal("unknown cluster app accepted")
	}
}

func TestFirewallKeepOpen(t *testing.T) {
	ports, err := NodeFirewall{}.KeepOpenPorts()
	if err != nil || len(ports) != 1 || ports[0].Proto != "tcp" || ports[0].Port != 22 || ports[0].From != nil {
		t.Fatal(ports, err)
	}
	local := []string{"tcp/22 from 192.168.1.0/24,fd00::/8", "udp/7443"}
	if ports, err := (NodeFirewall{KeepOpen: &local}).KeepOpenPorts(); err != nil || len(ports) != 2 || strings.Join(ports[0].From, " ") != "192.168.1.0/24 fd00::/8" || ports[1].From != nil {
		t.Fatal(ports, err)
	}
	none := []string{}
	if ports, err := (NodeFirewall{KeepOpen: &none}).KeepOpenPorts(); err != nil || len(ports) != 0 {
		t.Fatal("explicit empty keep_open keeps nothing", ports, err)
	}
	for _, bad := range []string{"22", "sctp/22", "tcp/0", "tcp/022", "tcp/70000", "tcp/22 from", "tcp/22 from 192.168.1.1/24", "tcp/22 from 10.0.0.0/8,10.0.0.0/8", "tcp/22 from fe80::%eth0/64"} {
		list := []string{bad}
		if _, err := (NodeFirewall{KeepOpen: &list}).KeepOpenPorts(); err == nil {
			t.Error(bad, "accepted")
		}
	}
}

// An old node.yaml that still names the Docker socket is refused with a
// message that says what to do (R18 E2: the engine is always sfed).
func TestNodeRefusesTheRemovedDockerSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.yaml")
	body := "version: 1\nnode:\n  id: a\n  state_dir: state\n  identity_dir: keys\n  listen: '127.0.0.1:40001'\nmodules:\n  network: {enabled: true, docker_socket: unix:///var/run/docker.sock}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadNode(path)
	if err == nil || !strings.Contains(err.Error(), "docker_socket was removed") || !strings.Contains(err.Error(), DefaultEngineAPI) {
		t.Fatal(err)
	}
}
