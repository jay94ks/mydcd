// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/app"
	"github.com/jay94ks/seafield/internal/bootstrap"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
)

func TestManagedInitCLIEmptyRootAndOriginalResume(t *testing.T) {
	root := t.TempDir()
	admin, err := identity.Create(filepath.Join(root, "admin"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(admin.Private)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.LocalAddr().String()
	_ = probe.Close()
	path, profile := filepath.Join(root, "node.yaml"), filepath.Join(root, "client.yaml")
	text := fmt.Sprintf("version: 1\nnode:\n  id: node-a\n  state_dir: state\n  identity_dir: keys/node\n  listen: '%s'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n", address)
	if err = os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadNode(path)
	if err != nil {
		t.Fatal(err)
	}
	var output, diagnostic bytes.Buffer
	if code := run([]string{"--config", path, "check"}, &output, &diagnostic); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	if runtime, err := app.Open(c); err == nil {
		_ = runtime.Close()
		t.Fatal("blank managed run implicitly initialized")
	}
	if _, err = os.Stat(c.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("uninitialized run opened runtime files", err)
	}
	invalid := c
	invalid.Node.StateDir = filepath.Join(root, "invalid-constructor")
	invalid.Node.Listen = "0.0.0.0:0"
	if _, err = bootstrap.PrepareInit(invalid, admin.Public, "init-one"); err == nil {
		t.Fatal("direct constructor accepted invalid advertised endpoint")
	}
	if _, err = os.Stat(invalid.Node.StateDir); !os.IsNotExist(err) {
		t.Fatal("invalid direct constructor mutated root", err)
	}
	invoke := func(want int, operation string) map[string]any {
		t.Helper()
		output.Reset()
		diagnostic.Reset()
		code := run([]string{"--config", path, "init", "--admin-public-key", admin.Actor(), "--request-id", operation, "--client-config-out", profile}, &output, &diagnostic)
		if code != want {
			t.Fatal("init exit", code, want, diagnostic.String())
		}
		if want != 0 {
			return nil
		}
		var result map[string]any
		if json.Unmarshal(output.Bytes(), &result) != nil {
			t.Fatal("invalid init JSON")
		}
		return result
	}
	first := invoke(0, "init-one")
	if first["status"] != "AwaitingAdminEnrollment" || first["standalone"] != true || first["voters"] != float64(1) || first["quorum"] != float64(1) || first["users"] != float64(0) || first["tenants"] != float64(0) {
		t.Fatal("init did not create blank N1/Q1", first)
	}
	if first["configuration_index"].(float64) < 1 || first["applied_index"].(float64) < first["configuration_index"].(float64) {
		t.Fatal("configuration not durably installed")
	}
	record, err := bootstrap.Read(c)
	if err != nil {
		t.Fatal(err)
	}
	client, err := config.LoadClient(profile)
	if err != nil || client.Auth != "user" || client.Cluster != first["cluster"] || len(client.Peers) != 1 || client.Peers[0].Key != first["node_key"] {
		t.Fatal("generated user profile", err)
	}
	second := invoke(0, "init-one")
	if second["cluster"] != first["cluster"] || second["node_key"] != first["node_key"] {
		t.Fatal("init retry replaced original identity")
	}
	// Same-request recovery may durably advance the installed/applied index.
	// Compare the rejected different request against the resulting current root.
	record, err = bootstrap.Read(c)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(record)
	invoke(1, "another-init")
	after, err := bootstrap.Read(c)
	afterBytes, _ := json.Marshal(after)
	if err != nil || !bytes.Equal(before, afterBytes) {
		t.Fatal("different init overwrote original root", err)
	}
	wrong := c
	wrong.Node.ID = "other"
	if _, err = app.Open(wrong); err == nil {
		t.Fatal("node ID switch accepted")
	}
	wrong = c
	wrong.Common.Cluster = fmt.Sprintf("%064x", 123)
	if _, err = app.Open(wrong); err == nil {
		t.Fatal("cluster switch accepted")
	}
	wrong = c
	wrong.Common.Cluster = client.Cluster
	wrong.Common.Admin = admin.Actor()
	wrong.Common.Peers = client.Peers
	if runtime, err := app.Open(wrong); err == nil {
		_ = runtime.Close()
		t.Fatal("managed root reinterpreted as legacy")
	}
	runtime, err := app.Open(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	installed, err := runtime.InstallConfiguration(ctx)
	if err != nil {
		_ = runtime.Close()
		t.Fatal(err)
	}
	configuration, err := runtime.Engine().InstalledConfiguration(ctx, true)
	if err != nil || configuration.Index != installed.Root.Installed.Index || configuration.AppliedIndex < configuration.Index {
		t.Fatal("SDK latest used without FSM proof", err)
	}
	if err = runtime.Close(); err != nil {
		t.Fatal(err)
	}
	// A missing original Raft DB cannot be converted into a fresh cluster.
	raftPath := filepath.Join(c.Node.StateDir, "control", "raft.db")
	raw, err := os.ReadFile(raftPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(raftPath); err != nil {
		t.Fatal(err)
	}
	if runtime, err := app.Open(c); err == nil {
		_ = runtime.Close()
		t.Fatal("missing installed Raft DB reinitialized")
	}
	if err = os.WriteFile(raftPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Owned foreign data remains byte-identical after refused init.
	foreign := c
	foreign.Node.StateDir = filepath.Join(root, "foreign")
	foreign.Node.IdentityDir = filepath.Join(root, "foreign-key")
	if err = os.Mkdir(foreign.Node.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(foreign.Node.StateDir, "existing-data")
	if err = os.WriteFile(sentinel, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrap.PrepareInit(foreign, admin.Public, "foreign-init"); err == nil {
		t.Fatal("foreign root accepted")
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "preserve" {
		t.Fatal("foreign data changed", err)
	}
}

func TestManagedInitHelpAndStrictConfiguration(t *testing.T) {
	var out, diagnostic bytes.Buffer
	if code := run([]string{"init", "--help"}, &out, &diagnostic); code != 0 {
		t.Fatal(code, diagnostic.String())
	}
	if !bytes.Contains(diagnostic.Bytes(), []byte("admin-public-key")) {
		t.Fatal("init help missing actual flags")
	}
	root := t.TempDir()
	path := filepath.Join(root, "node.yaml")
	base := "version: 1\nnode:\n  id: node-a\n  state_dir: state\n  identity_dir: key\n  listen: '127.0.0.1:17443'\nmodules:\n  network: {enabled: false}\n  workload: {enabled: false}\n  ingress: {enabled: false}\n"
	for _, endpoint := range []string{"127.0.0.1:017443", "[::ffff:127.0.0.1]:17443", "LOCALHOST:17443", "localhost.:17443", strings.Repeat("a", 321) + ":17443"} {
		text := strings.Replace(base, "127.0.0.1:17443", endpoint, 1)
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadNode(path); err == nil {
			t.Fatal("noncanonical managed endpoint accepted", endpoint)
		}
		c := config.Node{Version: 1, Common: config.Common{}}
		c.Node.ID, c.Node.Listen, c.Node.StateDir, c.Node.IdentityDir = "node-a", endpoint, filepath.Join(root, "state"), filepath.Join(root, "key")
		if _, err := bootstrap.PrepareInit(c, [32]byte{1}, "invalid-endpoint"); err == nil {
			t.Fatal("direct constructor opened noncanonical root")
		}
	}
	for _, text := range []string{strings.Replace(base, "id: node-a", "id: node-a\n  managed: true", 1), strings.Replace(base, "node:", "common: {user_catalog: true}\nnode:", 1), strings.Replace(base, "id: node-a", "id: node-a\n  bootstrap: true", 1), strings.Replace(base, "id: node-a", "id: invalid.id", 1), strings.Replace(base, "127.0.0.1:17443", "0.0.0.0:17443", 1)} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadNode(path); err == nil {
			t.Fatal("invalid managed configuration accepted", text)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "state")); !os.IsNotExist(err) {
		t.Fatal("configuration validation opened state root", err)
	}
}
