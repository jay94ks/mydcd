// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cliprofile"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func fakeDiscovery(t *testing.T, nodes map[string]sfcp.PublicIdentity) {
	t.Helper()
	old := discoverNode
	discoverNode = func(_ context.Context, network, address string) (sfcp.PublicIdentity, error) {
		if n, ok := nodes[network+":"+address]; ok {
			return n, nil
		}
		return sfcp.PublicIdentity{}, errors.New("connection refused")
	}
	t.Cleanup(func() { discoverNode = old })
}

func sfcli(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, diagnostic bytes.Buffer
	code := run(args, &out, &diagnostic)
	return code, out.String(), diagnostic.String()
}

func TestContextAddTrustSetUseRemove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	a := sfcp.PublicIdentity{Cluster: [32]byte{5}, Key: [32]byte{8}, Node: "node-a"}
	b := sfcp.PublicIdentity{Cluster: [32]byte{5}, Key: [32]byte{9}, Node: "node-b"}
	other := sfcp.PublicIdentity{Cluster: [32]byte{6}, Key: [32]byte{10}, Node: "node-x"}
	fakeDiscovery(t, map[string]sfcp.PublicIdentity{"sfcp:127.0.0.1:7443": a, "sfcp:127.0.0.1:7444": b, "sfcp:127.0.0.1:7445": other})
	keyA, keyB := hex.EncodeToString(a.Key[:]), hex.EncodeToString(b.Key[:])

	if code, _, e := sfcli(t, "context", "list"); code != 1 || !strings.Contains(e, "no context") {
		t.Fatal("list without ~/.sfc", code, e)
	}
	// Without --key nothing can confirm the key here (no terminal), and -y
	// does not count as confirming it.
	if code, _, e := sfcli(t, "context", "add", "prod", "sfcp://127.0.0.1:7443", "-y"); code == 0 || !strings.Contains(e, "needs confirmation on a terminal") {
		t.Fatal("unconfirmed key accepted", code, e)
	}
	if code, _, e := sfcli(t, "context", "add", "prod", "sfcp://127.0.0.1:7443", "--no-input"); code != 2 {
		t.Fatal("--no-input without --key", code, e)
	}
	if code, _, e := sfcli(t, "context", "add", "prod", "sfcp://127.0.0.1:7443", "--key", keyB); code == 0 || !strings.Contains(e, "not the --key given") {
		t.Fatal("wrong --key accepted", code, e)
	}
	if code, _, e := sfcli(t, "context", "add", "prod", "sfcp://127.0.0.1:7443", "--key", keyA, "--user", "alice", "--tenant", "shop"); code != 0 || !strings.Contains(e, "Now using context prod") {
		t.Fatal(code, e)
	}
	if code, _, e := sfcli(t, "context", "add", "prod", "sfcp://127.0.0.1:7444", "--key", keyB); code == 0 || !strings.Contains(e, "already exists") {
		t.Fatal("duplicate name", code, e)
	}
	if code, _, e := sfcli(t, "context", "add", "staging", "sfcp://127.0.0.1:7445", "--key", hex.EncodeToString(other.Key[:])); code != 0 || strings.Contains(e, "Now using") {
		t.Fatal("second context replaced the current one", code, e)
	}
	cfg, err := os.ReadFile(filepath.Join(home, ".sfc", "config.yaml"))
	if err != nil || !strings.Contains(string(cfg), "current: prod") || !strings.Contains(string(cfg), "endpoint: sfcp://127.0.0.1:7443") {
		t.Fatal(string(cfg), err)
	}

	// Trusting another node of the same cluster, but never one of another cluster.
	if code, _, e := sfcli(t, "context", "trust", "prod", "sfcp://127.0.0.1:7445", "--key", hex.EncodeToString(other.Key[:])); code == 0 || !strings.Contains(e, "not this context's cluster") {
		t.Fatal("foreign cluster trusted", code, e)
	}
	if code, _, e := sfcli(t, "context", "trust", "prod", "sfcp://127.0.0.1:7444", "--key", keyB); code != 0 {
		t.Fatal(code, e)
	}
	code, out, e := sfcli(t, "context", "show", "prod", "-o", "json")
	var shown contextView
	if code != 0 || json.Unmarshal([]byte(out), &shown) != nil || shown.Tenant != "shop" || len(shown.Nodes) != 2 || shown.Nodes[1].How != "out-of-band" {
		t.Fatal(code, out, e)
	}
	selected, err := resolveCommandProfile(home, "", "", "")
	if err != nil || selected.Target.Peer != "node-a" || len(selected.Client.Peers) != 2 {
		t.Fatal(selected, err)
	}

	if code, _, e := sfcli(t, "context", "set", "prod", "--tenant", ""); code != 0 {
		t.Fatal(code, e)
	}
	if code, _, e := sfcli(t, "context", "set", "prod"); code != 2 {
		t.Fatal("set without options", code, e)
	}
	// A node whose address changed: the context follows it, and the node
	// is trusted at the new address with its same key.
	fakeDiscovery(t, map[string]sfcp.PublicIdentity{"sfcp:127.0.0.1:7443": a, "sfcp:127.0.0.1:7444": b, "sfcp:127.0.0.1:7446": a})
	if code, _, e := sfcli(t, "context", "set", "prod", "--endpoint", "sfcp://127.0.0.1:7446"); code != 0 {
		t.Fatal(code, e)
	}
	if _, err := resolveCommandProfile(home, "prod", "", ""); err == nil || !strings.Contains(err.Error(), "context trust") {
		t.Fatal("untrusted new address selected", err)
	}
	if code, _, e := sfcli(t, "context", "trust", "prod", "--key", keyA); code != 0 {
		t.Fatal(code, e)
	}
	if selected, err := resolveCommandProfile(home, "prod", "", ""); err != nil || selected.Target.Peer != "node-a" {
		t.Fatal("moved context", selected, err)
	}
	if code, _, e := sfcli(t, "context", "set", "prod", "--endpoint", "sfcp://127.0.0.1:7443"); code != 0 {
		t.Fatal(code, e)
	}
	if code, _, e := sfcli(t, "context", "use", "staging"); code != 0 {
		t.Fatal(code, e)
	}
	code, out, _ = sfcli(t, "context", "list")
	if code != 0 || !strings.Contains(out, "*  staging") || strings.Contains(out, "shop") {
		t.Fatalf("%d %q", code, out)
	}

	if code, _, e := sfcli(t, "context", "trust", "prod", "--forget", "node-b", "-y"); code != 0 {
		t.Fatal(code, e)
	}
	if code, _, e := sfcli(t, "context", "remove", "prod"); code == 0 || !strings.Contains(e, "needs confirmation") {
		t.Fatal("remove without confirmation", code, e)
	}
	if code, _, e := sfcli(t, "context", "remove", "prod", "-y"); code != 0 {
		t.Fatal(code, e)
	}
	if _, err := os.Stat(filepath.Join(home, ".sfc", "trust", hex.EncodeToString(a.Cluster[:])+".yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("trust of a cluster no context uses was kept", err)
	}
	if _, err := resolveCommandProfile(home, "prod", "", ""); !errors.Is(err, cliprofile.ErrNotFound) {
		t.Fatal(err)
	}
}
