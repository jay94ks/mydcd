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

	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func fakeDiscovery(t *testing.T, nodes map[string]mydcp.PublicIdentity) {
	t.Helper()
	old := discoverNode
	discoverNode = func(_ context.Context, network, address string) (mydcp.PublicIdentity, error) {
		if n, ok := nodes[network+":"+address]; ok {
			return n, nil
		}
		return mydcp.PublicIdentity{}, errors.New("connection refused")
	}
	t.Cleanup(func() { discoverNode = old })
}

func mydc(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, diagnostic bytes.Buffer
	code := run(args, &out, &diagnostic)
	return code, out.String(), diagnostic.String()
}

func TestContextAddTrustSetUseRemove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	a := mydcp.PublicIdentity{Cluster: [32]byte{5}, Key: [32]byte{8}, Node: "node-a"}
	b := mydcp.PublicIdentity{Cluster: [32]byte{5}, Key: [32]byte{9}, Node: "node-b"}
	other := mydcp.PublicIdentity{Cluster: [32]byte{6}, Key: [32]byte{10}, Node: "node-x"}
	fakeDiscovery(t, map[string]mydcp.PublicIdentity{"mydcp:127.0.0.1:7443": a, "mydcp:127.0.0.1:7444": b, "mydcp:127.0.0.1:7445": other})
	keyA, keyB := hex.EncodeToString(a.Key[:]), hex.EncodeToString(b.Key[:])

	if code, _, e := mydc(t, "context", "list"); code != 1 || !strings.Contains(e, "no context") {
		t.Fatal("list without ~/.mydc", code, e)
	}
	// Without --key nothing can confirm the key here (no terminal), and -y
	// does not count as confirming it.
	if code, _, e := mydc(t, "context", "add", "prod", "mydcp://127.0.0.1:7443", "-y"); code == 0 || !strings.Contains(e, "needs confirmation on a terminal") {
		t.Fatal("unconfirmed key accepted", code, e)
	}
	if code, _, e := mydc(t, "context", "add", "prod", "mydcp://127.0.0.1:7443", "--no-input"); code != 2 {
		t.Fatal("--no-input without --key", code, e)
	}
	if code, _, e := mydc(t, "context", "add", "prod", "mydcp://127.0.0.1:7443", "--key", keyB); code == 0 || !strings.Contains(e, "not the --key given") {
		t.Fatal("wrong --key accepted", code, e)
	}
	if code, _, e := mydc(t, "context", "add", "prod", "mydcp://127.0.0.1:7443", "--key", keyA, "--user", "alice", "--tenant", "shop"); code != 0 || !strings.Contains(e, "Now using context prod") {
		t.Fatal(code, e)
	}
	if code, _, e := mydc(t, "context", "add", "prod", "mydcp://127.0.0.1:7444", "--key", keyB); code == 0 || !strings.Contains(e, "already exists") {
		t.Fatal("duplicate name", code, e)
	}
	if code, _, e := mydc(t, "context", "add", "staging", "mydcp://127.0.0.1:7445", "--key", hex.EncodeToString(other.Key[:])); code != 0 || strings.Contains(e, "Now using") {
		t.Fatal("second context replaced the current one", code, e)
	}
	cfg, err := os.ReadFile(filepath.Join(home, ".mydc", "config.yaml"))
	if err != nil || !strings.Contains(string(cfg), "current: prod") || !strings.Contains(string(cfg), "endpoint: mydcp://127.0.0.1:7443") {
		t.Fatal(string(cfg), err)
	}

	// Trusting another node of the same cluster, but never one of another cluster.
	if code, _, e := mydc(t, "context", "trust", "prod", "mydcp://127.0.0.1:7445", "--key", hex.EncodeToString(other.Key[:])); code == 0 || !strings.Contains(e, "not this context's cluster") {
		t.Fatal("foreign cluster trusted", code, e)
	}
	if code, _, e := mydc(t, "context", "trust", "prod", "mydcp://127.0.0.1:7444", "--key", keyB); code != 0 {
		t.Fatal(code, e)
	}
	code, out, e := mydc(t, "context", "show", "prod", "-o", "json")
	var shown contextView
	if code != 0 || json.Unmarshal([]byte(out), &shown) != nil || shown.Tenant != "shop" || len(shown.Nodes) != 2 || shown.Nodes[1].How != "out-of-band" {
		t.Fatal(code, out, e)
	}
	selected, err := resolveCommandProfile(home, "", "", "")
	if err != nil || selected.Target.Peer != "node-a" || len(selected.Client.Peers) != 2 {
		t.Fatal(selected, err)
	}

	if code, _, e := mydc(t, "context", "set", "prod", "--tenant", ""); code != 0 {
		t.Fatal(code, e)
	}
	if code, _, e := mydc(t, "context", "set", "prod"); code != 2 {
		t.Fatal("set without options", code, e)
	}
	if code, _, e := mydc(t, "context", "use", "staging"); code != 0 {
		t.Fatal(code, e)
	}
	code, out, _ = mydc(t, "context", "list")
	if code != 0 || !strings.Contains(out, "*  staging") || strings.Contains(out, "shop") {
		t.Fatalf("%d %q", code, out)
	}

	if code, _, e := mydc(t, "context", "trust", "prod", "--forget", "node-b", "-y"); code != 0 {
		t.Fatal(code, e)
	}
	if code, _, e := mydc(t, "context", "remove", "prod"); code == 0 || !strings.Contains(e, "needs confirmation") {
		t.Fatal("remove without confirmation", code, e)
	}
	if code, _, e := mydc(t, "context", "remove", "prod", "-y"); code != 0 {
		t.Fatal(code, e)
	}
	if _, err := os.Stat(filepath.Join(home, ".mydc", "trust", hex.EncodeToString(a.Cluster[:])+".yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("trust of a cluster no context uses was kept", err)
	}
	if _, err := resolveCommandProfile(home, "prod", "", ""); !errors.Is(err, cliprofile.ErrNotFound) {
		t.Fatal(err)
	}
}
