// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// runBoth is f.run that also returns the diagnostic stream, where errors go.
func (f *cliFixture) runBoth(want int, args ...string) (string, string) {
	f.t.Helper()
	var out, diagnostic bytes.Buffer
	code := cli.Execute(newRoot(&globals{}), append([]string{"-y", "--timeout", "20s"}, args...), cli.Env{Context: f.m.ctx, In: strings.NewReader(""), Out: &out, Err: &diagnostic})
	if code != want {
		f.t.Fatalf("sfcli %v: exit %d (want %d)\n%s%s", args, code, want, out.String(), diagnostic.String())
	}
	return out.String(), diagnostic.String()
}

// The errors people met in the smoke test say why, not "denied".
func TestExternalSourceErrorsSayWhy(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer plain.Close()
	f := newCLIFixture(t)
	f.run(0, "tenant", "create", "shop", "--nodes", "node-a")
	ext := func(want int, args ...string) (string, string) {
		t.Helper()
		return f.runBoth(want, append([]string{"--tenant", "shop", "registry", "external"}, args...)...)
	}

	// A CA reference is checked on add. No realm is the tenant's own tree,
	// "/ID" the cluster's.
	if _, e := ext(1, "add", "tls", "--authority", "192.0.2.11:5443", "--repository", "smoke/**", "--ca", "regca", "--ca-key", "CA"); !strings.Contains(e, "--ca") || !strings.Contains(e, "tenant shop") {
		t.Fatal("missing tenant CA", e)
	}
	if _, e := ext(1, "add", "tls", "--authority", "192.0.2.11:5443", "--repository", "smoke/**", "--ca", "/regca"); !strings.Contains(e, "the cluster") {
		t.Fatal("missing cluster CA", e)
	}
	if out, _ := ext(0, "list"); strings.Contains(out, "tls") {
		t.Fatal("source saved with a missing CA", out)
	}

	// check before bind, bind twice, bind to a second server.
	authority := strings.TrimPrefix(plain.URL, "http://")
	ext(0, "add", "local", "--authority", authority, "--repository", "smoke/**")
	if _, e := ext(1, "check", "local"); !strings.Contains(e, "bind local --node") {
		t.Fatal("check before bind", e)
	}
	ext(0, "bind", "local", "--node", "node-a")
	if _, e := ext(1, "bind", "local", "--node", "node-a"); !strings.Contains(e, "already reads through node-a") {
		t.Fatal("second bind", e)
	}
	if _, e := ext(1, "bind", "local", "--node", "node-b"); !strings.Contains(e, "unbind local") {
		t.Fatal("bind elsewhere", e)
	}

	// A plain HTTP registry is a result with its reason, not "unavailable".
	out, e := ext(3, "check", "local")
	if !strings.Contains(out, "PLAIN_HTTP") || !strings.Contains(e, "HTTPS only") {
		t.Fatal("plain HTTP check", out, e)
	}
	if _, e = ext(0, "pulls"); !strings.Contains(e, "No pulls yet") {
		t.Fatal("empty pulls", e)
	}
}

// A registry reserves MaxRequests connections against the tenant's and the
// server's max consumers; the CLI names the short one and its fix.
func TestRegistryConsumersShortNamesTheLimit(t *testing.T) {
	limits := []tenancy.NodeLimit{{Tenant: "", Node: "node-a", MaxConsumers: 128}, {Tenant: "shop", Node: "node-a", MaxConsumers: 32}, {Tenant: "shop", Node: "node-b", MaxConsumers: 8}}
	if got := consumersShort(limits, "shop", "node-a", 64); !strings.Contains(got, "tenant shop allows 32") || !strings.Contains(got, "sfcli tenant quota set shop node-a --consumers 64") {
		t.Fatal(got)
	}
	limits[1].MaxConsumers = 64
	if got := consumersShort(limits, "shop", "node-a", 64); got != "" {
		t.Fatal("enough consumers reported short:", got)
	}
	limits[0].MaxConsumers = 0
	if got := consumersShort(limits, "shop", "node-a", 64); !strings.Contains(got, "sfcli node quota set node-a --consumers 64") {
		t.Fatal(got)
	}
}
