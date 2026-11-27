// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// group9Node is a managed node with one tenant and a logged-in session that
// the commands use instead of the wallet.
type group9Node struct {
	t    *testing.T
	m    *managedNode
	s    *session
	root string
}

func newGroup9Node(t *testing.T) *group9Node {
	t.Helper()
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
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	m := newManagedNode(t, ctx, root, "node-a", admin)
	m.EnrollAdmin(access.User{ID: "sys", Username: "operator", Enabled: true, SystemAdmin: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: admin.Public, Enabled: true}}})
	if r := m.Change("tenant", "create-tenant", 0, control.TenantID{ID: "shop"}); r.Code != state.Applied {
		t.Fatal("create tenant", r)
	}
	return &group9Node{t: t, m: m, s: managedSession(t, m, home), root: root}
}

// run executes one command line and returns its output; want is the exit
// code.
func (n *group9Node) run(want int, args ...string) string {
	n.t.Helper()
	var out, why bytes.Buffer
	g := &globals{session: n.s}
	code := cli.Execute(newRoot(g), append([]string{"-y", "--tenant", "shop"}, args...), cli.Env{Context: n.m.ctx, In: strings.NewReader(""), Out: &out, Err: &why})
	if code != want {
		n.t.Fatalf("%v: exit %d, want %d\n%s%s", args, code, want, out.String(), why.String())
	}
	return out.String()
}

func (n *group9Node) file(name, text string) string {
	n.t.Helper()
	path := filepath.Join(n.root, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		n.t.Fatal(err)
	}
	return path
}

func (n *group9Node) opState(id string) cli.Op {
	n.t.Helper()
	x, err := openOps()
	if err != nil {
		n.t.Fatal(err)
	}
	defer x.Close()
	op, err := x.Get(id)
	if err != nil {
		n.t.Fatal(err)
	}
	return op
}

func TestLifecycleCommands(t *testing.T) {
	n := newGroup9Node(t)
	tenant, _ := n.m.Catalog().Tenant("shop")
	if r := n.m.Change("nodes", "set-nodes", tenant.Revision, control.NodeChangeTo("shop", tenant.AllowedNodes, []string{"node-a"})); r.Code != state.Applied {
		t.Fatal("assign nodes", r)
	}

	var moduleZIP bytes.Buffer
	w := zip.NewWriter(&moduleZIP)
	f, err := w.CreateHeader(&zip.FileHeader{Name: "example.invalid/safe@v1.0.0/safe.go", Method: zip.Store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Write([]byte("package safe\nconst Ready = true\n")); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(moduleZIP.Bytes())
	lock := fmt.Sprintf("- path: example.invalid/safe\n  version: v1.0.0\n  sha256: %s\n  size: %d\n", hex.EncodeToString(sum[:]), moduleZIP.Len())

	policy := n.file("lifecycle-policy.yaml", `version: 1
enabled: true
execution:
  max_concurrent: 1
  timeout: 5s
  cpu: 0.1
  memory: 32MiB
  max_pids: 16
  output: 4KiB
  probe: 4KiB
  capabilities: [file]
resolver:
  allow_packages: [context, example.invalid/safe, github.com/jay94ks/seafield/lifecycle/v1]
  modules:
`+indent(lock, "    ")+`  source_cache: 1MiB
`)
	n.run(0, "lifecycle", "policy", "set", "-f", policy, "--id", "policy-1")
	if op := n.opState("policy-1"); op.State != cli.Done {
		t.Fatalf("policy op: %+v", op)
	}
	shown := n.run(0, "lifecycle", "policy", "show")
	if !strings.Contains(shown, "version: 1") || !strings.Contains(shown, "example.invalid/safe") || !strings.Contains(shown, "memory: 32MiB") {
		t.Fatal("policy show:\n" + shown)
	}
	// What show prints can be set again unchanged.
	n.run(0, "lifecycle", "policy", "set", "-f", n.file("again.yaml", shown))

	source := n.file("ready.go", "package checker\n// first\n")
	locks := n.file("modules.yaml", lock)
	zipFile := filepath.Join(n.root, "safe.zip")
	if err := os.WriteFile(zipFile, moduleZIP.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	put := []string{"lifecycle", "script", "put", "ready", "-f", source, "--modules", locks, "--module", "example.invalid/safe=" + zipFile, "--id", "put-1"}
	n.run(0, put...)
	if op := n.opState("put-1"); op.State != cli.Done || op.Kind != "lifecycle-script" {
		t.Fatalf("put op: %+v", op)
	}
	view, err := n.m.Runtime.Engine().Read(n.m.ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	before := view.State.Index()
	// The same ID continues the saved put; the files are not read again and
	// nothing is proposed again.
	if err := os.Remove(source); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(zipFile); err != nil {
		t.Fatal(err)
	}
	n.run(0, put...)
	if view, err = n.m.Runtime.Engine().Read(n.m.ctx, true); err != nil || view.State.Index() != before {
		t.Fatal("repeated put proposed again", err)
	}

	list := n.run(0, "lifecycle", "script", "list")
	if !strings.Contains(list, "ready") {
		t.Fatal("script list:\n" + list)
	}
	if out := n.run(0, "lifecycle", "script", "show", "ready", "--source"); !strings.Contains(out, "// first") {
		t.Fatal("script show --source:\n" + out)
	}
	n.run(0, "op", "show", "put-1")
	n.run(2, "lifecycle", "script", "retire", "ready")
	n.run(0, "lifecycle", "script", "retire", "ready", "--revision", "1")
	n.run(0, "lifecycle", "script", "delete", "ready", "--revision", "1")
	if out := n.run(0, "lifecycle", "script", "list"); !strings.Contains(out, "deleted") {
		t.Fatal("deleted revision not shown as deleted:\n" + out)
	}
}

func indent(text, prefix string) string {
	lines := strings.SplitAfter(text, "\n")
	var b strings.Builder
	for _, l := range lines {
		if l != "" {
			b.WriteString(prefix + l)
		}
	}
	return b.String()
}

func TestIngressHostAndBlockCommands(t *testing.T) {
	n := newGroup9Node(t)
	n.run(0, "ingress", "hosts", "set", "--external-allowed", "--external", "shop.example.com,*.shop.example.com", "--local", "shop.lan")
	out := n.run(0, "ingress", "hosts", "show")
	if !strings.Contains(out, "*.shop.example.com") || !strings.Contains(out, "shop.lan") {
		t.Fatal("hosts show:\n" + out)
	}
	n.run(2, "ingress", "block", "b1", "--scope", "route")
	n.run(0, "--reason", "maintenance", "ingress", "block", "b1", "--scope", "tenant", "--for", "1h")
	if out = n.run(0, "ingress", "blocks"); !strings.Contains(out, "b1") {
		t.Fatal("blocks:\n" + out)
	}
	n.run(0, "ingress", "extend", "b1", "--for", "2h")
	n.run(0, "ingress", "unblock", "b1")
	if out = n.run(0, "ingress", "blocks"); !strings.Contains(out, "removed") {
		t.Fatal("unblocked block not shown as removed:\n" + out)
	}
}

func TestCertificateCommands(t *testing.T) {
	n := newGroup9Node(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "shop.example.com"}, DNSNames: []string{"shop.example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	chain := n.file("chain.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	keyFile := n.file("key.pem", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rawKey})))

	n.run(2, "certificate", "put", "shop", "--chain", chain, "--key", keyFile)
	n.run(0, "domain", "add", "example.com")
	n.run(0, "certificate", "put", "--chain", chain, "--key", keyFile, "--id", "cert-1")
	if op := n.opState("cert-1"); op.State != cli.Done || op.Kind != "certificate-put" || strings.Contains(op.Summary, "PRIVATE") {
		t.Fatalf("certificate op: %+v", op)
	}
	// The key is not read again for the same ID.
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	n.run(0, "certificate", "put", "--chain", chain, "--key", keyFile, "--id", "cert-1")
	// A second upload of the same chain is reported, not sent.
	if out := n.run(0, "certificate", "put", "--chain", chain, "--key", keyFile); !strings.Contains(out, "linked") {
		t.Fatal("existing certificate not reported:\n" + out)
	}
	sum := sha256.Sum256(der)
	id := hex.EncodeToString(sum[:])
	if out := n.run(0, "certificate", "list"); !strings.Contains(out, id[:12]) || !strings.Contains(out, "linked") {
		t.Fatal("certificate list:\n" + out)
	}
	if out := n.run(0, "certificate", "list", "--unlinked"); strings.Contains(out, id[:12]) {
		t.Fatal("linked certificate listed as unlinked:\n" + out)
	}
	for _, arg := range []string{"shop.example.com", id[:12], id} {
		if out := n.run(0, "certificate", "show", arg); !strings.Contains(out, id) || !strings.Contains(out, "CN=shop.example.com") {
			t.Fatal("certificate show " + arg + ":\n" + out)
		}
	}
	if out := n.run(0, "certificate", "show", "--issuer", "shop.example.com", "--serial", "1"); !strings.Contains(out, id) {
		t.Fatal("certificate show by issuer and serial:\n" + out)
	}
	n.run(1, "certificate", "delete", id[:12])
	n.run(0, "certificate", "disable", id[:12])
	if out := n.run(0, "certificate", "list", "--pending"); !strings.Contains(out, "disabled") {
		t.Fatal("disabled certificate not pending destroy:\n" + out)
	}
	n.run(0, "certificate", "delete", id[:12])
}

func TestDomainCommands(t *testing.T) {
	n := newGroup9Node(t)
	n.run(2, "domain", "add", "co.kr")
	n.run(0, "domain", "add", "Shop.Example.com")
	n.run(1, "domain", "add", "shop.example.com")
	n.run(0, "domain", "add", "예시.한국")
	out := n.run(0, "domain", "list")
	if !strings.Contains(out, "shop.example.com") || !strings.Contains(out, "예시.한국") || !strings.Contains(out, "xn--vv4b11d.xn--3e0b707e") {
		t.Fatal("domain list:\n" + out)
	}
	n.run(0, "domain", "remove", "shop.example.com")
	n.run(1, "domain", "remove", "shop.example.com")
	if out = n.run(0, "domain", "list", "-o", "json"); strings.Contains(out, "shop.example.com") || !strings.Contains(out, `"added_by"`) {
		t.Fatal("domain list after remove:\n" + out)
	}
}

func TestLifecyclePolicyFileRoundTrip(t *testing.T) {
	p := checker.TenantPolicy{Tenant: "shop", Enabled: true,
		Execution: checker.ExecutionPolicy{MaxConcurrent: 1, TimeoutMS: 5000, NanoCPU: 100_000_000, MemoryBytes: 32 << 20, MaxPIDs: 16, OutputBytes: 4096, ProbeBytes: 4096, Capabilities: []string{"file"}},
		Resolver:  checker.ResolverPolicy{AllowPackages: []string{"context"}, SourceCacheBytes: 1 << 20, Modules: []checker.ModulePin{{Path: "example.invalid/safe", Version: "v1.0.0", Digest: [32]byte{1}, Length: 10}}}}
	var out bytes.Buffer
	if err := writeLifecyclePolicy(&out, p); err != nil {
		t.Fatal(err)
	}
	var f lifecyclePolicyFile
	d := yaml.NewDecoder(bytes.NewReader(out.Bytes()))
	d.KnownFields(true)
	if err := d.Decode(&f); err != nil {
		t.Fatal(err, out.String())
	}
	back, err := f.policy("shop")
	if err != nil {
		t.Fatal(err, out.String())
	}
	if back.Execution.MemoryBytes != p.Execution.MemoryBytes || back.Execution.TimeoutMS != 5000 || back.Execution.NanoCPU != p.Execution.NanoCPU || back.Resolver.Modules[0] != p.Resolver.Modules[0] {
		t.Fatalf("round trip changed the policy: %+v", back)
	}
	f.Version = 2
	if _, err = f.policy("shop"); err == nil {
		t.Fatal("version 2 accepted")
	}
	f.Version, f.Execution.Timeout = 1, "soon"
	if _, err = f.policy("shop"); err == nil || !strings.Contains(err.Error(), "execution.timeout") {
		t.Fatal("bad time accepted", err)
	}
}
