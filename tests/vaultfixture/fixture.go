// SPDX-License-Identifier: Apache-2.0

// Package vaultfixture owns a pinned real Vault/TLS/file-storage test instance.
package vaultfixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every process/port/file below is owned by this test. Provision the pinned
// tool explicitly; ordinary test execution never downloads or installs it.
type Vault struct {
	t                                                    *testing.T
	binary, Root, Address, clusterAddress, configuration string
	Client                                               *http.Client
	Roots                                                *x509.CertPool
	process                                              *exec.Cmd
	done                                                 chan error
	log                                                  *os.File
	Admin, Unseal, CAFile                                string
	persistentRoot                                       bool
}

func Open(t *testing.T) *Vault {
	t.Helper()
	return open(t, "")
}

// OpenAt preserves the caller-owned provider DB/config on a failed system
// scenario. The caller owns removing the new absolute directory after positive
// product closure; ordinary Open keeps its original TempDir behavior.
func OpenAt(t *testing.T, root string) *Vault {
	t.Helper()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("explicit new absolute Vault fixture directory required")
	}
	return open(t, root)
}

func open(t *testing.T, root string) *Vault {
	t.Helper()
	binary := pinnedBinary(t)
	return openNew(t, root, binary)
}

func pinnedBinary(t *testing.T) string {
	t.Helper()
	requested := os.Getenv("MYDC_VAULT_TEST_BINARY")
	path := requested
	if path == "" {
		// the repository's work/ directory, whichever package runs the test
		_, self, _, _ := runtime.Caller(0)
		path = filepath.Join(filepath.Dir(self), "../../work/toolchains/vault1.21.0/vault")
	}
	binary, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(binary)
	if os.IsNotExist(err) {
		if requested != "" {
			t.Fatal("explicit pinned Vault test binary missing")
		}
		t.Skip("explicitly provision docs/development/vault-test-toolchain.json before real Vault tests")
	}
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	_ = f.Close()
	if err != nil || fmt.Sprintf("%x", h.Sum(nil)) != "7f08db3dd470ed8354665284cca5337362012f30e158510a27a4516f1403d0ba" {
		t.Fatal("pinned Vault test binary differs")
	}
	return binary
}

// ResumeAt reopens only the caller's original TLS/config/file-storage state.
// It never initializes storage, remints credentials or extends their lifetime.
func ResumeAt(t *testing.T, root, address, admin, unseal string) *Vault {
	t.Helper()
	return ResumeWithTLS(t, root, address, admin, unseal, filepath.Join(root, "vault.hcl"), filepath.Join(root, "tls.pem"))
}

// ResumeWithTLS selects explicit test TLS/config files while preserving the
// original file-storage DB. It never initializes storage or writes KV values.
func ResumeWithTLS(t *testing.T, root, address, admin, unseal, configuration, caFile string) *Vault {
	t.Helper()
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(configuration) || !filepath.IsAbs(caFile) || admin == "" || unseal == "" {
		t.Fatal("original private Vault recovery input required")
	}
	v := &Vault{t: t, binary: pinnedBinary(t), Root: root, Address: address, Admin: admin, Unseal: unseal,
		configuration: configuration, CAFile: caFile, persistentRoot: true}
	ca, err := os.ReadFile(v.CAFile)
	v.Roots = x509.NewCertPool()
	if err != nil || !v.Roots.AppendCertsFromPEM(ca) {
		t.Fatal("original Vault TLS trust missing", err)
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: v.Roots}}
	v.Client = &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { v.Stop(); transport.CloseIdleConnections(); v.Admin, v.Unseal = "", "" })
	v.Start()
	v.UnsealOriginal()
	return v
}

func openNew(t *testing.T, root, binary string) *Vault {
	t.Helper()
	persistentRoot := root != ""
	if root == "" {
		root = t.TempDir()
	} else if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal("refuse replacing the original provider DB", err)
	}
	v := &Vault{t: t, binary: binary, Root: root, persistentRoot: persistentRoot}
	free := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		a := l.Addr().String()
		_ = l.Close()
		return a
	}
	v.Address, v.clusterAddress = "https://"+free(), "https://"+free()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-vault-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	v.Roots = x509.NewCertPool()
	v.Roots.AddCert(parsed)
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	if err = os.WriteFile(filepath.Join(root, "tls.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	v.CAFile = filepath.Join(root, "tls.pem")
	v.configuration = filepath.Join(root, "vault.hcl")
	config := fmt.Sprintf("disable_mlock = true\napi_addr = %q\ncluster_addr = %q\nstorage \"file\" { path = %q }\nlistener \"tcp\" {\n address = %q\n cluster_address = %q\n tls_cert_file = %q\n tls_key_file = %q\n}\n", v.Address, v.clusterAddress, filepath.Join(root, "data"), strings.TrimPrefix(v.Address, "https://"), strings.TrimPrefix(v.clusterAddress, "https://"), filepath.Join(root, "tls.pem"), filepath.Join(root, "tls.key"))
	if err = os.WriteFile(v.configuration, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: v.Roots}}
	v.Client = &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() { v.Stop(); transport.CloseIdleConnections(); v.Admin, v.Unseal = "", "" })
	v.Start()
	var initialized struct {
		Keys  []string `json:"keys_base64"`
		Token string   `json:"root_token"`
	}
	v.API("POST", "sys/init", map[string]any{"secret_shares": 1, "secret_threshold": 1}, &initialized, "")
	if len(initialized.Keys) != 1 || initialized.Token == "" {
		t.Fatal("real Vault initialization returned no owned key/token")
	}
	v.Admin, v.Unseal = initialized.Token, initialized.Keys[0]
	v.UnsealOriginal()
	v.API("POST", "sys/mounts/kv", map[string]any{"type": "kv", "options": map[string]string{"version": "2"}}, nil, v.Admin)
	v.API("PUT", "sys/policies/acl/mydc-system-reader", map[string]any{"policy": `path "kv/data/system/credentials/*" { capabilities = ["read"] }`}, nil, v.Admin)
	return v
}

func (v *Vault) Start() {
	v.t.Helper()
	if v.process != nil {
		v.t.Fatal("owned Vault already running")
	}
	var err error
	v.log, err = os.OpenFile(filepath.Join(v.Root, "server.log"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		v.t.Fatal(err)
	}
	v.process = exec.Command(v.binary, "server", "-config="+v.configuration, "-log-level=error")
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "VAULT_") && !strings.HasPrefix(item, "GOMAXPROCS=") {
			v.process.Env = append(v.process.Env, item)
		}
	}
	v.process.Env = append(v.process.Env, "GOMAXPROCS=2")
	v.process.Stdout, v.process.Stderr = v.log, v.log
	if err = v.process.Start(); err != nil {
		v.process = nil
		_ = v.log.Close()
		v.t.Fatal(err)
	}
	v.done = make(chan error, 1)
	cmd := v.process
	go func() { v.done <- cmd.Wait() }()
	if v.persistentRoot {
		// Caller-owned diagnostics survive a coordinator crash. Never put
		// tokens/unseal material in this exact process-ownership record.
		stat, statErr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", cmd.Process.Pid))
		boot, bootErr := os.ReadFile("/proc/sys/kernel/random/boot_id")
		start := strings.LastIndexByte(string(stat), ')')
		fields := strings.Fields(string(stat)[max(0, start+1):])
		if statErr != nil || bootErr != nil || start < 0 || len(fields) <= 19 {
			v.Stop()
			v.t.Fatal("cannot preserve original provider ownership", statErr, bootErr)
		}
		record := map[string]any{"schema": 1, "pid": cmd.Process.Pid, "start_ticks": fields[19], "command": cmd.Args, "host_boot": strings.TrimSpace(string(boot))}
		raw, err := json.Marshal(record)
		if err == nil {
			var file *os.File
			file, err = os.OpenFile(filepath.Join(v.Root, ".process-owner.next"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err == nil {
				_, err = file.Write(raw)
				if err == nil {
					err = file.Sync()
				}
				closeErr := file.Close()
				if err == nil {
					err = closeErr
				}
			}
			if err == nil {
				err = os.Rename(filepath.Join(v.Root, ".process-owner.next"), filepath.Join(v.Root, "process-owner.json"))
			}
			if err == nil {
				var dir *os.File
				dir, err = os.Open(v.Root)
				if err == nil {
					err = dir.Sync()
					closeErr := dir.Close()
					if err == nil {
						err = closeErr
					}
				}
			}
		}
		if err != nil {
			v.Stop()
			v.t.Fatal("cannot preserve original provider process record")
		}
	}
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err := v.Client.Get(v.Address + "/v1/sys/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
			_ = r.Body.Close()
			return
		}
		select {
		case err := <-v.done:
			v.process = nil
			_ = v.log.Close()
			v.t.Fatal("owned Vault terminated before health", err)
		case <-deadline.C:
			v.t.Fatal("owned Vault health unavailable")
		case <-tick.C:
		}
	}
}

func (v *Vault) Stop() {
	v.t.Helper()
	if v.process == nil {
		return
	}
	_ = v.process.Process.Signal(syscall.SIGTERM)
	select {
	case <-v.done:
	case <-time.After(3 * time.Second):
		_ = v.process.Process.Kill()
		<-v.done
	}
	v.process = nil
	_ = v.log.Close()
}

func (v *Vault) API(method, path string, input, output any, token string) {
	v.t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		v.t.Fatal("private Vault request encoding failed")
	}
	defer clear(raw)
	request, err := http.NewRequestWithContext(context.Background(), method, v.Address+"/v1/"+path, bytes.NewReader(raw))
	if err != nil {
		v.t.Fatal("owned Vault request construction failed")
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := v.Client.Do(request)
	if err != nil {
		v.t.Fatal("owned Vault request transport failed", method, path)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		v.t.Fatal("owned Vault API rejected request", method, path, response.StatusCode)
	}
	if output != nil && json.NewDecoder(response.Body).Decode(output) != nil {
		v.t.Fatal("private Vault response decode failed")
	}
}

func (v *Vault) UnsealOriginal() {
	v.API("POST", "sys/unseal", map[string]any{"key": v.Unseal}, nil, "")
}
func (v *Vault) ReaderToken() string {
	v.t.Helper()
	var out struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	v.API("POST", "auth/token/create", map[string]any{"policies": []string{"mydc-system-reader"}, "no_default_policy": true, "ttl": "5m"}, &out, v.Admin)
	if out.Auth.Token == "" {
		v.t.Fatal("owned system reader token missing")
	}
	return out.Auth.Token
}
