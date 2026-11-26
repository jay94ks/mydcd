// SPDX-License-Identifier: Apache-2.0

// Package gitfixture is an owned smart-HTTPS Git server for actual source/CD
// adapter tests. It creates real Git objects/packs; it never supplies a MyDC
// ticket, candidate, operation result, native observation or approval.
package gitfixture

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/protocol/packp"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/jay94ks/mydcd/internal/config"
)

type Stats struct {
	Advertisements, Packs, Denied int
	Wants                         []string
}

type Fixture struct {
	t      *testing.T
	mu     sync.Mutex
	server *httptest.Server
	store  *memory.Storage
	work   *git.Worktree
	head   plumbing.Hash
	serial int64
	mode   string
	stats  Stats
	gate   *PackGate
}

// PackGate holds one actual upload-pack response. Cancellation still ends the
// request; it never supplies bytes, a candidate or a successful MyDC result.
type PackGate struct {
	Entered <-chan struct{}
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *PackGate) Release() { g.once.Do(func() { close(g.release) }) }

func (f *Fixture) HoldNextPack() *PackGate {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.gate != nil {
		f.t.Fatal("original Git pack gate is already pending")
	}
	entered := make(chan struct{})
	g := &PackGate{Entered: entered, entered: entered, release: make(chan struct{})}
	f.gate = g
	f.t.Cleanup(g.Release)
	return g
}

const username = "git-reader"
const password = "private-native-git-fixture-token"

func Open(t *testing.T) *Fixture {
	return OpenAt(t, "")
}

// OpenAt binds the owned TLS source to an explicitly planned namespace address.
// The empty address preserves the original loopback fixture behavior.
func OpenAt(t *testing.T, address string) *Fixture {
	return open(t, address, false)
}

// OpenEmptyLoopbackAt restores the address/default TLS identity of Open before
// its first Commit. The caller must check the original CA and empty history.
func OpenEmptyLoopbackAt(t *testing.T, address string) *Fixture {
	return open(t, address, true)
}

func open(t *testing.T, address string, originalLoopback bool) *Fixture {
	t.Helper()
	f := &Fixture{t: t, store: memory.NewStorage()}
	repo, err := git.Init(f.store, memfs.New())
	if err != nil {
		t.Fatal(err)
	}
	f.work, err = repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if address == "" {
		f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	} else {
		host, _, err := net.SplitHostPort(address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.IsUnspecified() {
			t.Fatal("explicit owned Git source IP required", address, err)
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		if originalLoopback {
			if !ip.IsLoopback() {
				t.Fatal("original loopback Git input required")
			}
			f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
			_ = f.server.Listener.Close()
			f.server.Listener = listener
			f.server.StartTLS()
			t.Cleanup(f.server.Close)
			return f
		}
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned-git-source"}, IPAddresses: []net.IP{ip}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, public, private)
		if err != nil {
			t.Fatal(err)
		}
		f.server = httptest.NewUnstartedServer(http.HandlerFunc(f.serve))
		_ = f.server.Listener.Close()
		f.server.Listener = listener
		f.server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
		f.server.StartTLS()
	}
	t.Cleanup(f.server.Close)
	return f
}

func (f *Fixture) Repository() string { return f.server.URL + "/repo.git" }

// Close allows a larger system scenario to stop its source before comparing
// host rollback. The registered Cleanup remains an idempotent failure fallback.
func (f *Fixture) Close() { f.server.Close() }

// Credential supplies an installation-local profile, with the real server CA
// and a private token file. No password or source bytes enter shared metadata.
func (f *Fixture) Credential(root, tenant, profile string) config.GitCredential {
	f.t.Helper()
	token, ca := filepath.Join(root, "git-fixture-token"), filepath.Join(root, "git-fixture-ca.pem")
	if err := os.WriteFile(token, []byte(password+"\n"), 0600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0644); err != nil {
		f.t.Fatal(err)
	}
	return config.GitCredential{Tenant: tenant, Profile: profile, Repository: f.Repository(), Username: username, PasswordFile: token, CAFile: ca}
}

func (f *Fixture) Commit(body []byte) string {
	return f.CommitFiles(map[string][]byte{"app.yaml": body})
}

// CommitFiles updates real Git blobs in one commit. Existing app.yaml callers
// retain their original history; build fixtures can supply a Dockerfile and
// context files without impersonating a fetched MyDC version or build result.
func (f *Fixture) CommitFiles(files map[string][]byte) string {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	names := make([]string, 0, len(files))
	for name := range files {
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || name == "." || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			f.t.Fatal("invalid owned Git fixture file path")
		}
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if err := f.work.Filesystem.MkdirAll(path.Dir(name), 0755); err != nil {
			f.t.Fatal(err)
		}
		file, err := f.work.Filesystem.Create(name)
		if err != nil {
			f.t.Fatal(err)
		}
		_, writeErr := file.Write(files[name])
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			f.t.Fatal(writeErr, closeErr)
		}
		if _, err := f.work.Add(name); err != nil {
			f.t.Fatal(err)
		}
	}
	f.serial++
	var err error
	f.head, err = f.work.Commit(fmt.Sprintf("fixture-%d", f.serial), &git.CommitOptions{Author: &object.Signature{Name: "fixture", Email: "fixture@mydc.test", When: time.Unix(f.serial, 0)}})
	if err != nil {
		f.t.Fatal(err)
	}
	return f.head.String()
}

func (f *Fixture) Mode(mode string) {
	f.t.Helper()
	if mode != "" && mode != "unauthorized" && mode != "unavailable" {
		f.t.Fatal("unsupported Git fixture fault")
	}
	f.mu.Lock()
	f.mode = mode
	f.mu.Unlock()
}

func (f *Fixture) Stats() Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.stats
	out.Wants = append([]string(nil), f.stats.Wants...)
	return out
}

func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	locked := true
	defer func() {
		if locked {
			f.mu.Unlock()
		}
	}()
	user, secret, ok := r.BasicAuth()
	if !ok || user != username || secret != password || f.mode == "unauthorized" {
		f.stats.Denied++
		http.Error(w, "private-fixture-auth-detail", http.StatusUnauthorized)
		return
	}
	if f.mode == "unavailable" {
		http.Error(w, "private-fixture-provider-detail", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/repo.git/info/refs" && r.URL.Query().Get("service") == "git-upload-pack" && !f.head.IsZero() {
		f.stats.Advertisements++
		advert := packp.NewAdvRefs()
		advert.Head = &f.head
		advert.References["refs/heads/main"] = f.head
		advert.Prefix = [][]byte{[]byte("# service=git-upload-pack\n"), nil}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		if err := advert.Encode(w); err != nil {
			f.t.Error(err)
		}
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/repo.git/git-upload-pack" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	request := packp.NewUploadPackRequest()
	if err := request.Decode(r.Body); err != nil || len(request.Wants) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.stats.Packs++
	for _, wanted := range request.Wants {
		f.stats.Wants = append(f.stats.Wants, wanted.String())
	}
	var hashes []plumbing.Hash
	iter, err := f.store.IterEncodedObjects(plumbing.AnyObject)
	if err == nil {
		err = iter.ForEach(func(encoded plumbing.EncodedObject) error {
			hashes = append(hashes, encoded.Hash())
			return nil
		})
	}
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	var pack bytes.Buffer
	if _, err := packfile.NewEncoder(&pack, f.store, false).Encode(hashes, 0); err != nil {
		f.t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	gate := f.gate
	f.gate = nil
	f.mu.Unlock()
	locked = false
	if gate != nil {
		close(gate.entered)
		select {
		case <-gate.release:
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	_, _ = io.WriteString(w, "0008NAK\n")
	_, _ = w.Write(pack.Bytes())
}
