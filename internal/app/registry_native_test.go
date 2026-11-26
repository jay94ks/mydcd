// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/registry"
	"github.com/jay94ks/mydcd/internal/userauth"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
	"github.com/jay94ks/mydcd/tests/gitfixture"
	"github.com/jay94ks/mydcd/tests/registryfixture"
	"github.com/moby/moby/api/pkg/authconfig"
	dockerauth "github.com/moby/moby/api/types/registry"
	"github.com/moby/moby/client"
)

// Owned Docker/host rollback and explicit non-insecure host IP are mandatory.
// No compiler/daemon build, remote image download or hidden TLS bypass here.
func TestE5ManagedRegistryCLIEngineAndAppRecovery(t *testing.T) {
	if os.Getenv("MYDC_REGISTRY_TEST_IP") == "" {
		t.Skip("explicit installed non-loopback IPv4 and E5 rollback baseline required")
	}
	if os.Getenv("MYDC_STORAGE_TEST_ROOT") == "" || os.Getenv("MYDC_STORAGE_TEST_OWNER") == "" || os.Getenv("MYDC_STORAGE_HOST_MOUNT_NS") == "" {
		t.Skip("E5 requires S1 owned ext4/private mount namespace inputs for fixed registry backing")
	}
	runManagedAppOwner(t, true, true, true, true, managedAppRegistry, true, false, false)
}

type managedRegistryNative struct {
	address, certFile, keyFile      string
	certificate                     []byte
	http                            *http.Client
	spec                            registry.Specification
	cli                             func([]*os.File, ...string) []byte
	runCLI                          func([]*os.File, ...string) ([]byte, []byte, error)
	public                          map[string]any
	save                            func()
	original                        control.RegistryRunRef
	native                          volumes.NativeReady
	upload                          string
	prefix                          []byte
	reference                       string
	seedPushIssued, seedPushExpires int64
	buildGit                        *gitfixture.Fixture
}

func configureManagedRegistryNative(t *testing.T, root, document string) (string, *managedRegistryNative) {
	t.Helper()
	ip, err := netip.ParseAddr(os.Getenv("MYDC_REGISTRY_TEST_IP"))
	if err != nil || !ip.Is4() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		t.Fatal("explicit installed non-loopback IPv4 required", err)
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	installed := false
	for _, a := range addresses {
		p, e := netip.ParsePrefix(a.String())
		installed = installed || e == nil && p.Addr() == ip
	}
	if !installed {
		t.Fatal("registry IP isn't installed on this host")
	}
	l, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	address := l.Addr().String()
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	// The certificate store refuses Ed25519; ECDSA P-256 is its default.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &key.PublicKey
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "owned-e5-registry"}, IPAddresses: []net.IP{net.IP(ip.AsSlice())}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f := &managedRegistryNative{address: address, certFile: filepath.Join(root, "registry-cert.pem"), keyFile: filepath.Join(root, "registry-key.pem"), certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	if err = os.WriteFile(f.certFile, f.certificate, 0600); err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	defer clear(encoded)
	if err = os.WriteFile(f.keyFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(f.certificate) {
		t.Fatal("owned certificate parse")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}, Proxy: nil}
	f.http = &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(transport.CloseIdleConnections)
	// The registry takes its pair from the cluster certificate store by the
	// authority host; installCertificate registers the IP and puts the pair.
	return document, f
}

func registryNativeWait(t *testing.T, ctx context.Context, label string, ready func() bool) {
	t.Helper()
	for !ready() {
		select {
		case <-ctx.Done():
			t.Fatal(label, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Engine CA is a new exact address directory; existing paths are never changed.
func (f *managedRegistryNative) installEngineCA(t *testing.T, ctx context.Context, c *engine.Client) {
	t.Helper()
	info, err := c.API.Info(ctx, client.InfoOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ip, err := netip.ParseAddrPort(f.address)
	if err != nil {
		t.Fatal(err)
	}
	if info.Info.RegistryConfig == nil {
		t.Fatal("Engine registry security configuration unavailable")
	}
	for _, prefix := range info.Info.RegistryConfig.InsecureRegistryCIDRs {
		if prefix.Contains(ip.Addr()) {
			t.Fatal("insecure registry CIDR would invalidate Engine TLS proof", prefix)
		}
	}
	if index := info.Info.RegistryConfig.IndexConfigs[f.address]; index != nil && !index.Secure {
		t.Fatal("explicit insecure registry would invalidate TLS proof")
	}
	parent := "/etc/docker/certs.d"
	parentInfo, parentErr := os.Lstat(parent)
	absent := os.IsNotExist(parentErr)
	if parentErr != nil && !absent {
		t.Fatal(parentErr)
	}
	if !absent && (!parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0) {
		t.Fatal("CA parent must be an ordinary directory")
	}
	dir := filepath.Join(parent, f.address)
	path := filepath.Join(dir, "ca.crt")
	if _, err = os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatal("new registry CA directory required", err)
	}
	hash := sha256.Sum256(f.certificate)
	f.public["RegistryCAPath"], f.public["RegistryCASHA256"], f.public["RegistryCAParentCreated"] = path, hex.EncodeToString(hash[:]), absent
	f.save()
	var dirInfo, caInfo os.FileInfo
	var written []byte
	madeParent := false
	t.Cleanup(func() {
		// The Runtime cleanup registered later runs before this callback.
		if parentInfo == nil {
			if madeParent {
				t.Error("CA parent identity not obtained; preserve it")
			}
			return
		}
		current, e := os.Lstat(parent)
		if e != nil || !os.SameFile(parentInfo, current) {
			t.Error("CA parent identity changed", e)
			return
		}
		if dirInfo != nil {
			current, e = os.Lstat(dir)
			if e != nil || !os.SameFile(dirInfo, current) {
				t.Error("CA directory identity changed", e)
				return
			}
			if caInfo != nil {
				current, e = os.Lstat(path)
				data, readErr := os.ReadFile(path)
				if e != nil || readErr != nil || !os.SameFile(caInfo, current) || !bytes.Equal(data, written) {
					t.Error("CA file changed; preserving it", e, readErr)
					return
				}
				if e = os.Remove(path); e != nil {
					t.Error(e)
					return
				}
			}
			if e = os.Remove(dir); e != nil {
				t.Error(e)
				return
			}
		}
		if madeParent {
			if e = os.Remove(parent); e != nil {
				t.Error("owned CA parent isn't empty", e)
				return
			}
		}
		f.public["RegistryCARestored"] = true
		f.save()
	})
	if absent {
		if err = os.Mkdir(parent, 0755); err != nil {
			t.Fatal(err)
		}
		madeParent = true
		parentInfo, err = os.Lstat(parent)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	dirInfo, err = os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		t.Fatal(err)
	}
	caInfo, err = fd.Stat()
	if err != nil {
		fd.Close()
		t.Fatal(err)
	}
	n, err := fd.Write(f.certificate)
	written = slices.Clone(f.certificate[:n])
	if err == nil {
		err = fd.Sync()
	}
	closeErr := fd.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}

}

func (f *managedRegistryNative) request(t *testing.T, ctx context.Context, method, path, token string, body []byte, headers map[string]string) (http.Header, []byte, int) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, "https://"+f.address+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	response, err := f.http.Do(req)
	if err != nil {
		t.Fatal("owned registry HTTP request", method, path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal("bounded registry response", err)
	}
	return response.Header.Clone(), data, response.StatusCode
}

func (f *managedRegistryNative) credential(t *testing.T, access string) []byte {
	t.Helper()
	file, err := os.CreateTemp(filepath.Dir(f.certFile), "registry-login-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close(); _ = os.Remove(file.Name()) }()
	output := f.cli([]*os.File{file}, "registry", "credential", f.spec.ID, "--tenant", "tenant", "--repository", "fixture", "--access", access, "--output-fd", "3")
	var metadata struct {
		Status, Authority, Username, Repository string
		ExpiresAt                               int64 `json:"expires_at"`
	}
	if json.Unmarshal(output, &metadata) != nil || metadata.Status != "credential-delivered" || metadata.Authority != f.address || metadata.Username != "admin" || metadata.Repository != "fixture" || bytes.Contains(output, []byte("mydc-registry-login-1.")) {
		t.Fatal("registry CLI public credential receipt invalid")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	secret, err := io.ReadAll(io.LimitReader(file, (12<<10)+1))
	if err != nil || len(secret) > 12<<10 {
		t.Fatal("bounded protected credential", err)
	}
	secret = bytes.TrimSuffix(secret, []byte{'\n'})
	if _, err = registry.ParseLogin(string(secret), time.Now().Unix()); err != nil {
		clear(secret)
		t.Fatal("derived registry login invalid", err)
	}
	return secret
}

func (f *managedRegistryNative) token(t *testing.T, ctx context.Context, secret []byte, scope string) string {
	return f.tokenFor(t, ctx, "admin", secret, scope)
}
func (f *managedRegistryNative) tokenFor(t *testing.T, ctx context.Context, username string, secret []byte, scope string) string {
	t.Helper()
	target := "https://" + f.address + "/token?" + url.Values{"service": {f.address}, "scope": {scope}}.Encode()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(username, string(secret))
	response, err := f.http.Do(req)
	if err != nil {
		t.Fatal("registry login exchange", err)
	}
	defer response.Body.Close()
	var result registry.TokenResponse
	err = json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&result)
	if err != nil || response.StatusCode != 200 || result.Token == "" {
		t.Fatal("registry token exchange refused", response.StatusCode, err)
	}
	return result.Token
}

// prepareCLI reuses the protected-descriptor account path without starting a
// managed registry, builder, or another native application.
func (f *managedRegistryNative) prepareCLI(t *testing.T, ctx context.Context, root string, cluster [32]byte, peer mydcp.Peer) {
	t.Helper()
	home := filepath.Join(root, "registry-cli-home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "registry-cli.yaml")
	document := fmt.Sprintf("version: 1\nauth: user\ncluster: '%x'\npeers:\n - {id: node-a, key: '%x', endpoint: '%s', voter: true}\n", cluster, peer.Key, peer.Endpoint)
	if err := os.WriteFile(profile, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	f.runCLI = func(inputs []*os.File, args ...string) ([]byte, []byte, error) {
		return runManagedCLICommand(ctx, os.Getenv("MYDC_TEST_CLI"), home, profile, args, inputs)
	}
	f.cli = func(inputs []*os.File, args ...string) []byte {
		t.Helper()
		output, diagnostic, err := f.runCLI(inputs, args...)
		if err != nil {
			// Mutation refusals use stdout for their original receipt. Keep
			// those public facts without dumping credential/content responses.
			var receipt struct {
				Result *struct {
					Code                        uint8
					Index, Revision, Generation uint64
				}
			}
			if json.Unmarshal(output, &receipt) == nil && receipt.Result != nil {
				t.Log("original registry mutation result", *receipt.Result)
			}
			t.Fatal("registry CLI", args, err, string(diagnostic))
		}
		return output
	}
	f.cli(nil, "wallet", "init")
	f.cli(nil, "login", "--username", "admin", "--method", "private-key", "--key-file", filepath.Join(root, "admin", "key.pem"))
}

func (f *managedRegistryNative) prepare(t *testing.T, ctx context.Context, owner **Runtime, root string, user userauth.Client, peer mydcp.Peer, p control.Policy, read func() cluster.View, change func(string, string, uint64, any), source *registryfixture.Fixture, public map[string]any, save func()) {
	t.Helper()
	f.public, f.save = public, save
	public["RegistryAddress"], public["RegistryCertificate"], public["RegistrySeedReference"] = f.address, f.certFile, source.Reference
	save()
	f.installEngineCA(t, ctx, (*owner).docker)
	// This callback runs before CA teardown and generic native journal cleanup.
	t.Cleanup(func() {
		if *owner == nil {
			return
		}
		r := *owner
		if t.Failed() {
			r.mu.RLock()
			cause := r.moduleError
			r.mu.RUnlock()
			t.Log("registry fixture first module failure cause", cause)
		}
		if err := r.Close(); err != nil {
			t.Error("registry producer didn't join; retain original writer", err)
			return
		}
		*owner = nil

		var pins []volumes.NativeLease
		for _, row := range r.registryRecords {
			if row.Pin != nil && !row.PinReturned {
				pins = append(pins, *row.Pin)
			}
		}
		public["RegistryJoinedRollbackPins"] = pins
		save()

	})
	f.prepareCLI(t, ctx, root, p.Cluster, peer)
	ip, _ := netip.ParseAddrPort(f.address)
	f.cli(nil, "domain", "add", ip.Addr().String())
	f.cli(nil, "certificate", "put", "--chain", f.certFile, "--key", f.keyFile, "--id", "registry-certificate")
	scope := volumes.Scope{Cluster: p.Cluster, Tenant: "tenant", Registry: "private", ID: "images", Generation: 1}
	public["RegistryScope"] = scope
	save()
	change("registry-volume", "begin-volume-create", 0, control.VolumeCreate{Scope: scope, Node: "node-a", UID: 10001, GID: 10001, Mode: 0700, QuotaMode: "observe"})
	registryNativeWait(t, ctx, "registry native retained Volume", func() bool {
		v, e := p.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		j, ok := v.Creation(scope)
		if ok && j.Ready != nil {
			f.native = *j.Ready
			return true
		}
		return false
	})
	f.spec = registry.Specification{Schema: 1, Tenant: "tenant", ID: "private", Node: "node-a", Address: f.address, Authority: f.address, Volume: scope, Enabled: true, Metadata: registry.MetadataLimits{ManifestBytes: 1 << 20, Records: 64, TotalBytes: 8 << 20}, Blobs: registry.BlobLimits{BlobBytes: 64 << 20, TotalBytes: 128 << 20, Records: 128}, Budget: workload.Resources{CPU: 100000000, Memory: 32 << 20}, MaxRequests: 8, MaxHeaderBytes: 32 << 10, RequestTimeoutMS: 30000, TokenSeconds: 300}
	if os.Getenv("MYDC_TEST_RQ6_LARGE_REGISTRY") == "1" {
		// This is an explicit initial test budget, never a retry-time increase.
		// The actual transfer remains 100 MiB plus tar framing, not 10 GiB.
		f.spec.Blobs.BlobBytes = 128 << 20
		f.spec.Blobs.TotalBytes = 256 << 20
	}
	public["RegistrySpec"], public["RegistryNative"] = f.spec, f.native
	save()
	change("registry-put", "put-registry", 0, control.RegistryPut{Spec: f.spec})
	registryNativeWait(t, ctx, "registry original owner serving", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", "private")
		if ok && entry.Active != nil && entry.Active.Ready != nil {
			f.original = entry.Active.Reference()
			return true
		}
		return false
	})
	f.cli(nil, "registry", "wait", "private", "--tenant", "tenant", "--until", "serving", "--wait-timeout", "30s")
	f.cli(nil, "registry", "list", "--tenant", "tenant")
	if _, _, status := f.request(t, ctx, "GET", "/v2/", "", nil, nil); status != 401 {
		t.Fatal("anonymous registry admitted", status)
	}
	// A separate client with no owned CA must fail this self-signed TLS chain.
	bad := &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: x509.NewCertPool()}}, Timeout: 3 * time.Second}
	response, tlsErr := bad.Get("https://" + f.address + "/v2/")
	if response != nil {
		response.Body.Close()
	}
	bad.CloseIdleConnections()
	if tlsErr == nil {
		t.Fatal("untrusted CA accepted")
	}
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") == "prune-follower" {
		// This remaining scope needs the installed owner/Volume and an empty
		// store, without replaying accepted push/build/large-context/app paths.
		return
	}
	if os.Getenv("MYDC_TEST_RQ6_REGISTRY_MAINTENANCE") == "1" && os.Getenv("MYDC_TEST_RQ6_REMAINING") != "prune-nonempty" {
		f.verifyEmptyRegistryMaintenance(t, ctx, p, read)
	}
	secret := f.credential(t, "pull,push")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull,push")
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") == "prune-nonempty" {
		grant, err := registry.ParseAccess(token, time.Now().Unix())
		if err != nil || grant.Repository != "fixture" || !slices.Contains(grant.Actions, "push") {
			t.Fatal("original seed push lease missing", err)
		}
		f.seedPushIssued, f.seedPushExpires = grant.IssuedAt, grant.ExpiresAt
		public["RegistryRQ6SeedPushIssuedAt"], public["RegistryRQ6SeedPushExpiresAt"] = grant.IssuedAt, grant.ExpiresAt
		save()
	}
	if _, _, status := f.request(t, ctx, "GET", "/v2/foreign/tags/list", token, nil, nil); status != 403 {
		t.Fatal("foreign repository admitted", status)
	}
	seed := source.Reference
	if _, err := (*owner).docker.Image(ctx, seed, true); err != nil {
		t.Fatal("explicit source image preparation", err)
	}
	tag := f.address + "/fixture:owned"
	public["RegistryTagReference"] = tag
	save()
	if _, err := (*owner).docker.API.ImageTag(ctx, client.ImageTagOptions{Source: seed, Target: tag}); err != nil {
		t.Fatal(err)
	}
	auth, err := authconfig.Encode(dockerauth.AuthConfig{ServerAddress: f.address, Username: "admin", Password: string(secret)})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := (*owner).docker.API.ImagePush(ctx, tag, client.ImagePushOptions{RegistryAuth: auth})
	if err != nil {
		t.Fatal("Engine authenticated registry push", err)
	}
	err = stream.Wait(ctx)
	closeErr := stream.Close()
	if err != nil || closeErr != nil {
		t.Fatal("Engine push stream", err, closeErr)
	}
	headers, data, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/owned", token, nil, nil)
	hash := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(hash[:])
	if status != 200 || headers.Get("Docker-Content-Digest") != digest {
		t.Fatal("published manifest digest", status)
	}
	f.verifyRevokedUser(t, ctx, user, peer, p, read, change)
	f.reference = f.address + "/fixture@" + digest
	public["RegistryReference"], public["RegistryRun"], public["Image"] = f.reference, f.original, f.reference
	save()
	// Remove exact temporary seed/tag/digest aliases before the app is accepted.
	// The unique fixture label protects this image, and Docker conflict checks
	// remain enabled. Missing is acceptable; force/shared cache pruning isn't.
	for _, ref := range []string{f.reference, tag, seed} {
		got, e := (*owner).docker.API.ImageInspect(ctx, ref)
		if cerrdefs.IsNotFound(e) {
			continue
		}
		if e != nil || got.Config == nil || got.Config.Labels["org.mydc.test.owner"] != public["Tag"] {
			t.Fatal("prepared image cleanup ownership", e)
		}
		if _, e = (*owner).docker.API.ImageRemove(ctx, ref, client.ImageRemoveOptions{}); e != nil && !cerrdefs.IsNotFound(e) {
			t.Fatal("remove owned temporary image alias", e)
		}
	}
	if _, err = (*owner).docker.API.ImageInspect(ctx, f.reference); !cerrdefs.IsNotFound(err) {
		t.Fatal("app must perform actual private Engine pull", err)
	}
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	if slices.ContainsFunc(tenant.ImageSources, func(rule access.TrustRule) bool { return rule.Registry == f.address }) {
		t.Fatal("registry creation implicitly added trust")
	}
	change("registry-explicit-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: append(tenant.ImageSources, access.TrustRule{Registry: f.address, Repository: "fixture"})})
	// Only the app's source metadata changes. It will pull through the production
	// Task adapter, not through this HTTP fixture's token or its user session.
	source.Reference = f.reference
	source.Registry = f.address
	if os.Getenv("MYDC_TEST_RQ6_REMAINING") == "prune-nonempty" {
		f.verifyRegistryPruneNonemptyNative(t, ctx, *owner, root, p, read)
		return
	}
	if os.Getenv("MYDC_TEST_RQ6_LARGE_REGISTRY") == "1" {
		f.verifyLargeRegistryContent(t, ctx, root, p, read)
	}
	if os.Getenv("MYDC_TEST_RQ6_IMAGE_BUILD") == "1" {
		f.verifyImageBuildNative(t, ctx, owner, root, p, read, change)
	}
}

func (f *managedRegistryNative) checkRunning(t *testing.T, ctx context.Context, owner **Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	r := *owner
	key := deployment.ResourceKey("task", "tenant", "app", "web")
	view := read()
	apps, err := p.Apps(view.State)
	if err != nil {
		t.Fatal(err)
	}
	object := view.State.Object(key)
	task := deployment.ObjectRef{Key: key, Revision: object.Revision, Generation: object.Generation}
	binding, ok := apps.Binding(task)
	if !ok {
		t.Fatal("private image Task binding missing")
	}
	got, err := r.docker.API.ImageInspect(ctx, f.reference)
	if err != nil || got.Config == nil || got.Config.Labels["org.mydc.test.owner"] != f.public["Tag"] {
		t.Fatal("real Task private image pull missing", err)
	}
	f.public["RegistryTaskImagePullVerified"] = true
	f.save()
	// This is a current, authenticated permit after the exact image is cached.
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	rules := slices.Clone(tenant.ImageSources)
	remaining := slices.DeleteFunc(slices.Clone(rules), func(rule access.TrustRule) bool { return rule.Registry == f.address })
	change("registry-remove-image-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: remaining})
	if _, err = r.appRegistryImageAuth(ctx, task, binding.Digest(), f.reference); err == nil {
		t.Fatal("cached image bypassed revoked source trust")
	}
	current, err := r.docker.API.ContainerInspect(ctx, gotContainerID(t, ctx, r, key), client.ContainerInspectOptions{})
	if err != nil || current.Container.State == nil || !current.Container.State.Running {
		t.Fatal("permission denial destroyed existing Task", err)
	}
	users, err = p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ = users.Tenant("tenant")
	change("registry-restore-image-trust", "set-trust", tenant.Revision, control.TrustAssignment{Tenant: "tenant", Rules: rules})
	if os.Getenv("MYDC_TEST_RQ6_REGISTRY_MAINTENANCE") == "1" {
		f.verifyUsedRegistryMaintenance(t, ctx, p, read, change)
	}
	secret := f.credential(t, "pull,push")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull,push")
	headers, _, status := f.request(t, ctx, "POST", "/v2/fixture/blobs/uploads/", token, nil, nil)
	if status != 202 || headers.Get("Docker-Upload-UUID") == "" {
		t.Fatal("original partial upload allocation", status)
	}
	location := headers.Get("Location")
	if !strings.HasPrefix(location, "/v2/fixture/blobs/uploads/") || strings.ContainsAny(location, "?#") {
		t.Fatal("unexpected original upload location")
	}
	f.upload = location
	f.prefix = []byte("same-original-upload-prefix")
	headers, _, status = f.request(t, ctx, "PATCH", location, token, f.prefix, map[string]string{"Content-Range": fmt.Sprintf("0-%d", len(f.prefix)-1)})
	if status != 202 || headers.Get("Range") != fmt.Sprintf("0-%d", len(f.prefix)-1) {
		t.Fatal("original upload durable offset", status)
	}
	f.public["RegistryOriginalUpload"], f.public["RegistryOriginalUploadOffset"] = f.upload, len(f.prefix)
	f.save()
	t.Log("real account CLI protected credential -> Engine HTTPS push -> original Task Engine authenticated digest pull; current trust removal denies cached image permit without destroying running Task; original partial upload saved before same DB restart")
}

func gotContainerID(t *testing.T, ctx context.Context, r *Runtime, key string) string {
	t.Helper()
	status, err := r.workload.Status(ctx, key)
	if err != nil || status.NativeID == "" {
		t.Fatal("original Task native", err)
	}
	return status.NativeID
}

func (f *managedRegistryNative) finish(t *testing.T, ctx context.Context, owner **Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	r := *owner

	// Revocation is an actual terminal close, unlike a daemon/quorum quiesce.
	// First observe the original closure; only an explicit fresh start may open
	// the next run. The same registry ID/data/upload survives that transition.
	registryNativeWait(t, ctx, "original registry closure after node revocation", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", "private")
		return ok && entry.Active == nil && entry.Closed != nil && entry.Closed.Run.Generation == f.original.Generation
	})
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	tenant, _ := users.Tenant("tenant")
	change("registry-restore-owner-node", "set-nodes", tenant.Revision, control.NodeAssignment{Tenant: "tenant", Nodes: []string{"node-a"}})
	book, err := p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := book.Entry("tenant", "private")
	if os.Getenv("MYDC_TEST_RQ4_REGISTRY_ACTION") == "1" {
		var preview control.RegistryActionPlan
		if json.Unmarshal(f.cli(nil, "registry", "start", "private", "--tenant", "tenant", "--preview"), &preview) != nil || preview.Expected != entry.Revision || preview.Current.Spec.Volume != entry.Spec.Volume || !preview.WouldEnable {
			t.Fatal("actual registry start preview changed target")
		}
		args := []string{"registry", "start", "private", "--tenant", "tenant", "--request-id", "rq4-registry-explicit-start", "--expected-revision", strconv.FormatUint(entry.Revision, 10)}
		f.cli(nil, args...)
		f.cli(nil, args...) // same journal/result; no second generation
	} else {
		change("registry-explicit-start-after-revoke", "start-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: "private"})
	}
	registryNativeWait(t, ctx, "explicit next registry run over same original data", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", "private")
		return ok && entry.Active != nil && entry.Active.Generation == f.original.Generation+1 && entry.Active.Ready != nil && entry.Active.Ready.Boot == r.registryBoot
	})
	book, err = p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = book.Entry("tenant", "private")
	run := entry.Active.Reference()
	if run.Spec != f.original.Spec || run.Owner != f.original.Owner || entry.DataOwner != f.original.Owner || run.Consumer.Generation != f.original.Consumer.Generation+1 {
		t.Fatal("explicit restart changed registry storage/owner or lost run floor")
	}
	f.public["RegistryExplicitPostRevocationRun"] = run.Generation
	f.save()
	v, err := p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	creation, ok := v.Creation(f.spec.Volume)
	if !ok || creation.Ready == nil || volumes.NativeBindingDigest(*creation.Ready) != volumes.NativeBindingDigest(f.native) {
		t.Fatal("registry native materialization changed")
	}
	secret := f.credential(t, "pull,push")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull,push")
	headers, _, status := f.request(t, ctx, "GET", f.upload, token, nil, nil)
	if status != 204 || headers.Get("Range") != fmt.Sprintf("0-%d", len(f.prefix)-1) || headers.Get("Location") != f.upload {
		t.Fatal("original upload URL/offset lost", status)
	}
	headers, _, status = f.request(t, ctx, "PATCH", f.upload, token, []byte("bad"), map[string]string{"Content-Range": "0-2"})
	if status != 416 || headers.Get("Location") != f.upload || headers.Get("Range") != fmt.Sprintf("0-%d", len(f.prefix)-1) {
		t.Fatal("failed append lost original upload offset", status)
	}
	tail := []byte("-after-original-db-reopen")
	full := append(slices.Clone(f.prefix), tail...)
	_, _, status = f.request(t, ctx, "PATCH", f.upload, token, tail, map[string]string{"Content-Range": fmt.Sprintf("%d-%d", len(f.prefix), len(full)-1)})
	if status != 202 {
		t.Fatal("original upload resume", status)
	}
	sum := sha256.Sum256(full)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	req, err := http.NewRequestWithContext(ctx, "PUT", "https://"+f.address+f.upload+"?digest="+digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := f.http.Do(req)
	if err != nil {
		t.Fatal("original finalize request", err)
	}
	// Deliberately discard the HTTP success result; do not create a new upload
	// or replay bytes. The original URL, followed by exact digest GET, decides.
	_ = response.Body.Close()
	headers, _, status = f.request(t, ctx, "GET", f.upload, token, nil, nil)
	if status != 204 || headers.Get("Range") != fmt.Sprintf("0-%d", len(full)-1) {
		t.Fatal("original finalize receipt lost", status)
	}
	_, body, status := f.request(t, ctx, "GET", "/v2/fixture/blobs/"+digest, token, nil, nil)
	if status != 200 || !bytes.Equal(body, full) {
		t.Fatal("original completed bytes/digest lost", status)
	}
	// Repeating the exact original finalize is receipt lookup, not a new effect.
	headers, _, status = f.request(t, ctx, "PUT", f.upload+"?digest="+digest, token, nil, nil)
	if status != 201 || headers.Get("Docker-Upload-UUID") != filepath.Base(f.upload) || headers.Get("Docker-Content-Digest") != digest {
		t.Fatal("same original completed upload not idempotent", status)
	}
	book, err = p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = book.Entry("tenant", "private")
	if os.Getenv("MYDC_TEST_RQ4_REGISTRY_ACTION") == "1" {
		var preview control.RegistryActionPlan
		if json.Unmarshal(f.cli(nil, "registry", "stop", "private", "--tenant", "tenant", "--preview"), &preview) != nil || preview.Expected != entry.Revision || preview.Current.Spec.Volume != entry.Spec.Volume || preview.WouldEnable {
			t.Fatal("actual registry stop preview changed data")
		}
		args := []string{"registry", "stop", "private", "--tenant", "tenant", "--request-id", "rq4-registry-stop", "--expected-revision", strconv.FormatUint(entry.Revision, 10)}
		f.cli(nil, args...)
		f.cli(nil, args...)
	} else {
		change("registry-stop", "stop-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: "private"})
	}
	registryNativeWait(t, ctx, "registry actual I/O/writer/shared closure", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", "private")
		return ok && entry.Active == nil && entry.Closed != nil
	})
	f.cli(nil, "registry", "wait", "private", "--tenant", "tenant", "--until", "stopped", "--wait-timeout", "30s")
	book, err = p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = book.Entry("tenant", "private")
	if entry.Closed.Run.Generation != run.Generation || entry.Closed.Run.Consumer != run.Consumer || !entry.Closed.Gone.Stopped || !entry.Closed.Gone.MountsGone {
		t.Fatal("original joined writer closure missing")
	}
	change("registry-delete", "delete-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: "private"})
	f.cli(nil, "registry", "show", "private", "--tenant", "tenant")
	v, err = p.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	volume, ok := v.Volume(f.spec.Volume)
	if !ok || len(volume.Consumers()) != 0 {
		t.Fatal("registry deletion lost retained Volume or leaked consumer")
	}
	actual, err := r.docker.API.VolumeInspect(ctx, f.native.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal("registry retained data Volume deleted", err)
	}
	db := filepath.Join(actual.Volume.Mountpoint, "registry", "registry.db")
	if info, err := os.Stat(db); err != nil || info.Size() == 0 {
		t.Fatal("registry data DB not retained", err)
	}
	f.public["RegistryCompletedUploadDigest"], f.public["RegistryClosedDataRetained"] = digest, true
	f.save()
	t.Log("same original registry run across daemon restart, then explicit next run after actual revocation closure using same native Volume and upload URL/offset -> offset rejection preserves bytes -> discarded finalize response/original receipt -> original Stop/join/native Return/shared closure -> definition deletion retains DB/data")
	f.verifyFixedBacking(t, ctx, owner, p, read, change)
}

func (f *managedRegistryNative) verifyRevokedUser(t *testing.T, ctx context.Context, user userauth.Client, peer mydcp.Peer, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	change("registry-reader-account", "put-user", 0, access.User{ID: "registry-reader", Username: "registry-reader", Enabled: true, Credentials: []access.Credential{{ID: "key", Method: access.PrivateKey, PublicKey: [32]byte(pub), Enabled: true}}})
	change("registry-reader-role", "set-membership", 0, access.Membership{Tenant: "tenant", User: "registry-reader", Role: access.Manager, Enabled: true})

	change("registry-foreign-tenant", "create-tenant", 0, control.TenantID{ID: "registry-other"})
	change("registry-foreign-reader-role", "set-membership", 0, access.Membership{Tenant: "registry-other", User: "registry-reader", Role: access.Manager, Enabled: true})
	session, err := user.Login(ctx, peer, "registry-reader", key)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = user.Query(ctx, peer, session, "select-tenant", "registry-other"); err != nil {
		t.Fatal("foreign tenant reader fixture isn't authenticated", err)
	}
	if reply, e := user.RegistryCredential(ctx, peer, session, "registry-other", userauth.RegistryCredentialRequest{ID: "private", Repository: "fixture", Actions: []string{"pull"}}); e == nil {
		clear(reply.RegistryCredential)
		t.Fatal("foreign tenant acquired private registry credential")
	}
	credential, err := user.RegistryCredential(ctx, peer, session, "tenant", userauth.RegistryCredentialRequest{ID: "private", Repository: "fixture", Actions: []string{"pull"}})
	if err != nil {
		t.Fatal("current registry reader credential", err)
	}
	defer clear(credential.RegistryCredential)
	token := f.tokenFor(t, ctx, "registry-reader", credential.RegistryCredential, "repository:fixture:pull")
	if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/owned", token, nil, nil); status != 200 {
		t.Fatal("authorized reader pull refused", status)
	}
	if _, _, status := f.request(t, ctx, "POST", "/v2/fixture/blobs/uploads/", token, nil, nil); status != 403 {
		t.Fatal("pull-only token opened push", status)
	}
	users, err := p.Catalog(read().State)
	if err != nil {
		t.Fatal(err)
	}
	membership, _ := users.Membership("tenant", "registry-reader")
	change("registry-reader-role-revoke", "set-membership", membership.Revision, access.Membership{Tenant: "tenant", User: "registry-reader", Role: access.Manager, Enabled: false})
	if _, _, status := f.request(t, ctx, "GET", "/v2/fixture/manifests/owned", token, nil, nil); status != 403 {
		t.Fatal("old bearer bypassed current membership revocation", status)
	}
	f.public["RegistryRevokedPullTokenDenied"] = true
	f.save()
}

// A second explicit registry ID reuses the now-vacant authority after its old
// definition is deleted. This is real fixed storage consumption, not another
// application rollout or a fake embedded writer.
func (f *managedRegistryNative) verifyFixedBacking(t *testing.T, ctx context.Context, owner **Runtime, p control.Policy, read func() cluster.View, change func(string, string, uint64, any)) {
	t.Helper()
	r := *owner
	f.public["FixedVolume"] = true
	f.save()
	fixed := prepareFixedAppNativeSource(t, ctx, r, filepath.Dir(f.certFile), p, read, change)
	f.public["FixedNative"] = fixed.ready
	f.save()
	copy := *f
	copy.spec.ID = "fixed-private"
	copy.spec.Volume = fixed.ready.Spec.Scope
	change("fixed-registry-put", "put-registry", 0, control.RegistryPut{Spec: copy.spec})
	var original control.RegistryRunRef
	registryNativeWait(t, ctx, "fixed registry native data writer", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", copy.spec.ID)
		if ok && entry.Active != nil && entry.Active.Ready != nil {
			original = entry.Active.Reference()
			return true
		}
		return false
	})
	secret := copy.credential(t, "pull,push")
	defer clear(secret)
	token := copy.token(t, ctx, secret, "repository:fixture:pull,push")
	data := []byte("original-node-fixed-registry-bytes")
	digest := sha256.Sum256(data)
	sum := "sha256:" + hex.EncodeToString(digest[:])
	_, _, status := copy.request(t, ctx, "POST", "/v2/fixture/blobs/uploads/?digest="+sum, token, data, nil)
	if status != 201 {
		t.Fatal("fixed registry actual blob publication", status)
	}
	_, actual, status := copy.request(t, ctx, "GET", "/v2/fixture/blobs/"+sum, token, nil, nil)
	if status != 200 || !bytes.Equal(actual, data) {
		t.Fatal("fixed registry actual retained bytes", status)
	}
	view := read()
	users, err := p.Catalog(view.State)
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.Volumes(view.State)
	if err != nil {
		t.Fatal(err)
	}
	current, ok := v.Volume(fixed.ready.Spec.Scope)
	if !ok || !current.Fixed() || len(current.Consumers()) != 1 || current.Consumers()[0] != original.Consumer {
		t.Fatal("fixed registry original shared writer missing")
	}
	source, revision := current.Owner()
	target := source
	target.Node = "node-b"
	target.Native = "move-forbidden"
	if _, err = current.Prepare(users, "admin", current.Revision(), revision, "fixed-registry-move", target, [32]byte{1}, 1<<20); !errors.Is(err, volumes.ErrNotMovable) {
		t.Fatal("actual fixed state allowed move or rejected for another reason", err)
	}
	fixed.cli(t, ctx, -1, "volume", "unregister", "data", "--id", "fixed-registry-live-unregister")
	book, err := p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := book.Entry("tenant", copy.spec.ID)
	change("fixed-registry-stop", "stop-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: copy.spec.ID})
	registryNativeWait(t, ctx, "fixed registry original pin/shared closure", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", copy.spec.ID)
		return ok && entry.Active == nil && entry.Closed != nil && entry.Closed.Run.Consumer == original.Consumer
	})
	book, err = p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ = book.Entry("tenant", copy.spec.ID)
	change("fixed-registry-delete", "delete-registry", entry.Revision, control.RegistrySelection{Tenant: "tenant", ID: copy.spec.ID})
	fixed.cli(t, ctx, 0, "volume", "unregister", "data", "--id", "fixed-registry-unregister", "--no-wait")
	registryNativeWait(t, ctx, "fixed registry explicit unregister", func() bool {
		v, e := p.Volumes(read().State)
		if e != nil {
			t.Fatal(e)
		}
		current, ok := v.Volume(fixed.ready.Spec.Scope)
		return ok && current.Deleted()
	})
	for _, id := range []string{"hdd", "ssd"} {
		roots, e := p.NodeStorage(read().State)
		if e != nil {
			t.Fatal(e)
		}
		root, _ := roots.Root("node-a", id)
		fixed.cli(t, ctx, 0, "node", "storage", "drain", "node-a", id, "--if-revision", fmt.Sprint(root.Revision), "--id", "fixed-registry-drain-"+id)
		registryNativeWait(t, ctx, "fixed registry root closure "+id, func() bool {
			roots, e := p.NodeStorage(read().State)
			if e != nil {
				t.Fatal(e)
			}
			root, ok := roots.Root("node-a", id)
			return ok && root.Closed != nil
		})
		roots, e = p.NodeStorage(read().State)
		if e != nil {
			t.Fatal(e)
		}
		root, _ = roots.Root("node-a", id)
		fixed.cli(t, ctx, 0, "node", "storage", "remove", "node-a", id, "--if-revision", fmt.Sprint(root.Revision), "--id", "fixed-registry-remove-"+id)
	}
	after, err := os.Stat(fixed.source)
	if err != nil || !os.SameFile(fixed.before, after) || after.Mode() != fixed.before.Mode() {
		t.Fatal("fixed source inode/mode changed", err)
	}
	originalBytes, err := os.ReadFile(filepath.Join(fixed.source, "original"))
	if err != nil || string(originalBytes) != "preexisting-original" {
		t.Fatal("original fixed source bytes erased", err)
	}
	if db, err := os.Stat(filepath.Join(fixed.source, "registry", "registry.db")); err != nil || db.Size() == 0 {
		t.Fatal("fixed registry DB erased on unregister", err)
	}
	f.public["RegistryFixedDataRetained"], f.public["RegistryFixedMoveDenied"] = true, true
	f.save()
	t.Log("real pre-registered fixed source -> registry original native data FD/TLS blob write and read -> product ErrNotMovable/live unregister denial -> actual I/O/writer closure -> explicit unregister/root close retains original inode and data")
}

// This hook runs after the original daemon DB reopen, before the base scenario
// intentionally revokes node placement and retires its application.
func (f *managedRegistryNative) checkRecovered(t *testing.T, ctx context.Context, r *Runtime, p control.Policy, read func() cluster.View) {
	t.Helper()
	registryNativeWait(t, ctx, "original registry serving after same DB reopen", func() bool {
		book, e := p.Registries(read().State)
		if e != nil {
			t.Fatal(e)
		}
		entry, ok := book.Entry("tenant", "private")
		return ok && entry.Active != nil && entry.Active.Ready != nil && entry.Active.Ready.Boot == r.registryBoot
	})
	book, err := p.Registries(read().State)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := book.Entry("tenant", "private")
	run := entry.Active.Reference()
	if run.Generation != f.original.Generation || run.SpecRevision != f.original.SpecRevision || run.Consumer != f.original.Consumer || run.Spec != f.original.Spec || run.Owner != f.original.Owner || run.Budget.Generation != f.original.Budget.Generation {
		t.Fatal("daemon restart replaced original registry run or pins")
	}
	secret := f.credential(t, "pull,push")
	defer clear(secret)
	token := f.token(t, ctx, secret, "repository:fixture:pull,push")
	headers, _, status := f.request(t, ctx, "GET", f.upload, token, nil, nil)
	if status != 204 || headers.Get("Location") != f.upload || headers.Get("Range") != fmt.Sprintf("0-%d", len(f.prefix)-1) {
		t.Fatal("same DB original upload not recovered", status)
	}
	f.public["RegistrySameRunDBRecoveryVerified"] = true
	f.save()
}
