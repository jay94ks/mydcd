// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/registryclient"
	"github.com/pelletier/go-toml/v2"
)

func buildTrustCertificate(t *testing.T) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestBuildTrustConfigIsExactHostReadOnlyAndHasNoInsecureOrKeypairSettings(t *testing.T) {
	spec, _ := testJobSpec(t)
	inputs := []FrozenSource{{Source: Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64", Kind: "from"}, Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}}
	roots := []registryclient.RegistryTrust{{Authority: "docker.io", Certificates: [][]byte{buildTrustCertificate(t)}}}
	files, digest, err := buildTrustControls(inputs, roots)
	if err != nil || digest == ([32]byte{}) || len(files) != 2 {
		t.Fatal("missing trust files", err)
	}
	var decoded map[string]any
	if err := toml.Unmarshal(files[1].data, &decoded); err != nil {
		t.Fatal(err)
	}
	registry := decoded["registry"].(map[string]any)
	host := registry["docker.io"].(map[string]any)
	if len(registry) != 1 || len(host) != 1 || host["ca"] == nil || strings.Contains(string(files[1].data), "insecure") || strings.Contains(string(files[1].data), "keypair") || strings.Contains(string(files[1].data), "http =") {
		t.Fatal("TLS config broadened trust", decoded)
	}
	var archive bytes.Buffer
	if err := writeControlFilesTAR(context.Background(), &archive, spec, inputs, nil, files); err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(&archive)
	seen := map[string]bool{}
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[h.Name] = true
		if strings.HasPrefix(h.Name, "tls/") || h.Name == "buildkitd.toml" {
			if h.Uid != 0 || h.Mode&0222 != 0 {
				t.Fatal("builder can rewrite TLS controls", h.Name)
			}
		}
	}
	if !seen["buildkitd.toml"] || !seen["tls/registry-0.pem"] {
		t.Fatal("CA/config missing from original control copy")
	}
}

func TestBuildTrustRejectsForeignMissingAndConflictingHostRoots(t *testing.T) {
	inputs := []FrozenSource{{Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}}
	ca := registryclient.RegistryTrust{Authority: "docker.io", Certificates: [][]byte{buildTrustCertificate(t)}}
	if _, _, err := buildTrustControls(inputs, nil); err == nil {
		t.Fatal("missing source trust became default trust")
	}
	foreign := ca
	foreign.Authority = "foreign.example"
	if _, _, err := buildTrustControls(inputs, []registryclient.RegistryTrust{foreign}); err == nil {
		t.Fatal("foreign authority roots accepted")
	}
	if _, _, err := buildTrustControls(inputs, []registryclient.RegistryTrust{ca, {Authority: "docker.io"}}); !errors.Is(err, ErrConflict) {
		t.Fatal("repository-specific trust was silently unioned", err)
	}
	if _, _, err := buildTrustControls(inputs, []registryclient.RegistryTrust{ca, ca}); err != nil {
		t.Fatal("identical host roots did not deduplicate", err)
	}
}

func TestBuildDefaultTrustNormalizesNilAndEmptyCertificateSets(t *testing.T) {
	inputs := []FrozenSource{{Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}}
	_, a, err := buildTrustControls(inputs, []registryclient.RegistryTrust{{Authority: "docker.io"}})
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := buildTrustControls(inputs, []registryclient.RegistryTrust{{Authority: "docker.io", Certificates: [][]byte{}}})
	if err != nil || a != b {
		t.Fatal("equivalent default trust changed frozen digest", err)
	}
}

func TestNativeSDKLegacyModeOmitsNewTLSFieldsAndNewControlsFreezeTrust(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	f.prepare(ctx)
	record, err := f.jobs.Record(f.spec)
	if err != nil || record.Solve.Trust == nil || !record.Solve.TLS {
		t.Fatal("TLS controls were not committed before Start", err)
	}
	if err := f.jobs.StageControlsTLS(ctx, f.spec, nil, nil); err != nil {
		t.Fatal("same original controls not idempotent", err)
	}
	legacy := *record.Solve
	legacy.TLS, legacy.Trust, legacy.SourceContent = false, nil, false
	raw, err := json.Marshal(legacy)
	if err != nil || bytes.Contains(raw, []byte(`"TLS"`)) || bytes.Contains(raw, []byte(`"Trust"`)) {
		t.Fatal("old canonical SDK record changed", err)
	}
}

func TestNativeTLSControlCopyCannotSwitchTrustAfterOriginalDispatch(t *testing.T) {
	f := newNativeFixture(t, false)
	ctx := f.ctx()
	if err := f.jobs.UseSDK(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	// Reopen an original SDK journal: the new owner-content mode deliberately
	// leaves these already selected daemon trust controls unchanged.
	f.jobs.mu.Lock()
	old, cause := f.jobs.load(f.spec)
	if cause == nil {
		old.Solve.SourceContent = false
		cause = f.jobs.save(old)
	}
	f.jobs.mu.Unlock()
	if cause != nil {
		t.Fatal(cause)
	}
	options, err := f.plan.createOptionsWithTLS(f.spec, true, true)
	if err != nil {
		t.Fatal(err)
	}
	f.edit(func() { f.options = options })
	input := FrozenSource{Source: Source{Reference: "docker.io/library/alpine:latest", Platform: "linux/amd64", Kind: "from"}, Image: "docker.io/library/alpine@sha256:" + strings.Repeat("a", 64)}
	f.grant.Run.Inputs = []FrozenSource{input}
	if err := f.jobs.Create(ctx, f.spec); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := tarContextFixture(t)
	if err := f.jobs.StageContext(ctx, f.spec, bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	root := registryclient.RegistryTrust{Authority: "docker.io", Certificates: [][]byte{buildTrustCertificate(t)}}
	if err := f.jobs.StageControlsTLS(ctx, f.spec, nil, []registryclient.RegistryTrust{root}); err != nil {
		t.Fatal(err)
	}
	before, err := f.jobs.Record(f.spec)
	if err != nil {
		t.Fatal(err)
	}
	copies := len(f.copied())
	root.Certificates = [][]byte{buildTrustCertificate(t)}
	if err := f.jobs.StageControlsTLS(ctx, f.spec, nil, []registryclient.RegistryTrust{root}); !errors.Is(err, ErrConflict) {
		t.Fatal("original trust was replaced", err)
	}
	after, err := f.jobs.Record(f.spec)
	if err != nil || !after.ControlsDone || after.Solve.Trust == nil || *after.Solve.Trust != *before.Solve.Trust || len(f.copied()) != copies {
		t.Fatal("changed trust replayed control archive", err)
	}
}
