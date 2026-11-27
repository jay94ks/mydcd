// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/registryclient"
)

func buildControlTrustCertificate(t *testing.T, f *nodeStorageFixture) []byte {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, f.node.Public(), f.node)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Actual FSM, current grants and signed owner reports. Certificate serving is
// injected; real owner chain/HTTPS/BuildKit paths belong to RQ6's final batch.
func TestBuildRegistryTrustIsBoundToServingLeafOriginalPermitAndCurrentJob(t *testing.T) {
	f, plan := buildJobFixture(t)
	der := buildControlTrustCertificate(t, f)
	fingerprint := sha256.Sum256(der)
	registryReportFixture(t, f, RegistryReport{Tenant: "tenant", ID: "private", Action: "serving", SpecRevision: 1, Generation: 1, Observation: &RegistryObservation{Boot: [32]byte{1}, Certificate: fingerprint}}, state.Applied)
	f.apply("manager", "begin-image-build", 0, plan.Change, state.Applied)
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin"}, state.Applied)
	q := ImageBuildRegistryRequest{Tenant: "tenant", Job: plan.Spec.ID, Snapshot: plan.Spec.Digest(), Action: "push", At: 3}
	permit, err := f.p.ImageBuildRegistryPermit(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil {
		t.Fatal(err)
	}
	trust := registryclient.RegistryTrust{Authority: permit.Run.Spec.Authority, Certificates: [][]byte{der}, Fingerprint: fingerprint}
	if err := f.p.ValidateImageBuildRegistryTrust(f.s, permit, trust, 3); err != nil {
		t.Fatal("original serving leaf rejected", err)
	}
	for _, edit := range []func(*registryclient.RegistryTrust){
		func(t *registryclient.RegistryTrust) { t.Authority = "foreign.example" },
		func(t *registryclient.RegistryTrust) { t.Fingerprint[0] ^= 1 },
		func(t *registryclient.RegistryTrust) { t.Certificates = nil },
	} {
		bad := trust
		edit(&bad)
		if err := f.p.ValidateImageBuildRegistryTrust(f.s, permit, bad, 3); err == nil {
			t.Fatal("unrelated serving trust accepted")
		}
	}
	bad := permit
	bad.Subject.Node[0] ^= 1
	if _, err := f.p.CurrentImageBuildRegistryTrust(f.s, bad, 3); err == nil {
		t.Fatal("another builder borrowed TLS permit")
	}
	bad = permit
	bad.Run.Generation++
	if _, err := f.p.CurrentImageBuildRegistryTrust(f.s, bad, 3); err == nil {
		t.Fatal("another registry generation borrowed TLS permit")
	}
	f.apply("manager", "cancel-image-build", 2, ImageBuildJobSelection{Tenant: "tenant", ID: plan.Spec.ID}, state.Applied)
	if err := f.p.ValidateImageBuildRegistryTrust(f.s, permit, trust, 3); err == nil {
		t.Fatal("cancelled job obtained fresh trust")
	}
}

func TestBuildBaseTrustDoesNotInventCAOrFallbackBeforeReservation(t *testing.T) {
	f, plan, inputs, sources := buildBoundSourceFixture(t)
	q := buildBaseQuery(plan, inputs[0].Source.Reference)
	read, err := f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil {
		t.Fatal(err)
	}
	trust := registryclient.RegistryTrust{Authority: "ghcr.io"}
	if err := f.p.ValidateImageBuildBaseTrust(f.s, read, trust, 3); err == nil {
		t.Fatal("queued job exported source material before reservation")
	}
	buildJobReportFixture(t, f, ImageBuildJobReport{Job: plan.Spec.ID, Action: "begin", Inputs: inputs, Sources: sources}, state.Applied)
	read, err = f.p.ImageBuildBaseRead(f.s, plan.Spec.Scope.Root.Key, q)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.ValidateImageBuildBaseTrust(f.s, read, trust, 3); err != nil {
		t.Fatal("default trust source rejected", err)
	}
	bad := trust
	bad.Certificates = [][]byte{buildControlTrustCertificate(t, f)}
	if err := f.p.ValidateImageBuildBaseTrust(f.s, read, bad, 3); err == nil {
		t.Fatal("unselected CA was added to a default-trust source")
	}
	f.apply("manager", "unbind-external-registry", 2, RegistrySelection{Tenant: "tenant", ID: sources[0].External.ID}, state.Applied)
	if err := f.p.ValidateImageBuildBaseTrust(f.s, read, trust, 3); err == nil {
		t.Fatal("drained source exported new trust")
	}
}
