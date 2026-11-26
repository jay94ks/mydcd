// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func trustTestCertificate(t *testing.T) []byte {
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

func TestExplicitPublicTrustNeverExportsCredentialsAndCopiesCertificateBytes(t *testing.T) {
	der := trustTestCertificate(t)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	client, err := New("registry.example", []byte("private-user"), []byte("private-password"), ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	trust := client.PublicTrust()
	if !trust.Valid() || len(trust.Certificates) != 1 || trust.Authority != "registry.example" || trust.Fingerprint != ([32]byte{}) {
		t.Fatal("explicit certificate not projected")
	}
	raw, err := json.Marshal(trust)
	if err != nil || strings.Contains(string(raw), "private-user") || strings.Contains(string(raw), "private-password") {
		t.Fatal("public trust exported credentials")
	}
	encoded, err := trust.PEM()
	if err != nil || string(encoded) != string(ca) {
		t.Fatal("public certificate round-trip changed", err)
	}
	trust.Certificates[0][0] ^= 1
	if !client.PublicTrust().Valid() {
		t.Fatal("caller modified original TLS client roots")
	}
}

func TestPublicTrustRejectsKeysGarbageExtraAuthorityAndWrongManagedFingerprint(t *testing.T) {
	der := trustTestCertificate(t)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for _, raw := range [][]byte{[]byte("private-prefix" + string(ca)), append(append([]byte(nil), ca...), []byte("private-tail")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})} {
		if client, err := New("registry.example", nil, nil, raw); err == nil {
			client.Close()
			t.Fatal("non-certificate CA input accepted")
		}
	}
	trust := RegistryTrust{Authority: "registry.example", Certificates: [][]byte{der}, Fingerprint: sha256.Sum256(der)}
	if !trust.Valid() {
		t.Fatal("managed serving leaf rejected")
	}
	trust.Fingerprint[0] ^= 1
	if trust.Valid() {
		t.Fatal("unrelated serving certificate accepted")
	}
	trust.Fingerprint = [32]byte{}
	trust.Authority = "https://registry.example/other"
	if trust.Valid() {
		t.Fatal("arbitrary CA URL accepted as authority")
	}
}
