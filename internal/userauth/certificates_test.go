// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
	"github.com/jay94ks/mydcd/internal/cluster/control"
)

func userCertificateMaterial(t *testing.T) certstore.Material {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"shop.example"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return certstore.Material{Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})}
}
func TestCertificateSensitiveInputCannotMixSecretApprovalOrOrdinarySelectors(t *testing.T) {
	q := SecretRequest{Schema: 1, Nonce: [32]byte{1}, Mode: "certificate", ID: "once", Certificate: &CertificateInput{Request: "once", Chain: []byte("chain"), Key: []byte("private")}}
	if !validSecretRequest(q) {
		t.Fatal("bounded certificate input rejected")
	}
	for _, edit := range []func(*SecretRequest){func(q *SecretRequest) { q.Realm = "tenant" }, func(q *SecretRequest) { q.Mode = "execute" }, func(q *SecretRequest) { q.ID = "other" }, func(q *SecretRequest) { q.Values = map[string][]byte{"key": []byte("private")} }, func(q *SecretRequest) { q.Password = []byte("password") }, func(q *SecretRequest) { q.Origin = &control.UserOperation{} }} {
		bad := q
		edit(&bad)
		if validSecretRequest(bad) {
			t.Fatal("mixed sensitive purpose accepted")
		}
	}
	recover := CertificateInput{Request: "once", Recover: true}
	if !validCertificateInput(recover) {
		t.Fatal("public result recovery rejected")
	}
	recover.Key = []byte("private")
	if validCertificateInput(recover) {
		t.Fatal("recovery accepted private material")
	}
}

func TestCertificateInputJournalKeepsOneDispatchAndOriginalOwner(t *testing.T) {
	home, c, session, node := journalFixture(t)
	intent, err := StageCertificateIntent(home, c, session, CertificateIntent{ID: "once", Owner: node.Public})
	if err != nil || intent.Dispatched {
		t.Fatal(err)
	}
	if err = UpdateCertificateIntent(home, c, session, "once", nil); err != nil {
		t.Fatal(err)
	}
	if err = UpdateCertificateIntent(home, c, session, "once", nil); err == nil {
		t.Fatal("second private dispatch admitted")
	}
	loaded, err := LoadCertificateIntent(home, c, session, "once")
	if err != nil || !loaded.Dispatched || loaded.Owner != node.Public {
		t.Fatal("original unknown input reset", err)
	}
	m := userCertificateMaterial(t)
	defer m.Clear()
	v, err := certstore.Seal(c.Cluster, session.User, "once", time.Now().Unix(), m, bytes.Repeat([]byte{8}, 32), node.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err = UpdateCertificateIntent(home, c, session, "once", &v); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadCertificateIntent(home, c, session, "once")
	if err != nil || loaded.Fact == nil || loaded.Fact.Digest() != v.Digest() {
		t.Fatal(err)
	}
	root, err := operationRoot(home, c, session.User, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	raw, err := root.ReadFile(certificateIntentName("once"))
	if err != nil || bytes.Contains(raw, m.Key) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(m.Key))) {
		t.Fatal("journal retained private input", err)
	}
	if _, err = StageCertificateIntent(home, c, session, CertificateIntent{ID: "once", Owner: [32]byte{9}}); !errors.Is(err, ErrPrivateState) {
		t.Fatal("original input target replaced", err)
	}
}
