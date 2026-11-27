// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/certstore"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

func controlCertificate(t *testing.T, f *nodeStorageFixture, serial int64, request string) certstore.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"shop.example"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(100+serial, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	material := certstore.Material{Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})}
	defer material.Clear()
	v, err := certstore.Seal(f.p.Cluster, "admin", request, 2, material, bytes.Repeat([]byte{5}, 32), f.node)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func TestCertificateManagementIsSystemAdminOnlyAndLinksFollowDomains(t *testing.T) {
	f := newNodeStorageFixture(t)
	v := controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("manager", "put-certificate", 0, CertificatePut{v}, state.Forbidden)
	v = controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 1, CertificatePut{v}, state.Invalid)
	v = controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 0, CertificatePut{v}, state.Applied)
	page, err := f.p.CertificatePage(f.s, f.sessions["admin"], 3, CertificateQuery{})
	if err != nil || len(page.Certificates) != 1 || page.Certificates[0].Metadata.ID != v.Metadata.ID || page.Certificates[0].State != certstore.StateUnlinked {
		t.Fatal("public certificate missing", err)
	}
	public, _ := json.Marshal(page)
	if bytes.Contains(public, []byte("SealedKey")) || bytes.Contains(public, []byte("Signature")) || bytes.Contains(public, []byte("Chain")) {
		t.Fatal("read page exposed replication-only material")
	}
	one, err := f.p.CertificatePage(f.s, f.sessions["admin"], 3, CertificateQuery{ID: v.Metadata.ID.String()})
	if err != nil || len(one.Certificates) != 1 || !bytes.Equal(one.Chain, v.Chain) {
		t.Fatal("single read lost the public chain", err)
	}
	if _, err = f.p.CertificatePage(f.s, f.sessions["manager"], 3, CertificateQuery{}); err == nil {
		t.Fatal("tenant manager read cluster certificates")
	}
	again := v
	again.Request = fmt.Sprintf("user-%d", f.next+1)
	again.Signature = ed25519.Sign(f.node, certstore.CertificateBytes(again))
	f.apply("admin", "put-certificate", 0, CertificatePut{again}, state.ConditionFailed)
	f.apply("admin", "add-domain", 1, DomainChange{"shop.example"}, state.Applied)
	newer := controlCertificate(t, f, 2, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 0, CertificatePut{newer}, state.Applied)
	c, _ := f.p.Certificates(f.s)
	if got := c.LookupHost("shop.example", 3); len(got) != 1 || got[0].Metadata.ID != newer.Metadata.ID {
		t.Fatal("later NotAfter did not take the link")
	}
	f.apply("admin", "delete-certificate", 0, CertificateSelection{newer.Metadata.ID}, state.ConditionFailed)
	f.apply("admin", "disable-certificate", 0, CertificateSelection{newer.Metadata.ID}, state.Applied)
	f.apply("admin", "delete-certificate", 0, CertificateSelection{newer.Metadata.ID}, state.Applied)
	f.apply("admin", "delete-certificate", 0, CertificateSelection{v.Metadata.ID}, state.ConditionFailed)
	// A key's ceiling is fixed when it is added: sign in with a put-only key.
	u, _ := f.users.User("admin")
	putOnly := [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{202}, ed25519.SeedSize)).Public().(ed25519.PublicKey))
	users, err := f.users.AddCredential("admin", f.p.Cluster, u.Revision, access.CredentialAddition{User: "admin", Credential: access.CredentialKey{ID: "put-only", Method: access.PrivateKey, PublicKey: putOnly}, Operations: []string{"put-certificate"}})
	if err != nil {
		t.Fatal(err)
	}
	f.users = users
	writes, code := f.p.checkpoint(f.s, users)
	if code != state.Applied {
		t.Fatal(code)
	}
	f.checkpoint(CatalogKey, writes)
	u, _ = users.User("admin")
	session := f.sessions["admin"]
	session.AccountRevision, session.Credential, session.Key = u.Revision, "put-only", putOnly
	session.Signature = ed25519.Sign(f.node, access.SessionBytes(session))
	f.sessions["admin"] = session
	if f.p.CertificateAllowed(f.s, session, 3, "put-certificate") != nil || f.p.CertificateAllowed(f.s, session, 3, "disable-certificate") == nil {
		t.Fatal("put-only system credential ceiling widened")
	}
	if _, err = f.p.CertificatePage(f.s, session, 3, CertificateQuery{}); err == nil {
		t.Fatal("put-only credential acquired read privilege")
	}
	encoded, err := state.Encode(f.s)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := state.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	store, err := f.p.Certificates(restored)
	if err != nil || len(store.Certificates) != 1 || store.Certificates[0].Certificate.Metadata.ID != v.Metadata.ID {
		t.Fatal("snapshot lost certificates", err)
	}
}
func TestCertificateExpiryRequiresCurrentControlAndPurgesPayloadFromCurrentSnapshot(t *testing.T) {
	f := newNodeStorageFixture(t)
	v := controlCertificate(t, f, 1, fmt.Sprintf("user-%d", f.next+1))
	f.apply("admin", "put-certificate", 0, CertificatePut{v}, state.Applied)
	report := CertificateExpiryReport{Schema: 1, Cluster: f.p.Cluster, Reporter: f.p.TrustRoot, RootRevision: f.s.Object(CertificatesKey).Revision, Epoch: f.s.ModuleEpoch(), At: 101}
	report.Signature = ed25519.Sign(f.node, CertificateExpiryBytes(report))
	cmd, err := report.Command()
	if err != nil {
		t.Fatal(err)
	}
	if !f.p.AdmitModule(f.s, cmd) {
		t.Fatal("current control expiry report denied")
	}
	next, result, err := state.ApplyTransactional(f.s, f.s.Index()+1, cmd, f.p.ValidateManaged, f.p.Reduce, f.p.AdmitModule, f.p.AdmitAppMutation, f.p.AdmitAppPatch)
	if err != nil || result.Code != state.Applied {
		t.Fatal("expiry did not commit", result.Code, err)
	}
	store, err := f.p.Certificates(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Entry(v.Metadata.ID); ok {
		t.Fatal("expired certificate kept")
	}
	encoded, _ := json.Marshal(store)
	if bytes.Contains(encoded, v.Chain) || bytes.Contains(encoded, v.SealedKey) {
		t.Fatal("expired certificate payload retained")
	}
	report.Reporter = [32]byte(f.manager.Public().(ed25519.PublicKey))
	report.RootRevision = next.Object(CertificatesKey).Revision
	report.Signature = ed25519.Sign(f.manager, CertificateExpiryBytes(report))
	cmd, _ = report.Command()
	if f.p.AdmitModule(next, cmd) {
		t.Fatal("user key became system expiry reporter")
	}
}
func TestDomainListIsSystemAdminOnlyAndOnTheFirstCertificatePage(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("manager", "add-domain", 0, DomainChange{"shop.example"}, state.Forbidden)
	f.apply("admin", "add-domain", 0, DomainChange{"Shop.example"}, state.Invalid)
	f.apply("admin", "add-domain", 0, DomainChange{"co.kr"}, state.Invalid)
	f.apply("admin", "add-domain", 0, DomainChange{"shop.example"}, state.Applied)
	f.apply("admin", "add-domain", 1, DomainChange{"shop.example"}, state.ConditionFailed)
	page, err := f.p.CertificatePage(f.s, f.sessions["admin"], 3, CertificateQuery{})
	if err != nil || page.Revision != 1 || len(page.Domains) != 1 || page.Domains[0].Name != "shop.example" || page.Domains[0].AddedBy != "admin" {
		t.Fatal("domain list missing", page, err)
	}
	f.apply("admin", "remove-domain", 0, DomainChange{"shop.example"}, state.ConditionFailed)
	f.apply("admin", "remove-domain", 1, DomainChange{"shop.example"}, state.Applied)
	if c, err := f.p.Certificates(f.s); err != nil || len(c.Domains) != 0 {
		t.Fatal("domain not removed", err)
	}
}

func TestACMEResponderIsSystemAdminOnlyAndOnTheFirstPage(t *testing.T) {
	f := newNodeStorageFixture(t)
	f.apply("manager", "set-acme-responder", 0, ACMEResponderChange{"10.0.0.5:8402"}, state.Forbidden)
	f.apply("admin", "set-acme-responder", 0, ACMEResponderChange{"web:8402"}, state.Invalid)
	f.apply("admin", "set-acme-responder", 0, ACMEResponderChange{"0.0.0.0:8402"}, state.Invalid)
	f.apply("admin", "set-acme-responder", 0, ACMEResponderChange{""}, state.ConditionFailed)
	f.apply("admin", "set-acme-responder", 0, ACMEResponderChange{"10.0.0.5:8402"}, state.Applied)
	f.apply("admin", "set-acme-responder", 1, ACMEResponderChange{"10.0.0.5:8402"}, state.ConditionFailed)
	page, err := f.p.CertificatePage(f.s, f.sessions["admin"], 3, CertificateQuery{})
	if err != nil || page.ACMEResponder == nil || page.ACMEResponder.Address != "10.0.0.5:8402" || page.ACMEResponder.SetBy != "admin" {
		t.Fatal("responder missing", page, err)
	}
	f.apply("admin", "set-acme-responder", 1, ACMEResponderChange{""}, state.Applied)
	if c, err := f.p.Certificates(f.s); err != nil || c.ACMEResponder != nil || c.Revision != 2 {
		t.Fatal("responder not cleared", err)
	}
}
