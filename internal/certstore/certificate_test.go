// SPDX-License-Identifier: Apache-2.0

package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/storage"
)

func materialWith(t *testing.T, key crypto.Signer, cn string, hosts []string, before, after int64) Material {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(after), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Unix(before, 0), NotAfter: time.Unix(after, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return Material{Chain: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})}
}
func certificateMaterial(t *testing.T, hosts []string, before, after int64) Material {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return materialWith(t, key, hosts[0], hosts, before, after)
}

var testSigner = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))

func sealed(t *testing.T, m Material, at int64) (Certificate, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{9}, 32)
	v, err := Seal([32]byte{1}, "admin", "original", at, m, key, testSigner)
	if err != nil {
		t.Fatal(err)
	}
	return v, key
}
func signedCertificate(t *testing.T, before, after, at int64, hosts ...string) (Certificate, []byte, Material) {
	t.Helper()
	m := certificateMaterial(t, hosts, before, after)
	v, key := sealed(t, m, at)
	return v, key, m
}

func TestCertificateSealingPairTimeAndIdentity(t *testing.T) {
	v, key, m := signedCertificate(t, 10, 300, 20, "shop.example")
	defer m.Clear()
	pair, err := Open(v, key)
	if err != nil || pair.Leaf == nil || pair.Leaf.VerifyHostname("shop.example") != nil {
		t.Fatal(err)
	}
	if v.Metadata.Algorithm != "ecdsa-p256" || v.Metadata.ID != ID(sumLeaf(t, m.Chain)) || v.Metadata.Serial != big.NewInt(300).Text(16) {
		t.Fatalf("metadata %+v", v.Metadata)
	}
	raw, _ := json.Marshal(v)
	if bytes.Contains(raw, m.Key) || bytes.Contains(v.SealedKey, m.Key) {
		t.Fatal("private PEM entered public certificate")
	}
	if _, err = json.Marshal(m); err == nil {
		t.Fatal("private material encoded")
	}
	other := certificateMaterial(t, []string{"shop.example"}, 10, 300)
	defer other.Clear()
	if _, err = Seal(v.Cluster, "admin", "bad", 20, Material{m.Chain, other.Key}, key, testSigner); err == nil {
		t.Fatal("mismatched key accepted")
	}
	for _, at := range []int64{9, 300} {
		if _, err = Seal(v.Cluster, "admin", "bad", at, m, key, testSigner); err == nil {
			t.Fatal("invalid period accepted")
		}
	}
	if _, err = Open(v, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("wrong key accepted")
	}
	for _, change := range []func(*Certificate){func(v *Certificate) { v.Metadata.ID[0]++ }, func(v *Certificate) { v.Cluster = [32]byte{2} }, func(v *Certificate) { v.Metadata.Hosts = []string{"other.example"} }} {
		bad := v
		bad.Metadata.Hosts = append([]string(nil), v.Metadata.Hosts...)
		change(&bad)
		bad.Signature = ed25519.Sign(testSigner, CertificateBytes(bad))
		if _, err = Open(bad, key); err == nil {
			t.Fatal("ciphertext rebound to different public identity")
		}
	}
}
func sumLeaf(t *testing.T, chain []byte) [32]byte {
	t.Helper()
	in, err := Inspect(chain, 20)
	if err != nil {
		t.Fatal(err)
	}
	return in.Metadata.ID
}

func TestInspectHostsAndAlgorithms(t *testing.T) {
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p521, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	for _, c := range []struct {
		key      crypto.Signer
		cn       string
		hosts    []string
		at       int64
		invalid  string
		alg      string
		wantHost []string
	}{
		{p384, "x", []string{"B.example", "192.0.2.1", "*.a.example"}, 20, "", "ecdsa-p384", []string{"*.a.example", "192.0.2.1", "b.example"}},
		{p384, "Only.Example", nil, 20, "", "ecdsa-p384", []string{"only.example"}},
		{p384, "", nil, 20, InvalidNoNames, "ecdsa-p384", []string{}},
		{rsaKey, "x", []string{"r.example"}, 20, "", "rsa-2048", []string{"r.example"}},
		{p521, "x", []string{"e.example"}, 20, InvalidKey, "", []string{"e.example"}},
		{edKey, "x", []string{"e.example"}, 20, InvalidKey, "", []string{"e.example"}},
		{p384, "x", []string{"t.example"}, 5, InvalidNotYetValid, "ecdsa-p384", []string{"t.example"}},
		{p384, "x", []string{"t.example"}, 300, InvalidExpired, "ecdsa-p384", []string{"t.example"}},
	} {
		m := materialWith(t, c.key, c.cn, c.hosts, 10, 300)
		in, err := Inspect(m.Chain, c.at)
		if err != nil || in.Invalid != c.invalid || in.Metadata.Algorithm != c.alg {
			t.Fatalf("%v: %+v %v", c.hosts, in, err)
		}
		if got, _ := json.Marshal(in.Metadata.Hosts); string(got) != mustJSON(c.wantHost) {
			t.Fatalf("hosts %s want %v", got, c.wantHost)
		}
	}
	if Family("rsa-4096") != "rsa" || Family("ecdsa-p384") != "ecdsa" || !Discouraged("rsa-2048") {
		t.Fatal("family")
	}
}
func mustJSON(v any) string { raw, _ := json.Marshal(v); return string(raw) }

func TestCatalogLinksStatesDeleteDisableExpire(t *testing.T) {
	c := New([32]byte{1})
	var err error
	c, err = c.AddDomain("shop.example", "admin", 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	old, _, m1 := signedCertificate(t, 10, 400, 20, "shop.example", "*.shop.example")
	newer, _, m2 := signedCertificate(t, 10, 900, 20, "shop.example")
	outside, _, m3 := signedCertificate(t, 10, 900, 20, "other.example")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	m4 := materialWith(t, rsaKey, "x", []string{"shop.example"}, 10, 500)
	rsaCert, _ := sealed(t, m4, 20)
	for _, m := range []Material{m1, m2, m3, m4} {
		defer m.Clear()
	}
	for _, v := range []Certificate{old, newer, outside, rsaCert} {
		if c, err = c.Put(v, 20); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = c.Put(old, 20); !errors.Is(err, ErrConflict) {
		t.Fatal("same ID put twice")
	}
	state := func(id ID) string {
		e, _ := c.Entry(id)
		return c.State(e, 30)
	}
	if state(old.Metadata.ID) != StateLinked || state(newer.Metadata.ID) != StateLinked || state(outside.Metadata.ID) != StateUnlinked || state(rsaCert.Metadata.ID) != StateLinked {
		t.Fatal("states", state(old.Metadata.ID), state(newer.Metadata.ID), state(outside.Metadata.ID))
	}
	if links := c.LinksOf(old.Metadata.ID, 30); len(links) != 1 || links[0].Host != "*.shop.example" {
		t.Fatalf("later NotAfter did not take the exact host: %+v", links)
	}
	got := c.LookupHost("shop.example", 30)
	if len(got) != 2 || got[0].Metadata.ID != newer.Metadata.ID || got[1].Metadata.ID != rsaCert.Metadata.ID {
		t.Fatal("lookup by family")
	}
	if got = c.LookupHost("api.shop.example", 30); len(got) != 1 || got[0].Metadata.ID != old.Metadata.ID {
		t.Fatal("wildcard lookup")
	}
	if len(c.LookupHost("deep.api.shop.example", 30)) != 0 || len(c.LookupHost("other.example", 30)) != 0 {
		t.Fatal("wildcard crossed a label, or unregistered host linked")
	}
	if _, err = c.Delete(newer.Metadata.ID, 30); !errors.Is(err, ErrLinked) {
		t.Fatal("linked certificate deleted")
	}
	c, err = c.Disable(newer.Metadata.ID, "admin", 30)
	if err != nil || state(newer.Metadata.ID) != StatePendingDestroy {
		t.Fatal("disable", err)
	}
	if got = c.LookupHost("shop.example", 30); got[0].Metadata.ID != old.Metadata.ID {
		t.Fatal("disabled link did not move to the next best")
	}
	if c, err = c.Delete(newer.Metadata.ID, 30); err != nil {
		t.Fatal(err)
	}
	if c, err = c.Delete(outside.Metadata.ID, 30); err != nil {
		t.Fatal(err)
	}
	c, removed, err := c.Expire(500)
	if err != nil || len(removed) != 2 || len(c.Certificates) != 0 || c.Validate() != nil {
		t.Fatal("expiry", err, len(removed))
	}
	if e, ok := c.Find("", "", ""); ok {
		t.Fatal("empty find", e)
	}
}

func TestCatalogFind(t *testing.T) {
	c := New([32]byte{1})
	v, _, m := signedCertificate(t, 10, 400, 20, "shop.example")
	defer m.Clear()
	c, _ = c.Put(v, 20)
	id := v.Metadata.ID.String()
	for _, q := range [][3]string{{id, "", ""}, {id[:12], "", ""}, {"", v.Metadata.Issuer, "190"}, {"", "shop.example", "01:90"}} {
		if e, ok := c.Find(q[0], q[1], q[2]); !ok || e.Certificate.Metadata.ID != v.Metadata.ID {
			t.Fatalf("find %v", q)
		}
	}
	if _, ok := c.Find(id[:11], "", ""); ok {
		t.Fatal("short prefix accepted")
	}
	if parsed, ok := ParseID(id); !ok || parsed != v.Metadata.ID {
		t.Fatal("parse id")
	}
}

func TestNativeReceiptUsesDerivedKeyAndSweeps(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "node.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	identity := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	n := Native{DB: db, Cluster: [32]byte{1}, Identity: identity}
	if _, err = n.Master(); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("master invented", err)
	}
	if err = n.GenerateMaster(); err != nil {
		t.Fatal(err)
	}
	master, err := n.Master()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(master)
	if err = n.InstallMaster(bytes.Repeat([]byte{9}, 32)); !errors.Is(err, ErrConflict) {
		t.Fatal("a second master replaced the first", err)
	}
	m := certificateMaterial(t, []string{"shop.example"}, 10, 5000)
	defer m.Clear()
	in, err := Inspect(m.Chain, 20)
	if err != nil {
		t.Fatal(err)
	}
	key, err := Derive(master, in.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	v, err := n.Prepare("admin", "once", 20, m, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(v, key); err != nil {
		t.Fatal("derived key does not open the receipt", err)
	}
	other, _ := Derive(master, ID{1})
	if _, err = Open(v, other); err == nil {
		t.Fatal("another certificate's key opened it")
	}
	recovered, err := n.Recover("admin", "once")
	if err != nil || !bytes.Equal(v.Signature, recovered.Signature) || v.Digest() != recovered.Digest() {
		t.Fatal("original receipt replaced", err)
	}
	// A second voter holding the same master derives the same key.
	peerDB, err := storage.Open(filepath.Join(t.TempDir(), "peer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer peerDB.Close()
	peer := Native{DB: peerDB, Cluster: n.Cluster, Identity: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))}
	if err = peer.InstallMaster(master); err != nil {
		t.Fatal(err)
	}
	peerMaster, err := peer.Master()
	if err != nil || !bytes.Equal(peerMaster, master) {
		t.Fatal("peer master", err)
	}
	foreign := peer
	foreign.Identity = identity
	if _, err = foreign.Master(); err == nil {
		t.Fatal("master envelope opened with a foreign identity")
	}
	if err = peer.EraseMaster(); err != nil {
		t.Fatal(err)
	}
	if _, err = peer.Master(); !errors.Is(err, storage.ErrMissing) {
		t.Fatal("erased master survived", err)
	}
	if err = n.Sweep(New(n.Cluster), 200); err != nil {
		t.Fatal(err)
	}
	if _, err = n.Recover("admin", "once"); err != nil {
		t.Fatal("uncommitted receipt retired inside the commit window", err)
	}
	if err = n.Sweep(New(n.Cluster), 2000); err != nil {
		t.Fatal(err)
	}
	if _, err = n.Recover("admin", "once"); err == nil {
		t.Fatal("receipt past the commit window survived")
	}
}

func TestSealRequestProvesKeyPossession(t *testing.T) {
	m := certificateMaterial(t, []string{"shop.example"}, 10, 5000)
	defer m.Clear()
	pair, err := tls.X509KeyPair(m.Chain, m.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf := pair.Certificate[0]
	q := SealRequest{Schema: 1, Cluster: [32]byte{1}, Member: [32]byte{2}, ID: sha256.Sum256(leaf), Leaf: leaf, At: 20}
	signed, err := SignSealRequest(q, pair.PrivateKey.(crypto.Signer))
	if err != nil {
		t.Fatal(err)
	}
	if err = signed.Verify([32]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err = signed.Verify([32]byte{3}); err == nil {
		t.Fatal("other cluster accepted")
	}
	moved := signed
	moved.Member = [32]byte{4}
	if err = moved.Verify([32]byte{1}); err == nil {
		t.Fatal("proof moved to another member")
	}
	other := certificateMaterial(t, []string{"other.example"}, 10, 5000)
	defer other.Clear()
	otherPair, _ := tls.X509KeyPair(other.Chain, other.Key)
	forged, _ := SignSealRequest(q, otherPair.PrivateKey.(crypto.Signer))
	if err = forged.Verify([32]byte{1}); err == nil {
		t.Fatal("proof by another key accepted")
	}
}
