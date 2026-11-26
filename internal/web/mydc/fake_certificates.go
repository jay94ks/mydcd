// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/jay94ks/mydcd/internal/certstore"
)

// FixtureCertificate seeds store certificates; each ValidDays item is one
// certificate for SANs (oldest first), valid from 30 days before the fake's
// start until that many days after it.
type FixtureCertificate struct {
	SANs       []string
	ValidDays  []int
	UploadedBy string
}

// FixtureIngressCert seeds a host one server's ingress serves.
type FixtureIngressCert struct {
	Node, Listener, Host string
}

// ingressCertObs is what one server's ingress serves for a listener and
// host (fake-only state behind Runtime.Certificates).
type ingressCertObs struct {
	Node, Listener, Host string
	Fingerprint          [32]byte // the store certificate ID
	NotAfter             int64
	LoadedAt             int64
	LastError            string
	Missing              bool
}

// NewTestCertificate makes a self-signed ECDSA P-256 chain and key in PEM,
// for fixtures and daemon tests (stands in for an ACME result).
func NewTestCertificate(sans []string, notBefore, notAfter time.Time) (chainPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: sans[0]}, Issuer: pkix.Name{CommonName: "MyDC Fake CA"},
		DNSNames: sans, NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// seedCertCache keeps generated fixture certificates for the process: the
// real receipt is sealed with the wallet KDF, too slow to redo per world.
var seedCertCache = struct {
	sync.Mutex
	base time.Time
	m    map[string]seededCert
}{m: map[string]seededCert{}}

type seededCert struct {
	real certstore.Certificate
}

func (w *world) seedCertificates(f Fixture) {
	w.creal = certRealState{cat: certstore.New(w.cluster), receipts: map[string]certReceipt{}}
	seedCertCache.Lock()
	defer seedCertCache.Unlock()
	if seedCertCache.base.IsZero() {
		seedCertCache.base = time.Unix(fixtureNow, 0)
		if now := time.Now(); now.After(seedCertCache.base) {
			seedCertCache.base = now
		}
	}
	base := seedCertCache.base
	for _, d := range f.Domains {
		cat, err := w.creal.cat.AddDomain(d, "admin", w.creal.cat.Revision, base.Add(-90*24*time.Hour).Unix())
		if err != nil {
			panic(err)
		}
		w.creal.cat = cat
	}
	for _, fc := range f.Certificates {
		uploader := fc.UploadedBy
		if u := w.byName(fc.UploadedBy); u != nil {
			uploader = u.rec.ID
		}
		for i, days := range fc.ValidDays {
			k := fmt.Sprintf("%x/%q/%v/%d/%s", w.cluster, fc.SANs, fc.ValidDays, i, uploader)
			sc, ok := seedCertCache.m[k]
			if !ok {
				chain, key, err := NewTestCertificate(fc.SANs, base.Add(-30*24*time.Hour), base.Add(time.Duration(days)*24*time.Hour))
				if err != nil {
					panic(err)
				}
				at := base.Add(time.Duration(i-len(fc.ValidDays)) * 24 * time.Hour).Unix()
				real, err := w.sealCertificate(uploader, fmt.Sprintf("seed-%s-%d", fc.SANs[0], i+1), at, chain, key)
				if err != nil {
					panic(err)
				}
				sc = seededCert{real: real}
				seedCertCache.m[k] = sc
			}
			w.root++
			cat, err := w.creal.cat.Put(sc.real, sc.real.Metadata.UploadedAt)
			if err != nil {
				panic(err)
			}
			w.creal.cat = cat
		}
	}
	for _, ic := range f.IngressCerts {
		w.ingressCerts = append(w.ingressCerts, ingressCertObs{Node: ic.Node, Listener: ic.Listener, Host: ic.Host, LoadedAt: base.Add(-time.Hour).Unix()})
	}
	w.loadRealCertificates(base.Unix())
}

// loadRealCertificates simulates dynamic loading: every ingress host serves
// the certificate the store links for it (ECDSA first).
func (w *world) loadRealCertificates(now int64) {
	for i := range w.ingressCerts {
		o := &w.ingressCerts[i]
		got := w.creal.cat.LookupHost(o.Host, now)
		if len(got) == 0 {
			o.Fingerprint, o.NotAfter, o.Missing = [32]byte{}, 0, true
			continue
		}
		m := got[0].Metadata
		if o.Fingerprint != m.ID {
			o.LoadedAt = now
		}
		o.Fingerprint, o.NotAfter, o.LastError, o.Missing = m.ID, m.NotAfter, "", false
	}
}
