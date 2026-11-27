// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"
)

// FakeCA is an in-process ACME authority for development and tests. It
// issues certificates from its own throwaway root that nothing trusts.
// Validate checks the DNS-01 TXT values through Lookup, the same view of
// the zone the web app has through its DNS provider.
type FakeCA struct {
	// Lookup returns the TXT values at an FQDN.
	Lookup func(ctx context.Context, fqdn string) ([]string, error)
	// HTTPGet fetches http://host/.well-known/acme-challenge/token and
	// returns the body (HTTP-01).
	HTTPGet func(ctx context.Context, host, token string) (string, error)
	// Lifetime of issued certificates (default 90 days).
	Lifetime time.Duration

	mu       sync.Mutex
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	accounts map[string]string // thumbprint → URL
	orders   map[string]*fakeOrder
	revoked  map[string]bool
	reasons  []RevokeReason
	seq      int
	failNext error
	issued   int
}

type fakeOrder struct {
	o       Order
	account string
	tokens  map[string]string // name → token
	valid   bool
}

// NewFakeCA returns a fake CA.
func NewFakeCA() *FakeCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Seafield Cluster Fake ACME Root"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	root, _ := x509.ParseCertificate(der)
	return &FakeCA{root: root, rootKey: k, accounts: map[string]string{}, orders: map[string]*fakeOrder{}, revoked: map[string]bool{}}
}

// FailNext makes the next call fail with err.
func (f *FakeCA) FailNext(err error) { f.mu.Lock(); f.failNext = err; f.mu.Unlock() }

// Issued counts issued certificates.
func (f *FakeCA) Issued() int { f.mu.Lock(); defer f.mu.Unlock(); return f.issued }

// RevokeReasons lists the reasons of every revocation, in order.
func (f *FakeCA) RevokeReasons() []RevokeReason {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]RevokeReason(nil), f.reasons...)
}

// Revoked reports whether a leaf (DER) was revoked.
func (f *FakeCA) Revoked(der []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[string(der)]
}

func (f *FakeCA) enter() error {
	f.mu.Lock()
	err := f.failNext
	f.failNext = nil
	return err
}

// Info implements CA.
func (f *FakeCA) Info() CAInfo {
	return CAInfo{ID: "fake", Name: "Fake ACME (development)", Directory: "fake://acme", Staging: true, CAA: "sfc-fake-ca.invalid",
		KeyTypes: []KeyType{EC256, EC384, RSA2048, RSA3072}, Ready: true, Note: "in-process fake; certificates are not trusted"}
}

// Register implements CA.
func (f *FakeCA) Register(ctx context.Context, key crypto.Signer, email string, eab *EAB) (string, error) {
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return "", err
	}
	th, err := thumbprint(key.Public())
	if err != nil {
		return "", err
	}
	if u, ok := f.accounts[th]; ok {
		return u, nil
	}
	f.seq++
	u := fmt.Sprintf("fake://acme/acct/%d", f.seq)
	f.accounts[th] = u
	return u, nil
}

func (f *FakeCA) checkAccount(key crypto.Signer, account string) error {
	th, err := thumbprint(key.Public())
	if err != nil {
		return err
	}
	if f.accounts[th] != account {
		return fmt.Errorf("%w: unknown account", ErrRejected)
	}
	return nil
}

// NewOrder implements CA.
func (f *FakeCA) NewOrder(ctx context.Context, key crypto.Signer, account string, names []string, method Method) (Order, error) {
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return Order{}, err
	}
	if err := f.checkAccount(key, account); err != nil {
		return Order{}, err
	}
	f.seq++
	o := Order{URL: fmt.Sprintf("fake://acme/order/%d", f.seq), Names: slices.Clone(names)}
	fo := &fakeOrder{account: account, tokens: map[string]string{}}
	for i, n := range names {
		tok := fmt.Sprintf("tok-%d-%d", f.seq, i)
		url := fmt.Sprintf("%s/chall/%d", o.URL, i)
		if pick(method, n) == HTTP01 {
			th, err := thumbprint(key.Public())
			if err != nil {
				return Order{}, err
			}
			ka := tok + "." + th
			fo.tokens[n] = ka
			o.Challenges = append(o.Challenges, Challenge{Name: n, Type: HTTP01, Token: tok, KeyAuth: ka, URL: url})
			continue
		}
		v, err := KeyAuthDigest(tok, key)
		if err != nil {
			return Order{}, err
		}
		fo.tokens[n] = v
		o.Challenges = append(o.Challenges, Challenge{Name: n, Type: DNS01, TXTName: ChallengeName(n), TXTValue: v, URL: url})
	}
	fo.o = o
	f.orders[o.URL] = fo
	return o, nil
}

// Validate implements CA.
func (f *FakeCA) Validate(ctx context.Context, key crypto.Signer, account string, o Order) error {
	f.mu.Lock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		f.mu.Unlock()
		return err
	}
	fo := f.orders[o.URL]
	lookup, get := f.Lookup, f.HTTPGet
	f.mu.Unlock()
	if fo == nil || fo.account != account {
		return fmt.Errorf("%w: unknown order", ErrRejected)
	}
	for _, c := range fo.o.Challenges {
		if c.Type == HTTP01 {
			if get == nil {
				return errors.New("fake CA has no HTTP fetch")
			}
			body, err := get(ctx, c.Name, c.Token)
			if err != nil {
				return fmt.Errorf("%w: %s: %v", ErrRejected, c.Name, err)
			}
			if body != fo.tokens[c.Name] {
				return fmt.Errorf("%w: %s: wrong HTTP-01 response", ErrRejected, c.Name)
			}
			continue
		}
		if lookup == nil {
			return errors.New("fake CA has no DNS lookup")
		}
		vals, err := lookup(ctx, c.TXTName)
		if err != nil {
			return err
		}
		if !slices.Contains(vals, fo.tokens[c.Name]) {
			return fmt.Errorf("%w: %s: TXT record not found", ErrRejected, c.TXTName)
		}
	}
	f.mu.Lock()
	fo.valid = true
	f.mu.Unlock()
	return nil
}

// Finalize implements CA.
func (f *FakeCA) Finalize(ctx context.Context, key crypto.Signer, account string, o Order, csrDER []byte) ([][]byte, error) {
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return nil, err
	}
	fo := f.orders[o.URL]
	if fo == nil || !fo.valid || fo.account != account {
		return nil, fmt.Errorf("%w: order not ready", ErrRejected)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		return nil, fmt.Errorf("%w: bad CSR", ErrRejected)
	}
	a, b := slices.Clone(csr.DNSNames), slices.Clone(fo.o.Names)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		return nil, fmt.Errorf("%w: CSR names differ from the order", ErrRejected)
	}
	life := f.Lifetime
	if life == 0 {
		life = 90 * 24 * time.Hour
	}
	f.seq++
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(int64(f.seq) + 1000), Subject: pkix.Name{CommonName: csr.DNSNames[0]}, DNSNames: csr.DNSNames,
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(life), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, f.root, csr.PublicKey, f.rootKey)
	if err != nil {
		return nil, err
	}
	delete(f.orders, o.URL)
	f.issued++
	return [][]byte{der, f.root.Raw}, nil
}

// Revoke implements CA.
func (f *FakeCA) Revoke(ctx context.Context, key crypto.Signer, account string, der []byte, reason RevokeReason) error {
	defer f.mu.Unlock()
	if err := f.enter(); err != nil {
		return err
	}
	f.revoked[string(der)] = true
	f.reasons = append(f.reasons, reason)
	return nil
}
