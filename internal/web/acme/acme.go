// SPDX-License-Identifier: Apache-2.0

// Package acme is mydc-web's certificate automation layer (devel/design/
// web-acme-plan.md). The ACME client, DNS-01 records and renewal schedule
// all run inside mydc-web; mydcd only stores the result in its certificate
// store (REQUEST.md REQ-21). Only DNS-01 is used.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// KeyType is a certificate key algorithm.
type KeyType string

const (
	EC256   KeyType = "ec256"
	EC384   KeyType = "ec384"
	RSA2048 KeyType = "rsa2048"
	RSA3072 KeyType = "rsa3072"
	RSA4096 KeyType = "rsa4096"
)

// DefaultKeyTypes is the default preference order: ECDSA P-256 only. RSA
// is an algorithm to avoid (Jay, 2026-11-26); it can still be picked, and
// "RSA도 함께 받기" (DualRSA, off by default) adds an RSA copy for old
// clients.
var DefaultKeyTypes = []KeyType{EC256}

// NewKey makes a certificate private key. It lives in memory only.
func NewKey(t KeyType) (crypto.Signer, error) {
	switch t {
	case EC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case RSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unknown key type %q", t)
}

// CSR builds a certificate request for names.
func CSR(key crypto.Signer, names []string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names}, key)
}

// EAB is external account binding (ZeroSSL, Google Trust Services).
type EAB struct {
	KeyID string `json:"keyId"`
	HMAC  []byte `json:"hmac"`
}

// CAInfo describes a certificate authority.
type CAInfo struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Directory string    `json:"directory"`
	Staging   bool      `json:"staging"`
	NeedsEAB  bool      `json:"needsEab"`
	CAA       string    `json:"caa"` // issuer domain for CAA records
	KeyTypes  []KeyType `json:"keyTypes"`
	Ready     bool      `json:"ready"`
	Note      string    `json:"note,omitempty"`
}

// Challenge types.
const (
	DNS01  = "dns-01"
	HTTP01 = "http-01"
)

// Challenge is one challenge. DNS-01: put TXTValue at TXTName. HTTP-01:
// answer http://<Name>/.well-known/acme-challenge/<Token> with KeyAuth.
type Challenge struct {
	Name     string `json:"name"`               // the identifier ("shop.example.com", "*.shop.example.com")
	Type     string `json:"type"`               // DNS01 or HTTP01
	TXTName  string `json:"txtName,omitempty"`  // "_acme-challenge.shop.example.com"
	TXTValue string `json:"txtValue,omitempty"` // base64url(sha256(key authorization))
	Token    string `json:"token,omitempty"`    // HTTP-01 path token
	KeyAuth  string `json:"keyAuth,omitempty"`  // HTTP-01 response body
	URL      string `json:"url"`
	Authz    string `json:"authz,omitempty"` // authorization URL (RFC 8555 CAs)
}

// HTTP01Path is the HTTP-01 path prefix.
const HTTP01Path = "/.well-known/acme-challenge/"

// Method picks the challenge type of an identifier (DNS01 or HTTP01). A
// wildcard name always gets DNS01.
type Method func(name string) string

// Order is an ACME order.
type Order struct {
	URL        string      `json:"url"`
	Names      []string    `json:"names"`
	Challenges []Challenge `json:"challenges"`
}

// CA is one ACME directory.
type CA interface {
	Info() CAInfo
	// Register creates (or finds) the account of key and returns its URL.
	Register(ctx context.Context, key crypto.Signer, email string, eab *EAB) (string, error)
	// NewOrder creates an order and returns one challenge per name that
	// still needs one, of the type method picks.
	NewOrder(ctx context.Context, key crypto.Signer, account string, names []string, method Method) (Order, error)
	// Validate tells the CA the TXT records are in place and waits until
	// every challenge is valid.
	Validate(ctx context.Context, key crypto.Signer, account string, o Order) error
	// Finalize sends the CSR and returns the issued chain (DER, leaf first).
	Finalize(ctx context.Context, key crypto.Signer, account string, o Order, csr []byte) ([][]byte, error)
	Revoke(ctx context.Context, key crypto.Signer, account string, certDER []byte) error
}

func pick(method Method, name string) string {
	if strings.HasPrefix(name, "*.") || method == nil {
		return DNS01
	}
	if method(name) == HTTP01 {
		return HTTP01
	}
	return DNS01
}

// ChallengeName returns the TXT name of an identifier.
func ChallengeName(name string) string {
	return "_acme-challenge." + strings.TrimPrefix(name, "*.")
}

// KeyAuthDigest is the DNS-01 TXT value for token and the account key.
func KeyAuthDigest(token string, accountKey crypto.Signer) (string, error) {
	thumb, err := thumbprint(accountKey.Public())
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(token + "." + thumb))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

func thumbprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// Error kinds.
var (
	ErrRateLimited = errors.New("acme: rate limited")
	ErrRejected    = errors.New("acme: the CA rejected the request")
)

// CertInfo is the public data of an issued certificate.
type CertInfo struct {
	Fingerprint string    `json:"fingerprint"` // SHA-256 of the leaf, hex
	Names       []string  `json:"names"`
	Issuer      string    `json:"issuer"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	KeyType     KeyType   `json:"keyType"`
}

// Inspect reads the leaf of a DER chain.
func Inspect(chain [][]byte, kt KeyType) (CertInfo, error) {
	if len(chain) == 0 {
		return CertInfo{}, errors.New("empty chain")
	}
	c, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return CertInfo{}, err
	}
	h := sha256.Sum256(chain[0])
	return CertInfo{Fingerprint: hex.EncodeToString(h[:]), Names: c.DNSNames, Issuer: c.Issuer.CommonName, NotBefore: c.NotBefore, NotAfter: c.NotAfter, KeyType: kt}, nil
}

// ChainPEM encodes a DER chain as PEM.
func ChainPEM(chain [][]byte) []byte {
	var out []byte
	for _, d := range chain {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return out
}

// KeyPEM encodes a private key as PKCS#8 PEM (only to hand it to the
// certificate store; never stored by the web app).
func KeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM reads a PKCS#8 PEM private key (the sealed account key).
func ParseKeyPEM(b []byte) (crypto.Signer, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("not a signing key")
	}
	return s, nil
}

// RenewAt returns when a certificate should be renewed: when a third of its
// lifetime remains.
func RenewAt(notBefore, notAfter time.Time) time.Time {
	life := notAfter.Sub(notBefore)
	return notAfter.Add(-life / 3)
}

// Registry is the set of CAs.
type Registry struct{ cas []CA }

// Register adds a CA.
func (r *Registry) Register(c CA) { r.cas = append(r.cas, c) }

// List returns the CAs.
func (r *Registry) List() []CA {
	if r == nil {
		return nil
	}
	return r.cas
}

// Get returns the CA with id.
func (r *Registry) Get(id string) (CA, error) {
	for _, c := range r.List() {
		if c.Info().ID == id {
			if !c.Info().Ready {
				return nil, fmt.Errorf("%s is not available yet", c.Info().Name)
			}
			return c, nil
		}
	}
	return nil, fmt.Errorf("unknown certificate authority %q", id)
}

// NewKeyTypeCheck reports whether t is a known key type.
func NewKeyTypeCheck(t KeyType) (KeyType, error) {
	switch t {
	case EC256, EC384, RSA2048, RSA3072, RSA4096:
		return t, nil
	}
	return "", fmt.Errorf("unknown key type %q", t)
}
