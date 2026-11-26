// SPDX-License-Identifier: Apache-2.0

// Package certstore owns the cluster certificate store. Certificates have no
// names: the ID is the SHA-256 of the leaf DER, and hosts come from the leaf.
// Public state contains only chains, authenticated ciphertext and signed facts.
package certstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

const MaxChainBytes = 8 << 10
const MaxKeyBytes = 8 << 10
const MaxEntries = 256
const MaxHosts = 128

var ErrCertificate = errors.New("invalid or unavailable certificate")
var ErrConflict = errors.New("certificate state conflict")

// ErrLinked refuses deleting a certificate that still holds links.
var ErrLinked = errors.New("certificate is linked")

// Refusal codes for a chain that cannot enter the store. They match the web
// `invalid` values and the CLI messages.
const (
	InvalidExpired     = "expired"
	InvalidNotYetValid = "not-yet-valid"
	InvalidKey         = "unsupported-key"
	InvalidNoNames     = "no-names"
)

// Material never participates in public JSON or structured logging. Only the
// dedicated sensitive input codec explicitly encodes its byte fields.
type Material struct{ Chain, Key []byte }

func (Material) MarshalJSON() ([]byte, error) { return nil, ErrCertificate }
func (Material) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted certificate material]")
}
func (m Material) Clear() { clear(m.Chain); clear(m.Key) }

// ID is the SHA-256 of the leaf certificate DER.
type ID [32]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// ParseID reads a full 64-character lower-case hex ID.
func ParseID(s string) (ID, bool) {
	var id ID
	if len(s) != 64 || strings.ToLower(s) != s {
		return id, false
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, false
	}
	return id, true
}

type Metadata struct {
	ID ID
	// Hosts are the leaf DNS and IP SANs, or the Subject CN when the leaf has
	// no SAN. DNS names are lower case; a wildcard keeps its "*." prefix.
	Hosts []string
	// Algorithm is ecdsa-p256, ecdsa-p384 or rsa-<bits>.
	Algorithm           string
	Issuer, Serial      string
	NotBefore, NotAfter int64
	UploadedBy          string
	UploadedAt          int64
}

// Family is the link family of an algorithm: one link per (host, family).
func Family(algorithm string) string {
	if strings.HasPrefix(algorithm, "rsa-") {
		return "rsa"
	}
	return "ecdsa"
}

// Discouraged reports an accepted algorithm that people should move off.
func Discouraged(algorithm string) bool { return Family(algorithm) == "rsa" }

type Certificate struct {
	Schema        uint8
	Cluster       [32]byte
	Metadata      Metadata
	Chain         []byte
	SealedKey     []byte
	KeyID, Sealer [32]byte
	Request       string
	Signature     []byte
}

func CertificateBytes(v Certificate) []byte {
	v.Signature = nil
	raw, _ := json.Marshal(v)
	return append([]byte("mydc-certificate-2\x00"), raw...)
}
func (v Certificate) Digest() [32]byte { return sha256.Sum256(CertificateBytes(v)) }

func validDNSHost(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	host := strings.TrimPrefix(name, "*.")
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range []byte(label) {
			if c != '-' && !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}

// Inspection is what the store reads from a chain before any key is seen.
// Invalid is empty when the chain can enter the store at `at`.
type Inspection struct {
	Metadata Metadata
	Subjects []string
	Invalid  string
}

func parseChain(chain []byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 || len(chain) > MaxChainBytes {
		return nil, ErrCertificate
	}
	rest := chain
	var out []*x509.Certificate
	for len(bytes.TrimSpace(rest)) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, ErrCertificate
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCertificate
		}
		out = append(out, parsed)
		if len(out) > 16 {
			return nil, ErrCertificate
		}
		rest = next
	}
	if len(out) == 0 {
		return nil, ErrCertificate
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].CheckSignatureFrom(out[i]) != nil {
			return nil, ErrCertificate
		}
	}
	return out, nil
}
func leafHosts(leaf *x509.Certificate) []string {
	hosts := []string{}
	for _, name := range leaf.DNSNames {
		hosts = append(hosts, strings.ToLower(name))
	}
	for _, ip := range leaf.IPAddresses {
		if a, ok := netip.AddrFromSlice(ip); ok {
			hosts = append(hosts, a.Unmap().String())
		}
	}
	if len(hosts) == 0 && leaf.Subject.CommonName != "" {
		hosts = append(hosts, strings.ToLower(leaf.Subject.CommonName))
	}
	for _, h := range hosts {
		if _, err := netip.ParseAddr(h); err != nil && !validDNSHost(h) {
			return nil
		}
	}
	slices.Sort(hosts)
	return slices.Compact(hosts)
}
func leafAlgorithm(leaf *x509.Certificate) string {
	switch key := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			return "ecdsa-p256"
		case elliptic.P384():
			return "ecdsa-p384"
		}
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits >= 2048 && bits <= 8192 {
			return "rsa-" + strconv.Itoa(bits)
		}
	}
	return ""
}

// Inspect reads a public chain. It returns ErrCertificate only for a chain
// that is not a parseable leaf-first chain; refusals go to Invalid.
func Inspect(chain []byte, at int64) (Inspection, error) {
	certs, err := parseChain(chain)
	if err != nil {
		return Inspection{}, err
	}
	leaf := certs[0]
	if leaf.IsCA || leaf.NotAfter.Unix() <= leaf.NotBefore.Unix() || leaf.NotBefore.Unix() < 0 {
		return Inspection{}, ErrCertificate
	}
	out := Inspection{Metadata: Metadata{ID: sha256.Sum256(leaf.Raw), Hosts: leafHosts(leaf), Algorithm: leafAlgorithm(leaf), Issuer: leaf.Issuer.String(), Serial: strings.ToLower(leaf.SerialNumber.Text(16)), NotBefore: leaf.NotBefore.Unix(), NotAfter: leaf.NotAfter.Unix()}}
	for _, c := range certs {
		out.Subjects = append(out.Subjects, c.Subject.String())
	}
	switch {
	case len(out.Metadata.Hosts) == 0 || len(out.Metadata.Hosts) > MaxHosts:
		out.Invalid = InvalidNoNames
	case out.Metadata.Algorithm == "":
		out.Invalid = InvalidKey
	case at < out.Metadata.NotBefore:
		out.Invalid = InvalidNotYetValid
	case at >= out.Metadata.NotAfter:
		out.Invalid = InvalidExpired
	}
	return out, nil
}

func (v Certificate) Validate() error {
	m := v.Metadata
	if v.Schema != 2 || v.Cluster == ([32]byte{}) || m.UploadedBy == "" || len(m.UploadedBy) > 128 || m.UploadedAt < m.NotBefore || m.UploadedAt >= m.NotAfter || v.KeyID == ([32]byte{}) || v.Sealer == ([32]byte{}) || v.Request == "" || len(v.Request) > 256 || len(v.SealedKey) < 12+16+1 || len(v.SealedKey) > 32<<10 || !ed25519.Verify(v.Sealer[:], CertificateBytes(v), v.Signature) {
		return ErrCertificate
	}
	in, err := Inspect(v.Chain, m.UploadedAt)
	if err != nil || in.Invalid != "" {
		return ErrCertificate
	}
	in.Metadata.UploadedBy, in.Metadata.UploadedAt = m.UploadedBy, m.UploadedAt
	a, _ := json.Marshal(in.Metadata)
	b, _ := json.Marshal(m)
	if !bytes.Equal(a, b) {
		return ErrCertificate
	}
	return nil
}

// keyAAD binds the ciphertext to its cluster and certificate.
func keyAAD(cluster [32]byte, id ID) []byte {
	return append(append([]byte("mydc-certificate-key-1\x00"), cluster[:]...), id[:]...)
}
func keyAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCertificate
	}
	return cipher.NewGCM(block)
}

// Seal encrypts the private key with AES-256-GCM under key, the key derived
// for this certificate (Derive), and signs the public receipt as sealer.
func Seal(cluster [32]byte, user, request string, at int64, m Material, key []byte, sealer ed25519.PrivateKey) (Certificate, error) {
	if len(key) != 32 || len(sealer) != ed25519.PrivateKeySize || len(m.Key) == 0 || len(m.Key) > MaxKeyBytes {
		return Certificate{}, ErrCertificate
	}
	pair, err := tls.X509KeyPair(m.Chain, m.Key)
	if err != nil || len(pair.Certificate) == 0 {
		return Certificate{}, ErrCertificate
	}
	in, err := Inspect(m.Chain, at)
	if err != nil || in.Invalid != "" {
		return Certificate{}, ErrCertificate
	}
	meta := in.Metadata
	meta.UploadedBy, meta.UploadedAt = user, at
	aead, err := keyAEAD(key)
	if err != nil {
		return Certificate{}, ErrCertificate
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Certificate{}, ErrCertificate
	}
	sealed := aead.Seal(nonce, nonce, m.Key, keyAAD(cluster, meta.ID))
	v := Certificate{Schema: 2, Cluster: cluster, Metadata: meta, Chain: bytes.Clone(m.Chain), SealedKey: sealed, KeyID: sha256.Sum256(key), Request: request}
	copy(v.Sealer[:], sealer.Public().(ed25519.PublicKey))
	v.Signature = ed25519.Sign(sealer, CertificateBytes(v))
	if v.Validate() != nil {
		return Certificate{}, ErrCertificate
	}
	return v, nil
}
func Open(v Certificate, key []byte) (tls.Certificate, error) {
	if v.Validate() != nil || len(key) != 32 || sha256.Sum256(key) != v.KeyID {
		return tls.Certificate{}, ErrCertificate
	}
	aead, err := keyAEAD(key)
	if err != nil || len(v.SealedKey) < aead.NonceSize()+aead.Overhead() {
		return tls.Certificate{}, ErrCertificate
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, v.SealedKey[:n], v.SealedKey[n:], keyAAD(v.Cluster, v.Metadata.ID))
	if err != nil {
		return tls.Certificate{}, ErrCertificate
	}
	defer clear(plain)
	pair, err := tls.X509KeyPair(v.Chain, plain)
	if err != nil {
		return tls.Certificate{}, ErrCertificate
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ErrCertificate
	}
	return pair, nil
}
