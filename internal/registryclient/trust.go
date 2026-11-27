// SPDX-License-Identifier: Apache-2.0

package registryclient

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"github.com/jay94ks/seafield/internal/access"
)

const MaxCertificateBytes = 64 << 10

// RegistryTrust contains public certificates only, never a TLS private key or
// an arbitrary Vault value. Fingerprint is the managed server's leaf hash;
// external CA sets have no managed fingerprint.
type RegistryTrust struct {
	Authority    string
	Certificates [][]byte
	Fingerprint  [32]byte `json:",omitempty"`
}

func validCertificates(certificates [][]byte) bool {
	if len(certificates) > 128 {
		return false
	}
	total := 0
	pemBytes := 0
	for _, raw := range certificates {
		if len(raw) == 0 || len(raw) > MaxCertificateBytes-total {
			return false
		}
		if _, err := x509.ParseCertificate(raw); err != nil {
			return false
		}
		total += len(raw)
		pemBytes += len(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
		if pemBytes > MaxCertificateBytes {
			return false
		}
	}
	return true
}

func (t RegistryTrust) Valid() bool {
	if _, err := access.CanonicalTrust([]access.TrustRule{{Registry: t.Authority, Repository: "**"}}); err != nil || !validCertificates(t.Certificates) {
		return false
	}
	return t.Fingerprint == ([32]byte{}) || len(t.Certificates) > 0 && sha256.Sum256(t.Certificates[0]) == t.Fingerprint
}

func (t RegistryTrust) PEM() ([]byte, error) {
	if !t.Valid() {
		return nil, &Error{Code: "INVALID_CA"}
	}
	var out []byte
	for _, raw := range t.Certificates {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
	}
	return out, nil
}

func parseCertificates(raw []byte) ([][]byte, error) {
	if len(raw) == 0 || len(raw) > MaxCertificateBytes {
		return nil, &Error{Code: "INVALID_CA"}
	}
	var certificates [][]byte
	for rest := bytes.TrimSpace(raw); len(rest) > 0; {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, &Error{Code: "INVALID_CA"}
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, &Error{Code: "INVALID_CA"}
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, &Error{Code: "INVALID_CA"}
		}
		certificates = append(certificates, bytes.Clone(block.Bytes))
		rest = bytes.TrimSpace(tail)
	}
	if !validCertificates(certificates) {
		return nil, &Error{Code: "INVALID_CA"}
	}
	return certificates, nil
}

func cloneCertificates(certificates [][]byte) [][]byte {
	var out [][]byte
	for _, raw := range certificates {
		out = append(out, bytes.Clone(raw))
	}
	return out
}

// PublicTrust copies only the explicit public CA additions. System trust and
// credentials are not serialized or exported to another node/container.
func (a *Access) PublicTrust() RegistryTrust {
	return RegistryTrust{Authority: a.authority, Certificates: cloneCertificates(a.certificates)}
}
