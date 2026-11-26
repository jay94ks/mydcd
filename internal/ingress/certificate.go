// SPDX-License-Identifier: Apache-2.0

package ingress

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
)

// LoadCertificate is the shared installation-local TLS loader. It returns no
// private material to management and grants neither a listener nor a hostname.
func LoadCertificate(c Certificate) (*tls.Config, [32]byte, error) {
	info, err := os.Lstat(c.KeyFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, [32]byte{}, errors.New("TLS key must be a private regular file")
	}
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil || len(pair.Certificate) == 0 {
		return nil, [32]byte{}, errors.New("local TLS certificate unavailable")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, [32]byte{}, err
	}
	pair.Leaf = leaf
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, NextProtos: []string{"h2", "http/1.1"}}, sha256.Sum256(leaf.Raw), nil
}
