// SPDX-License-Identifier: Apache-2.0

// Package identity owns local Ed25519 keys and pinned-key TLS certificates.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Identity struct {
	Private     ed25519.PrivateKey
	Public      [32]byte
	Certificate tls.Certificate
}

func (i *Identity) Actor() string { return hex.EncodeToString(i.Public[:]) }
func ParseKey(s string) ([32]byte, error) {
	var key [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return key, errors.New("public key must be 64 hexadecimal characters")
	}
	copy(key[:], b)
	if key == [32]byte{} {
		return key, errors.New("zero public key")
	}
	return key, nil
}
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Create never replaces an existing identity. The directory is installation-local.
func Create(root string) (*Identity, error) {
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: hex.EncodeToString(key.Public().(ed25519.PublicKey))}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(root, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, err
	}
	if err := writeNew(filepath.Join(root, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644); err != nil {
		return nil, err
	}
	dir, err := os.Open(root)
	if err != nil {
		return nil, err
	}
	err = dir.Sync()
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	return Load(root)
}
func Load(root string) (*Identity, error) {
	info, err := os.Lstat(filepath.Join(root, "key.pem"))
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private key permissions must exclude group/other")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem"))
	if err != nil {
		return nil, err
	}
	key, ok := cert.PrivateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity requires Ed25519")
	}
	i := &Identity{Private: key, Certificate: cert}
	copy(i.Public[:], key.Public().(ed25519.PublicKey))
	return i, nil
}
func PeerKey(cs tls.ConnectionState) ([32]byte, error) {
	var result [32]byte
	if len(cs.PeerCertificates) != 1 {
		return result, errors.New("one pinned peer certificate required")
	}
	cert := cs.PeerCertificates[0]
	key, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || len(key) != 32 || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil {
		return result, errors.New("invalid pinned peer certificate")
	}
	copy(result[:], key)
	return result, nil
}
func (i *Identity) TLS(server bool, approve func([32]byte) bool) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{i.Certificate}, NextProtos: []string{"mydcp-go-1"}, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		key, err := PeerKey(cs)
		if err != nil {
			return err
		}
		if !approve(key) {
			return errors.New("peer public key not approved")
		}
		return nil
	}}
	if server {
		c.ClientAuth = tls.RequireAnyClientCert
	}
	return c
}
