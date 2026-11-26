// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	"crypto/x509"
	"io"
	"os"
	"syscall"
	"time"
)

// InstalledProfile accepts only explicit node installation files. No app,
// tenant metadata, ambient Vault credential or URL can supply this material.
func InstalledProfile(id, address, mount, prefix, namespace, caFile, tokenFile string) (VaultProfile, error) {
	f, err := os.OpenFile(tokenFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return VaultProfile{}, ErrProvider
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return VaultProfile{}, ErrProvider
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return VaultProfile{}, ErrProvider
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	defer clear(raw)
	if err != nil || len(raw) > 16384 {
		return VaultProfile{}, ErrProvider
	}
	token := bytes.TrimSuffix(raw, []byte{'\n'})
	if len(token) == 0 || bytes.ContainsAny(token, "\x00\r\n\t ") {
		return VaultProfile{}, ErrProvider
	}
	ca, err := os.Open(caFile)
	if err != nil {
		return VaultProfile{}, ErrProvider
	}
	defer ca.Close()
	pem, err := io.ReadAll(io.LimitReader(ca, (1<<20)+1))
	if err != nil || len(pem) > 1<<20 {
		return VaultProfile{}, ErrProvider
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return VaultProfile{}, ErrProvider
	}
	return VaultProfile{ID: id, Address: address, Mount: mount, Prefix: prefix, Namespace: namespace, Roots: roots, Token: string(token), Timeout: 5 * time.Second, MaxBytes: 128 << 10}, nil
}
