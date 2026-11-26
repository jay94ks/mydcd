// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/secrets"
)

// Backend is a system-only credential provider. It never accepts tenant/app
// provider configuration and never falls back to another source or revision.
type Backend struct {
	vault   *secrets.Vault
	profile string
	budget  *Budget
}

func (*Backend) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*Backend) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted credential backend]")
}

func NewBackend(profile secrets.VaultProfile) (*Backend, error) {
	if profile.Prefix != "system/credentials" {
		return nil, ErrDenied
	}
	v, err := secrets.NewVault(profile)
	if err != nil {
		return nil, ErrDenied
	}
	return &Backend{vault: v, profile: profile.ID, budget: NewBudget()}, nil
}

func (b *Backend) Close() {
	if b != nil {
		b.vault.Close()
	}
}

func (b *Backend) Verify(ctx context.Context, cluster [32]byte, user access.User, credential access.Credential, presented []byte, source string, now time.Time) (Grant, error) {
	if b == nil || !user.Enabled || len(presented) == 0 || len(presented) > 1024 {
		return Grant{}, ErrDenied
	}
	ref, err := Reference(credential.VerifierRef)
	if err != nil || ref.Profile != b.profile || !strings.HasPrefix(ref.Object, "system/credentials/") {
		return Grant{}, ErrDenied
	}
	release, err := b.budget.Begin(ctx, user.Username, source, now)
	if err != nil {
		return Grant{}, ErrDenied
	}
	defer release()
	fetched, err := b.vault.Fetch(ctx, credential.ID, ref)
	if err != nil {
		return Grant{}, ErrDenied
	}
	defer func() {
		for _, value := range fetched.Values {
			clear(value)
		}
	}()
	m, err := Restore(fetched.Values["credential"])
	if err != nil {
		return Grant{}, ErrDenied
	}
	defer m.Destroy()
	if ctx.Err() != nil {
		return Grant{}, ErrDenied
	}
	g, err := m.Verify(cluster, user.ID, credential, presented, now.Unix())
	if err != nil || ctx.Err() != nil {
		return Grant{}, ErrDenied
	}
	if m.record.OneTime && b.vault.ConsumeSystemCredential(ctx, ref) != nil {
		// A lost claim response burns the token; absence of a successful reply
		// never authorizes a second login. Existing issued sessions are separate.
		return Grant{}, ErrDenied
	}
	return g, nil
}

// OpenLocal reads only explicitly installed files. Neither VAULT_* nor tenant
// data can provide a CA, endpoint, namespace or system provider credential.
func OpenLocal(id, address, mount, namespace, caFile, tokenFile string) (*Backend, error) {
	f, err := os.OpenFile(tokenFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrDenied
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, ErrDenied
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, ErrDenied
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	defer clear(raw)
	if err != nil || len(raw) > 16384 {
		return nil, ErrDenied
	}
	token := bytes.TrimSuffix(raw, []byte{'\n'})
	if len(token) == 0 || bytes.ContainsAny(token, "\x00\r\n\t ") {
		return nil, ErrDenied
	}
	ca, err := os.Open(caFile)
	if err != nil {
		return nil, ErrDenied
	}
	defer ca.Close()
	pem, err := io.ReadAll(io.LimitReader(ca, (1<<20)+1))
	if err != nil || len(pem) > 1<<20 {
		return nil, ErrDenied
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, ErrDenied
	}
	return NewBackend(secrets.VaultProfile{ID: id, Address: address, Mount: mount, Prefix: "system/credentials", Namespace: namespace, Token: string(token), Roots: roots, Timeout: 5 * time.Second, MaxBytes: 128 << 10})
}
