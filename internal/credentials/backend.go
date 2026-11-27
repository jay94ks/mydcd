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

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/secrets"
)

// Store is one system credential provider: the builtin Raft store or an
// installed external Vault. Put is ONE immutable create; Read observes that
// original write by its public receipt; Consume is an atomic cluster-wide
// single-use claim. Any error leaves the effect unknown.
type Store interface {
	Ready() bool
	Put(ctx context.Context, ref secrets.Reference, receipt string, material []byte, binding Binding) error
	Read(ctx context.Context, ref secrets.Reference, receipt string) ([]byte, error)
	Fetch(ctx context.Context, ref secrets.Reference) ([]byte, error)
	Consume(ctx context.Context, ref secrets.Reference) error
	Close()
}

// Binding is the public account binding of a new record.
type Binding struct {
	Reference, User, Credential string
	Method                      access.Method
	At                          int64
}

type vaultStore struct{ vault *secrets.Vault }

func (s vaultStore) Ready() bool { return s.vault != nil }
func (s vaultStore) Put(ctx context.Context, ref secrets.Reference, receipt string, material []byte, _ Binding) error {
	_, err := s.vault.PutSystemCredential(ctx, ref, receipt, material)
	return err
}
func (s vaultStore) Read(ctx context.Context, ref secrets.Reference, receipt string) ([]byte, error) {
	f, err := s.vault.ReadSystemCredential(ctx, ref, receipt)
	return fetchedCredential(f, err)
}
func (s vaultStore) Fetch(ctx context.Context, ref secrets.Reference) ([]byte, error) {
	f, err := s.vault.Fetch(ctx, "credential", ref)
	return fetchedCredential(f, err)
}
func (s vaultStore) Consume(ctx context.Context, ref secrets.Reference) error {
	return s.vault.ConsumeSystemCredential(ctx, ref)
}
func (s vaultStore) Close() { s.vault.Close() }

func fetchedCredential(f secrets.Fetched, err error) ([]byte, error) {
	if err != nil {
		return nil, ErrDenied
	}
	out := f.Values["credential"]
	for key, value := range f.Values {
		if key != "credential" {
			clear(value)
		}
	}
	if len(out) == 0 {
		return nil, ErrDenied
	}
	return out, nil
}

// Backend holds the system credential providers of this node: always the
// builtin store, plus at most one installed external Vault. It never accepts
// tenant/app provider configuration and never falls back from one provider,
// source or revision to another; the verifier reference names its provider.
type Backend struct {
	stores map[string]Store
	budget *Budget
}

func (*Backend) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (*Backend) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted credential backend]")
}

// NewBackends returns a backend with the builtin store (when ledger is set)
// and the given external Vault backend's store, if any.
func NewBackends(ledger BuiltinLedger, external *Backend) (*Backend, error) {
	b := &Backend{stores: map[string]Store{}, budget: NewBudget()}
	if external != nil {
		for id, s := range external.stores {
			b.stores[id] = s
		}
	}
	if ledger != nil {
		if _, taken := b.stores[BuiltinProfile]; taken {
			return nil, ErrDenied
		}
		b.stores[BuiltinProfile] = NewBuiltinStore(ledger)
	}
	return b, nil
}

// NewBackend opens an external Vault provider. Its profile ID cannot be the
// builtin one.
func NewBackend(profile secrets.VaultProfile) (*Backend, error) {
	if profile.Prefix != "system/credentials" || profile.ID == BuiltinProfile {
		return nil, ErrDenied
	}
	v, err := secrets.NewVault(profile)
	if err != nil {
		return nil, ErrDenied
	}
	return &Backend{stores: map[string]Store{profile.ID: vaultStore{v}}, budget: NewBudget()}, nil
}

// AttemptsLeft is how many more password or token attempts this node admits
// for username now, out of max (Budget; it refills one every 12 seconds).
func (b *Backend) AttemptsLeft(username string, now time.Time) (left, max int) {
	if b == nil {
		return 0, 0
	}
	return b.budget.Left(username, now), userBurst
}

func (b *Backend) Close() {
	if b != nil {
		for _, s := range b.stores {
			s.Close()
		}
	}
}

func (b *Backend) store(profile string) (Store, bool) {
	if b == nil {
		return nil, false
	}
	s, ok := b.stores[profile]
	return s, ok
}

// Ready reports whether this node can use the provider of reference ref
// now. A builtin record on a node that is not a voter is not ready: the
// caller sends the user to a voter before any secret is sent.
func (b *Backend) Ready(ref string) bool {
	r, err := Reference(ref)
	if err != nil {
		return false
	}
	s, ok := b.store(r.Profile)
	return ok && s.Ready()
}

// DefaultProfile is the provider used when none is named: the installed
// external Vault, else builtin.
func (b *Backend) DefaultProfile() string {
	if b == nil {
		return ""
	}
	for id := range b.stores {
		if id != BuiltinProfile {
			return id
		}
	}
	if _, ok := b.stores[BuiltinProfile]; ok {
		return BuiltinProfile
	}
	return ""
}

// Has reports whether profile is a provider of this node.
func (b *Backend) Has(profile string) bool {
	_, ok := b.store(profile)
	return ok
}

func (b *Backend) Verify(ctx context.Context, cluster [32]byte, user access.User, credential access.Credential, presented []byte, source string, now time.Time) (Grant, error) {
	if b == nil || !user.Enabled || len(presented) == 0 || len(presented) > 1024 {
		return Grant{}, ErrDenied
	}
	ref, err := Reference(credential.VerifierRef)
	if err != nil || !strings.HasPrefix(ref.Object, "system/credentials/") {
		return Grant{}, ErrDenied
	}
	store, ok := b.store(ref.Profile)
	if !ok {
		return Grant{}, ErrDenied
	}
	release, err := b.budget.Begin(ctx, user.Username, source, now)
	if err != nil {
		return Grant{}, ErrThrottled
	}
	defer release()
	fetched, err := store.Fetch(ctx, ref)
	if err != nil {
		return Grant{}, ErrDenied
	}
	defer clear(fetched)
	m, err := Restore(fetched)
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
	if m.record.OneTime && store.Consume(ctx, ref) != nil {
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
