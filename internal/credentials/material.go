// SPDX-License-Identifier: Apache-2.0

// Package credentials binds private authentication material to public catalog
// references. It grants neither user roles nor node/tenant Vault authority.
package credentials

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/secrets"
)

var ErrDenied = errors.New("credential authentication unavailable or denied")

const MaxMaterial = 32 << 10

type protectedRecord struct {
	Schema     uint8
	Cluster    [32]byte
	User       string
	Credential string
	Method     access.Method
	Reference  string
	Verifier   []byte
	ExpiresAt  int64
	Scopes     []access.Scope
	OneTime    bool `json:",omitempty"`
}

type Material struct{ record protectedRecord }

func (Material) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (Material) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted credential material]")
}

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Reference never selects latest, a URL, or another profile implicitly.
func Reference(raw string) (secrets.Reference, error) {
	var ref secrets.Reference
	if len(raw) > 256 || !strings.HasPrefix(raw, "vault/") {
		return ref, ErrDenied
	}
	profile, tail, ok := strings.Cut(strings.TrimPrefix(raw, "vault/"), "/")
	object, version, found := strings.Cut(tail, "@")
	n, err := strconv.ParseUint(version, 10, 31)
	if !ok || !found || !identifier(profile) || object == "" || path.Clean(object) != object || strings.HasPrefix(object, "/") || object == ".." || strings.HasPrefix(object, "../") || strings.ContainsAny(object, "%?#\\\x00\r\n:@") || err != nil || n == 0 || strconv.FormatUint(n, 10) != version {
		return ref, ErrDenied
	}
	return secrets.Reference{Profile: profile, Object: object, Revision: n, Keys: []string{"credential"}}, nil
}

func ownScopes(scopes []access.Scope) []access.Scope {
	if scopes == nil {
		return nil
	}
	out := slices.Clone(scopes)
	for i := range out {
		out[i].Actions = slices.Clone(out[i].Actions)
	}
	return out
}

func (m Material) valid() bool {
	r := m.record
	if r.Schema != 1 || r.Cluster == ([32]byte{}) || !identifier(r.User) || !identifier(r.Credential) {
		return false
	}
	if _, err := Reference(r.Reference); err != nil {
		return false
	}
	switch r.Method {
	case access.Password:
		_, err := identity.RestorePasswordVerifier(r.Verifier)
		return err == nil && r.ExpiresAt == 0 && r.Scopes == nil && !r.OneTime
	case access.Token:
		return len(r.Verifier) == 32 && r.ExpiresAt > 0 && access.ValidateScopes(r.Scopes)
	}
	return false
}

func NewPassword(cluster [32]byte, user, credential, ref string, password, salt []byte, cost identity.PasswordCost) (Material, error) {
	v, err := identity.PasswordHash(password, salt, cost)
	if err != nil {
		return Material{}, ErrDenied
	}
	raw, err := v.ProtectedBytes()
	if err != nil {
		return Material{}, ErrDenied
	}
	m := Material{protectedRecord{Schema: 1, Cluster: cluster, User: user, Credential: credential, Method: access.Password, Reference: ref, Verifier: raw}}
	if !m.valid() {
		clear(raw)
		return Material{}, ErrDenied
	}
	return m, nil
}

func canonicalToken(token []byte) bool {
	if len(token) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(token))
	defer clear(raw)
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == string(token)
}

// NewToken accepts the canonical encoding of a caller-generated 32B random
// value; the raw token is returned only by its generator, never by Material.
func NewToken(cluster [32]byte, user, credential, ref string, token []byte, expires int64, scopes []access.Scope) (Material, error) {
	if !canonicalToken(token) {
		return Material{}, ErrDenied
	}
	digest := sha256.Sum256(token)
	m := Material{protectedRecord{Schema: 1, Cluster: cluster, User: user, Credential: credential, Method: access.Token, Reference: ref, Verifier: slices.Clone(digest[:]), ExpiresAt: expires, Scopes: ownScopes(scopes)}}
	if !m.valid() {
		return Material{}, ErrDenied
	}
	return m, nil
}

// NewOneTimeToken uses the existing token verifier. Actual single use is an
// atomic protected-provider claim after verification, never an in-memory flag.
func NewOneTimeToken(cluster [32]byte, user, credential, ref string, token []byte, expires int64, scopes []access.Scope) (Material, error) {
	m, err := NewToken(cluster, user, credential, ref, token, expires, scopes)
	if err == nil {
		m.record.OneTime = true
	}
	return m, err
}

// ProtectedBytes is exclusively for the system-protected provider, not a
// shared credential, receipt, command body, ordinary config or log field.
func (m Material) ProtectedBytes() ([]byte, error) {
	if !m.valid() {
		return nil, ErrDenied
	}
	b, err := json.Marshal(m.record)
	if err != nil || len(b) > MaxMaterial {
		clear(b)
		return nil, ErrDenied
	}
	return b, nil
}

func Restore(raw []byte) (Material, error) {
	if len(raw) == 0 || len(raw) > MaxMaterial {
		return Material{}, ErrDenied
	}
	var r protectedRecord
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return Material{}, ErrDenied
	}
	m := Material{r}
	canonical, err := m.ProtectedBytes()
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) {
		m.Destroy()
		return Material{}, ErrDenied
	}
	return m, nil
}

func (m *Material) Destroy() {
	if m != nil {
		clear(m.record.Verifier)
		m.record = protectedRecord{}
	}
}

type Grant struct {
	Credential string
	ExpiresAt  int64
	Scopes     []access.Scope
}

// Verify checks the exact public binding before the KDF. Only an authorized
// adapter may turn this grant into a signed session after re-reading policy.
func (m Material) Verify(cluster [32]byte, user string, credential access.Credential, presented []byte, now int64) (Grant, error) {
	r := m.record
	if !m.valid() || now < 0 || cluster != r.Cluster || user != r.User || credential.ID != r.Credential || !credential.Enabled || credential.Method != r.Method || credential.OneTime != r.OneTime || credential.VerifierRef != r.Reference || credential.PublicKey != ([32]byte{}) {
		return Grant{}, ErrDenied
	}
	if r.Method == access.Password {
		v, err := identity.RestorePasswordVerifier(r.Verifier)
		if err != nil || !v.Verify(presented) {
			return Grant{}, ErrDenied
		}
		return Grant{Credential: r.Credential}, nil
	}
	if now >= r.ExpiresAt || !canonicalToken(presented) {
		return Grant{}, ErrDenied
	}
	digest := sha256.Sum256(presented)
	if subtle.ConstantTimeCompare(digest[:], r.Verifier) != 1 {
		return Grant{}, ErrDenied
	}
	return Grant{Credential: r.Credential, ExpiresAt: r.ExpiresAt, Scopes: ownScopes(r.Scopes)}, nil
}

// Select refuses ambiguous credentials rather than reading several providers or
// performing several expensive password checks for one login attempt.
func Select(user access.User, method access.Method, id string) (access.Credential, error) {
	if !user.Enabled || method != access.Password && method != access.Token {
		return access.Credential{}, ErrDenied
	}
	var selected access.Credential
	for _, c := range user.Credentials {
		if !c.Enabled || c.Method != method || id != "" && id != c.ID {
			continue
		}
		if selected.ID != "" {
			return access.Credential{}, ErrDenied
		}
		if _, err := Reference(c.VerifierRef); err != nil {
			return access.Credential{}, ErrDenied
		}
		selected = c
	}
	if selected.ID == "" {
		return selected, ErrDenied
	}
	return selected, nil
}
