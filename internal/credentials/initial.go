// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/identity"
)

// InitialRequest contains PUBLIC intent only. Operation must be a stable
// caller-selected nonce saved before dispatch, never a digest of a password.
type InitialRequest struct {
	Schema               uint8
	Cluster, Owner       [32]byte
	Operation            [32]byte
	User, Username       string
	Credential, Profile  string
	Method               access.Method
	ExpectedUserRevision uint64
	At                   int64
}

func (r InitialRequest) Valid() bool {
	return r.Schema == 1 && r.Cluster != ([32]byte{}) && r.Owner != ([32]byte{}) && r.Operation != ([32]byte{}) &&
		identifier(r.User) && len(r.Username) > 0 && len(r.Username) <= 63 && identifier(r.Credential) && identifier(r.Profile) &&
		(r.Method == access.Password || r.Method == access.Token) && r.ExpectedUserRevision > 0 && r.At > 0 && r.At <= 1<<62
}

func (r InitialRequest) Receipt() string {
	raw, _ := json.Marshal(r)
	digest := sha256.Sum256(append([]byte("mydc-initial-credential-1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}

func (r InitialRequest) Reference() string {
	return "vault/" + r.Profile + "/system/credentials/initial/" + hex.EncodeToString(r.Cluster[:]) + "/" + r.Receipt() + "@1"
}

func (r InitialRequest) CredentialRecord() access.Credential {
	return access.Credential{ID: r.Credential, Method: r.Method, VerifierRef: r.Reference(), Enabled: true, OneTime: r.Method == access.Token}
}

// InitialFact proves only that the installed owner observed this immutable
// provider write. It grants no account authority without an administrator's
// signed management action and an exact current target-user CAS.
type InitialFact struct {
	Request   InitialRequest
	Signature []byte
}

func initialFactBytes(r InitialRequest) []byte {
	raw, _ := json.Marshal(r)
	return append([]byte("mydc-initial-credential-fact-1\x00"), raw...)
}

func (f InitialFact) Verify() bool {
	return f.Request.Valid() && ed25519.Verify(ed25519.PublicKey(f.Request.Owner[:]), initialFactBytes(f.Request), f.Signature)
}

func SignInitialFact(r InitialRequest, private ed25519.PrivateKey) (InitialFact, error) {
	if !r.Valid() || len(private) != ed25519.PrivateKeySize {
		return InitialFact{}, ErrDenied
	}
	f := InitialFact{Request: r, Signature: ed25519.Sign(private, initialFactBytes(r))}
	if !f.Verify() {
		return InitialFact{}, ErrDenied
	}
	return f, nil
}

// InitialIssued deliberately cannot enter ordinary logs, operation journals,
// or ordinary JSON replies. The protected provisioning adapter copies Token
// explicitly; its consumer keeps it private until publication succeeds and
// clears it on every exit. Recovery never returns those bytes again.
type InitialIssued struct {
	Request InitialRequest
	Token   []byte
}

func (InitialIssued) MarshalJSON() ([]byte, error) { return nil, ErrDenied }
func (InitialIssued) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted initial credential]")
}
func (i *InitialIssued) Destroy() {
	if i != nil {
		clear(i.Token)
		i.Token = nil
	}
}

func initialTokenScopes() []access.Scope {
	return []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read, access.ManageNetwork, access.Deploy, access.ManageSecrets, access.ManageVolumes, access.ManageRoutes, access.ManageServices, access.ManageCD, access.ManageRegistry, access.ManageTrust, access.ManageMembers, access.ManageCluster, access.ManageCredentials}}}
}

// PrepareInitial is ONE explicitly dispatched CAS=0 provider write. Adapters
// authorize the target and preserve public intent before calling it. On error
// they may only ObserveInitial, not regenerate/retry a password or token.
func (b *Backend) PrepareInitial(ctx context.Context, r InitialRequest, password []byte, source string, now time.Time) (InitialIssued, error) {
	if b == nil || !r.Valid() || r.Profile != b.profile || r.At > now.Unix() || now.Unix()-r.At > 300 || source == "" ||
		r.Method == access.Password && (len(password) == 0 || len(password) > 1024) || r.Method == access.Token && len(password) != 0 {
		return InitialIssued{}, ErrDenied
	}
	release, err := b.budget.Begin(ctx, r.Username, source, now)
	if err != nil {
		return InitialIssued{}, ErrDenied
	}
	defer release()
	ref, err := Reference(r.Reference())
	if err != nil {
		return InitialIssued{}, ErrDenied
	}
	issued := InitialIssued{Request: r}
	var material Material
	if r.Method == access.Password {
		salt := make([]byte, 16)
		if _, err = rand.Read(salt); err == nil {
			material, err = NewPassword(r.Cluster, r.User, r.Credential, r.Reference(), password, salt, identity.DefaultPasswordCost())
		}
		clear(salt)
	} else {
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err == nil {
			issued.Token = []byte(base64.RawURLEncoding.EncodeToString(raw))
			material, err = NewOneTimeToken(r.Cluster, r.User, r.Credential, r.Reference(), issued.Token, r.At+86400, initialTokenScopes())
		}
		clear(raw)
	}
	defer material.Destroy()
	if err != nil {
		issued.Destroy()
		return InitialIssued{}, ErrDenied
	}
	raw, err := material.ProtectedBytes()
	defer clear(raw)
	if err != nil || ctx.Err() != nil {
		issued.Destroy()
		return InitialIssued{}, ErrDenied
	}
	if _, err = b.vault.PutSystemCredential(ctx, ref, r.Receipt(), raw); err != nil {
		issued.Destroy()
		return InitialIssued{}, ErrDenied
	}
	return issued, nil
}

// ObserveInitial does not return private material or a previously generated
// token, even when the original provider response was lost.
func (b *Backend) ObserveInitial(ctx context.Context, r InitialRequest) error {
	if b == nil || !r.Valid() || r.Profile != b.profile {
		return ErrDenied
	}
	ref, err := Reference(r.Reference())
	if err != nil {
		return ErrDenied
	}
	fetched, err := b.vault.ReadSystemCredential(ctx, ref, r.Receipt())
	if err != nil {
		return ErrDenied
	}
	for _, data := range fetched.Values {
		defer clear(data)
	}
	m, err := Restore(fetched.Values["credential"])
	if err != nil {
		return ErrDenied
	}
	defer m.Destroy()
	x := m.record
	if x.Cluster != r.Cluster || x.User != r.User || x.Credential != r.Credential || x.Method != r.Method || x.Reference != r.Reference() || x.OneTime != (r.Method == access.Token) || r.Method == access.Token && x.ExpiresAt != r.At+86400 {
		return ErrDenied
	}
	return nil
}
