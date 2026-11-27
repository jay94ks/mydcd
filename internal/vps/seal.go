// SPDX-License-Identifier: Apache-2.0

package vps

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// SealInfo separates VPS provider keys from every other key derived from
// the cluster master key (devel/design/vps-nodes.md §2).
const SealInfo = "sfc/vps-provider/v1"

var ErrSeal = errors.New("vps: sealed credential refused")

var accountName = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidAccountName reports whether name is a provider account name: 1–32
// lower-case letters, digits and inner hyphens.
func ValidAccountName(name string) bool { return accountName.MatchString(name) }

// SealedCredential is a provider credential encrypted with a key only
// current voters can derive, signed by the voter that sealed it. It is what
// Raft stores; the plain key pair never is.
type SealedCredential struct {
	Schema  uint8
	Cluster [32]byte
	Account string
	Request string // the write ID that produced it
	KeyID   [32]byte
	Sealer  [32]byte
	Box     []byte // nonce || AES-256-GCM(credential JSON)
	Hint    string // last four characters of the access key, for display
	// SSHPublic is the account SSH key in authorized_keys form, for the
	// user to register with the vendor; "" without one.
	SSHPublic string `json:",omitempty"`
	Sig       []byte
}

func (s SealedCredential) signed() []byte {
	b := bytes.NewBufferString("sfc/vps-sealed/v1\x00")
	b.Write(s.Cluster[:])
	b.WriteString(s.Account + "\x00" + s.Request + "\x00" + s.Hint + "\x00" + s.SSHPublic + "\x00")
	b.Write(s.KeyID[:])
	b.Write(s.Sealer[:])
	b.Write(s.Box)
	return b.Bytes()
}

func aad(cluster [32]byte, account string) []byte {
	return append(append([]byte("sfc/vps-credential\x00"), cluster[:]...), account...)
}

// DeriveKey is the AES key of account's credential.
func DeriveKey(master []byte, account string) ([]byte, error) {
	if len(master) != 32 || !ValidAccountName(account) {
		return nil, ErrSeal
	}
	return hkdf.Key(sha256.New, master, []byte(account), SealInfo, 32)
}

// Validate checks the shape and the sealer's signature. Whether the sealer
// may seal (a current voter) is the caller's check.
func (s SealedCredential) Validate() error {
	if s.Schema != 1 || s.Cluster == ([32]byte{}) || !ValidAccountName(s.Account) || s.Request == "" || len(s.Request) > 128 || len(s.Hint) > 4 || len(s.SSHPublic) > 256 || strings.ContainsAny(s.SSHPublic, "\r\n") ||
		s.KeyID == ([32]byte{}) || s.Sealer == ([32]byte{}) || len(s.Box) < 12+16+1 || len(s.Box) > 4<<10 || !ed25519.Verify(s.Sealer[:], s.signed(), s.Sig) {
		return ErrSeal
	}
	return nil
}

type plainCredential struct {
	A, S string
	K    string `json:",omitempty"`
}

// Seal encrypts c for account with key (from DeriveKey) and signs it.
func Seal(cluster [32]byte, account, request string, c Credential, key []byte, sealer ed25519.PrivateKey) (SealedCredential, error) {
	if !c.Valid() || len(key) != 32 || len(sealer) != ed25519.PrivateKeySize {
		return SealedCredential{}, ErrSeal
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return SealedCredential{}, ErrSeal
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return SealedCredential{}, ErrSeal
	}
	plain, err := json.Marshal(plainCredential{A: c.AccessKey, S: c.SecretKey, K: c.SSHSeed})
	if err != nil {
		return SealedCredential{}, ErrSeal
	}
	defer clear(plain)
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SealedCredential{}, ErrSeal
	}
	hint := c.AccessKey
	if len(hint) > 4 {
		hint = hint[len(hint)-4:]
	}
	public := ""
	if signer, ok := c.SSHSigner(); ok {
		pub, err := ssh.NewPublicKey(signer.Public())
		if err != nil {
			return SealedCredential{}, ErrSeal
		}
		public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " sfc-" + account
	}
	s := SealedCredential{Schema: 1, Cluster: cluster, Account: account, Request: request, KeyID: sha256.Sum256(key), Hint: hint, SSHPublic: public,
		Box: aead.Seal(nonce, nonce, plain, aad(cluster, account))}
	copy(s.Sealer[:], sealer.Public().(ed25519.PublicKey))
	s.Sig = ed25519.Sign(sealer, s.signed())
	if s.Validate() != nil {
		return SealedCredential{}, ErrSeal
	}
	return s, nil
}

// Open decrypts s with key (from DeriveKey).
func Open(s SealedCredential, key []byte) (Credential, error) {
	if s.Validate() != nil || len(key) != 32 || sha256.Sum256(key) != s.KeyID {
		return Credential{}, ErrSeal
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Credential{}, ErrSeal
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Credential{}, ErrSeal
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, s.Box[:n], s.Box[n:], aad(s.Cluster, s.Account))
	if err != nil {
		return Credential{}, ErrSeal
	}
	defer clear(plain)
	var p plainCredential
	if json.Unmarshal(plain, &p) != nil {
		return Credential{}, ErrSeal
	}
	c := Credential{AccessKey: p.A, SecretKey: p.S, SSHSeed: p.K}
	if !c.Valid() {
		return Credential{}, ErrSeal
	}
	return c, nil
}
