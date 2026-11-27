// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/sealed"
	"github.com/jay94ks/seafield/internal/secrets"
)

// BuiltinProfile is the credential provider every cluster has. Its records
// live in replicated Raft state, sealed with a key derived from the cluster
// master key that only current voters hold. An installed external provider
// cannot use this name.
const BuiltinProfile = "builtin"

// BuiltinInfo separates credential keys from certificate keys derived from
// the same master key.
const BuiltinInfo = "sfc/credential/v1"

// MaxBuiltinSealed bounds one sealed record (nonce, material, tag).
const MaxBuiltinSealed = MaxMaterial + sealed.Overhead

// ErrBuiltinUnavailable means this node cannot open builtin records: it is
// not a current voter holding the master key.
var ErrBuiltinUnavailable = errors.New("builtin credential store needs a voter")

// BuiltinRecord is one builtin credential as stored in Raft. Everything but
// Sealed is public binding data; Sealed is AES-256-GCM over the protected
// material, so a Raft log, snapshot or non-voter replica reveals no
// verifier. Consumed is set once by a single-use login.
type BuiltinRecord struct {
	Schema     uint8
	Cluster    [32]byte
	ID         string
	Reference  string
	Receipt    string
	User       string
	Credential string
	Method     access.Method
	At         int64
	Sealer     [32]byte
	Sealed     []byte
	Consumed   bool `json:",omitempty"`
}

// BuiltinID names the record of a verifier reference.
func BuiltinID(reference string) string {
	digest := sha256.Sum256([]byte("sfc-builtin-credential-id-1\x00" + reference))
	return hex.EncodeToString(digest[:])
}

func validHex32(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}

// Valid checks the public shape. It cannot check the sealed contents.
func (r BuiltinRecord) Valid(cluster [32]byte) bool {
	ref, err := Reference(r.Reference)
	return err == nil && r.Schema == 1 && r.Cluster == cluster && cluster != ([32]byte{}) && ref.Profile == BuiltinProfile && strings.HasPrefix(ref.Object, "system/credentials/") && ref.Revision == 1 &&
		r.ID == BuiltinID(r.Reference) && validHex32(r.Receipt) && identifier(r.User) && identifier(r.Credential) &&
		(r.Method == access.Password || r.Method == access.Token) && r.At > 0 && r.At <= 1<<62 && r.Sealer != ([32]byte{}) &&
		len(r.Sealed) > sealed.Overhead && len(r.Sealed) <= MaxBuiltinSealed
}

func builtinAAD(r BuiltinRecord) []byte {
	r.Sealed, r.Consumed = nil, false
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-builtin-credential-1\x00"), raw...)
}

func builtinSalt(id string) ([]byte, error) {
	if !validHex32(id) {
		return nil, ErrDenied
	}
	return hex.DecodeString(id)
}

// SealBuiltin encrypts material for record r (Sealed is replaced).
func SealBuiltin(master []byte, r BuiltinRecord, material []byte) (BuiltinRecord, error) {
	if len(material) == 0 || len(material) > MaxMaterial {
		return BuiltinRecord{}, ErrDenied
	}
	salt, err := builtinSalt(r.ID)
	if err != nil {
		return BuiltinRecord{}, err
	}
	r.Consumed = false
	if r.Sealed, err = sealed.Seal(master, salt, BuiltinInfo, material, builtinAAD(r)); err != nil {
		return BuiltinRecord{}, ErrDenied
	}
	if !r.Valid(r.Cluster) {
		return BuiltinRecord{}, ErrDenied
	}
	return r, nil
}

// OpenBuiltin returns the protected material of r. The caller clears it.
func OpenBuiltin(master []byte, r BuiltinRecord) ([]byte, error) {
	if !r.Valid(r.Cluster) {
		return nil, ErrDenied
	}
	salt, err := builtinSalt(r.ID)
	if err != nil {
		return nil, err
	}
	out, err := sealed.Open(master, salt, BuiltinInfo, r.Sealed, builtinAAD(r))
	if err != nil {
		return nil, ErrDenied
	}
	return out, nil
}

// BuiltinLedger is the node's view of the replicated builtin records.
// Record reads the current quorum-backed state. Put and Consume are single
// Raft writes: Put succeeds only for an absent ID, Consume only once per
// record; any other answer leaves the effect unknown.
type BuiltinLedger interface {
	Cluster() [32]byte
	Self() [32]byte
	// Ready reports whether this node is a voter holding the master key.
	Ready() bool
	Master() ([]byte, error)
	Record(ctx context.Context, id string) (BuiltinRecord, bool, error)
	Put(ctx context.Context, r BuiltinRecord) error
	Consume(ctx context.Context, id string) error
}

type builtinStore struct{ ledger BuiltinLedger }

// NewBuiltinStore wraps the node's ledger as the builtin provider.
func NewBuiltinStore(ledger BuiltinLedger) Store {
	return builtinStore{ledger}
}

func (s builtinStore) Ready() bool { return s.ledger != nil && s.ledger.Ready() }

func (s builtinStore) master() ([]byte, error) {
	if !s.Ready() {
		return nil, ErrBuiltinUnavailable
	}
	return s.ledger.Master()
}

func (s builtinStore) Put(ctx context.Context, ref secrets.Reference, receipt string, material []byte, binding Binding) error {
	master, err := s.master()
	if err != nil {
		return err
	}
	defer clear(master)
	reference := binding.Reference
	r := BuiltinRecord{Schema: 1, Cluster: s.ledger.Cluster(), ID: BuiltinID(reference), Reference: reference, Receipt: receipt, User: binding.User, Credential: binding.Credential, Method: binding.Method, At: binding.At, Sealer: s.ledger.Self()}
	if ref.Profile != BuiltinProfile || reference != "vault/"+ref.Profile+"/"+ref.Object+"@1" {
		return ErrDenied
	}
	if r, err = SealBuiltin(master, r, material); err != nil {
		return err
	}
	return s.ledger.Put(ctx, r)
}

func (s builtinStore) read(ctx context.Context, ref secrets.Reference, receipt string) ([]byte, error) {
	master, err := s.master()
	if err != nil {
		return nil, err
	}
	defer clear(master)
	reference := "vault/" + ref.Profile + "/" + ref.Object + "@1"
	r, found, err := s.ledger.Record(ctx, BuiltinID(reference))
	if err != nil || !found || r.Reference != reference || receipt != "" && r.Receipt != receipt {
		return nil, ErrDenied
	}
	return OpenBuiltin(master, r)
}

func (s builtinStore) Read(ctx context.Context, ref secrets.Reference, receipt string) ([]byte, error) {
	if receipt == "" {
		return nil, ErrDenied
	}
	return s.read(ctx, ref, receipt)
}

func (s builtinStore) Fetch(ctx context.Context, ref secrets.Reference) ([]byte, error) {
	return s.read(ctx, ref, "")
}

func (s builtinStore) Consume(ctx context.Context, ref secrets.Reference) error {
	if !s.Ready() {
		return ErrBuiltinUnavailable
	}
	return s.ledger.Consume(ctx, BuiltinID("vault/"+ref.Profile+"/"+ref.Object+"@1"))
}

func (builtinStore) Close() {}

// SameBuiltin reports whether two records are the same original write.
func SameBuiltin(a, b BuiltinRecord) bool {
	a.Consumed, b.Consumed = false, false
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
