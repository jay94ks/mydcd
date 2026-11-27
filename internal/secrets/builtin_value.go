// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	"github.com/jay94ks/seafield/internal/sealed"
)

// BuiltinInfo separates builtin Secret keys from certificate and credential
// keys derived from the same cluster master key.
const BuiltinInfo = "sfc/secret/v1"

// BuiltinMaxBytes bounds the raw values of one builtin write, the same
// usable size as an installed Vault profile (half of its 128KB encoding).
const BuiltinMaxBytes = 64 << 10

// MaxBuiltinValue bounds one encoded BuiltinValue (JSON, sealed bytes in
// base64) as stored locally and sent between voters.
const MaxBuiltinValue = 160 << 10

// ErrBuiltin is the only error for sealing, opening or binding a builtin
// value: callers must not learn which check failed.
var ErrBuiltin = errors.New("builtin secret value unavailable")

// BuiltinValue is one builtin write's value as voters store it. Everything but
// Sealed is public binding data and the AAD; Sealed is AES-256-GCM over the
// canonical JSON of the write's {key: bytes}. A voter that receives it only
// checks the public fields; only a voter holding the master key opens it.
type BuiltinValue struct {
	Schema   uint8
	Cluster  [32]byte
	Realm    string
	Kind     WriteKind
	Object   string
	Revision uint64
	Keys     []string
	Write    string
	Epoch    uint64
	Receipt  string
	Sealer   [32]byte
	Sealed   []byte
}

// BuiltinWriteKey names the local index entry of one original write.
func BuiltinWriteKey(cluster [32]byte, realm string, w WriteRecord) string {
	return providerJournalKey(cluster, realm, w)
}

// Digest is SHA-256 over the whole encoded value, sealed bytes included. It
// is the only part of a value that enters Raft.
func (v BuiltinValue) Digest() [32]byte {
	raw, _ := json.Marshal(v)
	return sha256.Sum256(raw)
}

func (v BuiltinValue) aad() []byte {
	v.Sealed = nil
	raw, _ := json.Marshal(v)
	return append([]byte("sfc-secret-builtin-value-1\x00"), raw...)
}

// StoreKey names a value in a voter's local store: its digest.
func (v BuiltinValue) StoreKey() string {
	d := v.Digest()
	return hex.EncodeToString(d[:])
}

func (v BuiltinValue) salt() []byte {
	s := sha256.Sum256([]byte("sfc-secret-builtin-salt-1\x00" + v.Realm + "\x00" + string(v.Kind) + "\x00" + v.Object + "\x00" + strconv.FormatUint(v.Revision, 10)))
	return s[:]
}

func builtinKeys(w WriteRecord) []string {
	if w.Request.Kind == VerifierWrite {
		return []string{"verifier"}
	}
	return slices.Clone(w.Request.Keys)
}

// Binds reports whether v is the value of original builtin write w of realm.
func (v BuiltinValue) Binds(cluster [32]byte, realm string, w WriteRecord) bool {
	return v.Schema == 1 && cluster != ([32]byte{}) && v.Cluster == cluster && v.Realm == realm && w.Writer.Builtin() && w.Request.Profile == BuiltinProfile &&
		v.Kind == w.Request.Kind && v.Object == w.Request.ProviderObject && w.Request.ExpectedProviderRevision < 1<<31-1 && v.Revision == w.Request.ExpectedProviderRevision+1 &&
		slices.Equal(v.Keys, builtinKeys(w)) && v.Write == w.Request.ID && v.Epoch == w.Request.Epoch && v.Receipt == writeReceipt(w) &&
		v.Sealer != ([32]byte{}) && len(v.Sealed) > sealed.Overhead && len(v.Sealed) <= MaxBuiltinValue
}

// SealBuiltinValue seals values for original write w. values must hold
// exactly the write's keys (a verifier write: "verifier").
func SealBuiltinValue(master []byte, cluster [32]byte, realm string, w WriteRecord, sealer [32]byte, values map[string][]byte) (BuiltinValue, error) {
	keys := builtinKeys(w)
	if len(values) != len(keys) || len(keys) == 0 {
		return BuiltinValue{}, ErrBuiltin
	}
	total := 0
	for _, k := range keys {
		value, ok := values[k]
		if !ok {
			return BuiltinValue{}, ErrBuiltin
		}
		total += len(value)
	}
	if total > BuiltinMaxBytes {
		return BuiltinValue{}, ErrBuiltin
	}
	plain, err := json.Marshal(values)
	if err != nil {
		return BuiltinValue{}, ErrBuiltin
	}
	defer clear(plain)
	v := BuiltinValue{Schema: 1, Cluster: cluster, Realm: realm, Kind: w.Request.Kind, Object: w.Request.ProviderObject, Revision: w.Request.ExpectedProviderRevision + 1, Keys: keys, Write: w.Request.ID, Epoch: w.Request.Epoch, Receipt: writeReceipt(w), Sealer: sealer}
	if v.Sealed, err = sealed.Seal(master, v.salt(), BuiltinInfo, plain, v.aad()); err != nil {
		return BuiltinValue{}, ErrBuiltin
	}
	if !v.Binds(cluster, realm, w) {
		return BuiltinValue{}, ErrBuiltin
	}
	return v, nil
}

// OpenBuiltinValue returns the values of v. The caller clears them.
func OpenBuiltinValue(master []byte, v BuiltinValue) (map[string][]byte, error) {
	if v.Schema != 1 || len(v.Sealed) <= sealed.Overhead || len(v.Sealed) > MaxBuiltinValue {
		return nil, ErrBuiltin
	}
	plain, err := sealed.Open(master, v.salt(), BuiltinInfo, v.Sealed, v.aad())
	if err != nil {
		return nil, ErrBuiltin
	}
	defer clear(plain)
	var out map[string][]byte
	if json.Unmarshal(plain, &out) != nil || len(out) != len(v.Keys) {
		return nil, ErrBuiltin
	}
	for _, k := range v.Keys {
		if _, ok := out[k]; !ok {
			return nil, ErrBuiltin
		}
	}
	return out, nil
}

// HolderBytes is what a voter signs after it stored v durably. It equals
// HolderBytes of the Applied observation that carries v's digest.
func (v BuiltinValue) HolderBytes(voter [32]byte) []byte {
	return HolderBytes(WriteObservation{Cluster: v.Cluster, Tenant: v.Realm, Request: WriteRequest{ID: v.Write, Epoch: v.Epoch, ProviderObject: v.Object}, ProviderRevision: v.Revision, Digest: v.Digest()}, voter)
}

// BuiltinReceipt is the provider receipt of an original builtin write: its
// revision and public intent receipt, as an installed Vault gives them.
func BuiltinReceipt(v BuiltinValue) ProviderReceipt {
	return ProviderReceipt{Revision: v.Revision, Original: v.Receipt}
}
