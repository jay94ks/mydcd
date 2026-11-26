// SPDX-License-Identifier: Apache-2.0

package wallet

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/localstore"
	"github.com/jay94ks/mydcd/internal/schema"
)

var (
	ErrExists    = errors.New("wallet or named key already exists")
	ErrMissing   = errors.New("wallet or named key does not exist")
	ErrPending   = errors.New("wallet commit is pending; use wallet status/recover without resubmitting")
	ErrPublished = errors.New("wallet update is already published; finish recovery instead of aborting")
)

const walletFile = "wallet.bin"
const nextFile = "wallet.next"
const intentFile = "wallet.intent"

type diskFiles interface {
	Read(string, int) ([]byte, error)
	WriteNew(string, []byte) error
	Rename(string, string) error
	Remove(string) error
	Sync() error
	Close() error
}
type Disk struct {
	files   diskFiles
	lock    *localstore.Lock
	entries []Entry
	loaded  bool
	base    [32]byte
}

func OpenDisk(home string, create bool) (*Disk, error) {
	root, e := localstore.Open(home, create)
	if e != nil {
		return nil, e
	}
	lock, e := root.Lock("wallet.lock")
	if e != nil {
		_ = root.Close()
		return nil, e
	}
	return &Disk{files: root, lock: lock}, nil
}
func (d *Disk) Close() error {
	if d == nil {
		return nil
	}
	Clear(d.entries)
	d.entries = nil
	d.loaded = false
	var a, b error
	if d.lock != nil {
		a = d.lock.Close()
		d.lock = nil
	}
	if d.files != nil {
		b = d.files.Close()
		d.files = nil
	}
	return errors.Join(a, b)
}
func (d *Disk) check() error {
	if d == nil || d.files == nil || d.lock == nil {
		return ErrWallet
	}
	return d.lock.Check()
}
func (d *Disk) read(name string, limit int) ([]byte, bool, error) {
	if d.check() != nil {
		return nil, false, ErrWallet
	}
	b, e := d.files.Read(name, limit)
	if errors.Is(e, fs.ErrNotExist) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, ErrWallet
	}
	return b, true, nil
}

type Status struct {
	Exists               bool `json:"exists"`
	Pending              bool `json:"pending"`
	UnpublishedCandidate bool `json:"unpublished_candidate"`
	Published            bool `json:"published"`
}
type commitIntent struct {
	Schema    uint8    `json:"schema"`
	OldExists bool     `json:"old_exists"`
	Old       [32]byte `json:"old"`
	New       [32]byte `json:"new"`
}

func (d *Disk) intent() (commitIntent, bool, error) {
	b, exists, e := d.read(intentFile, 4096)
	defer clear(b)
	if e != nil || !exists {
		return commitIntent{}, exists, e
	}
	i, e := schema.Decode[commitIntent](b)
	if e != nil || i.Schema != 1 || i.New == ([32]byte{}) || !i.OldExists && i.Old != ([32]byte{}) || i.Old == i.New {
		return commitIntent{}, true, ErrWallet
	}
	return i, true, nil
}
func (d *Disk) current() ([]byte, bool, [32]byte, error) {
	raw, exists, e := d.read(walletFile, MaxFileBytes)
	var hash [32]byte
	if e != nil {
		return nil, false, hash, e
	}
	if exists {
		hash = sha256.Sum256(raw)
	}
	return raw, exists, hash, nil
}
func (d *Disk) Status() (Status, error) {
	raw, exists, hash, e := d.current()
	clear(raw)
	if e != nil {
		return Status{}, e
	}
	i, pending, e := d.intent()
	if e != nil {
		return Status{}, e
	}
	candidate, next, e := d.read(nextFile, MaxFileBytes)
	clear(candidate)
	if e != nil {
		return Status{}, e
	}
	return Status{Exists: exists, Pending: pending, UnpublishedCandidate: next && !pending, Published: pending && exists && hash == i.New}, nil
}
func (d *Disk) Unlock(password []byte) error {
	Clear(d.entries)
	d.entries = nil
	d.loaded = false
	d.base = [32]byte{}
	s, e := d.Status()
	if e != nil {
		return e
	}
	if s.Pending || s.UnpublishedCandidate {
		return ErrPending
	}
	if !s.Exists {
		return ErrMissing
	}
	raw, _, hash, e := d.current()
	defer clear(raw)
	if e != nil {
		return e
	}
	entries, e := Unseal(password, raw)
	if e != nil {
		return e
	}
	Clear(d.entries)
	d.entries = entries
	d.loaded = true
	d.base = hash
	return nil
}
func (d *Disk) Init(password []byte) error {
	if d.loaded {
		return ErrExists
	}
	s, e := d.Status()
	if e != nil {
		return e
	}
	if s.Pending || s.UnpublishedCandidate {
		return ErrPending
	}
	if s.Exists {
		return ErrExists
	}
	raw, e := Seal(password, nil)
	if e != nil {
		return e
	}
	defer clear(raw)
	if e = d.commit(raw, false, [32]byte{}); e != nil {
		return e
	}
	d.entries = nil
	d.loaded = true
	d.base = sha256.Sum256(raw)
	return nil
}

type PublicKey struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	ID   string `json:"id"`
}

func public(e Entry) PublicKey {
	k := e.Public()
	return PublicKey{Name: e.Name, Key: base64.StdEncoding.EncodeToString(k[:]), ID: hex.EncodeToString(k[:])}
}
func (d *Disk) List() ([]PublicKey, error) {
	if !d.loaded || d.check() != nil {
		return nil, ErrWallet
	}
	result := make([]PublicKey, 0, len(d.entries))
	for _, e := range d.entries {
		if e.IsKey() {
			result = append(result, public(e))
		}
	}
	return result, nil
}
func (d *Disk) Get(name string) (Entry, error) {
	if !d.loaded || !cliprofile.ValidKeyName(name) || d.check() != nil {
		return Entry{}, ErrWallet
	}
	for _, entry := range d.entries {
		if entry.Name == name {
			if !entry.IsKey() {
				return Entry{}, ErrWallet
			}
			return entry.Clone(), nil
		}
	}
	return Entry{}, ErrMissing
}

// Put never overwrites an existing key. Exact readback/retry is idempotent; the
// same name with another private key is an error, including during migration.
func (d *Disk) Put(entry Entry) (bool, error) {
	if !d.loaded || d.check() != nil || !cliprofile.ValidKeyName(entry.Name) || !entry.IsKey() {
		return false, ErrWallet
	}
	for _, old := range d.entries {
		if old.Name == entry.Name {
			if !old.IsKey() {
				return false, ErrExists
			}
			if subtle.ConstantTimeCompare(old.Seed[:], entry.Seed[:]) == 1 {
				return false, nil
			}
			return false, ErrExists
		}
	}
	if len(d.entries) >= MaxEntries {
		return false, ErrWallet
	}
	d.entries = append(d.entries, entry)
	slices.SortFunc(d.entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	return true, nil
}
func (d *Disk) Generate(name string) (PublicKey, error) {
	if !d.loaded || !cliprofile.ValidKeyName(name) {
		return PublicKey{}, ErrWallet
	}
	for _, e := range d.entries {
		if e.Name == name {
			return PublicKey{}, ErrExists
		}
	}
	entry := Entry{Name: name}
	defer clear(entry.Seed[:])
	if _, e := rand.Read(entry.Seed[:]); e != nil {
		return PublicKey{}, ErrWallet
	}
	if _, e := d.Put(entry); e != nil {
		return PublicKey{}, e
	}
	return public(entry), nil
}
func (d *Disk) Save(password []byte) error {
	if !d.loaded {
		return ErrWallet
	}
	status, e := d.Status()
	if e != nil {
		return e
	}
	if status.Pending || status.UnpublishedCandidate {
		return ErrPending
	}
	raw, e := Seal(password, d.entries)
	if e != nil {
		return e
	}
	defer clear(raw)
	if e = d.commit(raw, true, d.base); e != nil {
		return e
	}
	d.base = sha256.Sum256(raw)
	return nil
}
func (d *Disk) commit(raw []byte, oldExists bool, oldHash [32]byte) error {
	if d.check() != nil {
		return ErrWallet
	}
	s, e := d.Status()
	if e != nil {
		return e
	}
	if s.Pending || s.UnpublishedCandidate {
		return ErrPending
	}
	old, exists, hash, e := d.current()
	clear(old)
	if e != nil {
		return e
	}
	if exists != oldExists || hash != oldHash {
		return ErrWallet
	}
	if _, e = DecodeHeader(raw); e != nil {
		return e
	}
	i := commitIntent{Schema: 1, OldExists: oldExists, Old: oldHash, New: sha256.Sum256(raw)}
	if e = d.files.WriteNew(nextFile, raw); e != nil {
		return ErrWallet
	}
	intent, e := json.Marshal(i)
	if e != nil {
		return ErrWallet
	}
	defer clear(intent)
	if e = d.files.WriteNew(intentFile, intent); e != nil {
		return ErrPending
	}
	if e = d.apply(i); e != nil {
		return ErrPending
	}
	return nil
}
func (d *Disk) apply(i commitIntent) error {
	if d.check() != nil {
		return ErrWallet
	}
	raw, exists, hash, e := d.current()
	clear(raw)
	if e != nil {
		return e
	}
	candidate, next, e := d.read(nextFile, MaxFileBytes)
	defer clear(candidate)
	if e != nil {
		return e
	}
	if next && (sha256.Sum256(candidate) != i.New || len(candidate) < HeaderSize) {
		return ErrWallet
	}
	if !exists || hash != i.New {
		if exists != i.OldExists || hash != i.Old || !next {
			return ErrWallet
		}
		if _, e = DecodeHeader(candidate); e != nil {
			return e
		}
		if d.check() != nil || d.files.Rename(nextFile, walletFile) != nil {
			return ErrWallet
		}
	} else if next {
		if d.files.Remove(nextFile) != nil {
			return ErrWallet
		}
	}
	if d.files.Sync() != nil {
		return ErrWallet
	}
	installed, ok, h, e := d.current()
	clear(installed)
	if e != nil || !ok || h != i.New {
		return ErrWallet
	}
	if d.files.Remove(intentFile) != nil || d.files.Sync() != nil {
		return ErrWallet
	}
	return nil
}

// Recover continues the exact staged ciphertext; it never reencrypts, generates
// keys, changes an accepted goal, or treats a post-rename failure as rollback.
func (d *Disk) Recover(abort bool) error {
	if d.check() != nil {
		return ErrWallet
	}
	Clear(d.entries)
	d.entries = nil
	d.loaded = false
	i, pending, e := d.intent()
	if e != nil {
		return e
	}
	if !pending {
		raw, next, e := d.read(nextFile, MaxFileBytes)
		defer clear(raw)
		if e != nil {
			return e
		}
		if !next {
			return nil
		}
		if !abort {
			return ErrPending
		}
		if _, e = DecodeHeader(raw); e != nil {
			return e
		}
		if d.files.Remove(nextFile) != nil || d.files.Sync() != nil {
			return ErrPending
		}
		return nil
	}
	if !abort {
		if d.apply(i) != nil {
			return ErrPending
		}
		return nil
	}
	raw, exists, hash, e := d.current()
	clear(raw)
	if e != nil {
		return e
	}
	if exists && hash == i.New {
		return ErrPublished
	}
	if exists != i.OldExists || hash != i.Old {
		return ErrWallet
	}
	candidate, next, e := d.read(nextFile, MaxFileBytes)
	defer clear(candidate)
	if e != nil {
		return e
	}
	if next {
		if sha256.Sum256(candidate) != i.New {
			return ErrWallet
		}
		if d.files.Remove(nextFile) != nil {
			return ErrPending
		}
	}
	if d.files.Remove(intentFile) != nil || d.files.Sync() != nil {
		return ErrPending
	}
	return nil
}

// ReadBack decrypts the actual installed wallet again under the same lock. It
// must be used before a session migration replaces a legacy plaintext seed.
func (d *Disk) ReadBack(name string, password []byte) (Entry, error) {
	if err := d.Unlock(password); err != nil {
		return Entry{}, err
	}
	return d.Get(name)
}
