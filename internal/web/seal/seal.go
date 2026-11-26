// SPDX-License-Identifier: Apache-2.0

// Package seal keeps mydc-web secrets (AI API keys, DNS provider tokens,
// ACME account keys, the auto-response account key, webhook secrets) in
// sealed files: one AES-256-GCM file per secret under <data-dir>/secrets,
// encrypted with the seal key the container receives at start
// (MYDC_WEB_SEAL_KEY, usually a Docker secret). Secrets never go to bbolt.
//
// Without a key, or with a key that does not open the existing files, the
// box is unavailable: callers turn the features that need it off and show
// the reason. There is no plaintext fallback.
package seal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// KeySize is the seal key length in bytes.
const KeySize = 32

// State says whether the box can be used.
type State string

const (
	StateReady    State = "ready"     // key present and it opens the files
	StateNoKey    State = "no-key"    // MYDC_WEB_SEAL_KEY not given
	StateWrongKey State = "wrong-key" // key does not open the existing files
	StateBroken   State = "broken"    // folder unreadable or a file damaged
)

var (
	// ErrUnavailable is returned by every call on a box that is not ready.
	ErrUnavailable = errors.New("seal: sealed storage is not available")
	// ErrNotFound is returned when no secret has the name.
	ErrNotFound = errors.New("seal: secret not found")
	// ErrReady is returned by Reset on a box that works: resetting would
	// throw away secrets that can still be read.
	ErrReady = errors.New("seal: sealed storage works; reset is only for a lost key")
	// ErrName is returned for a name outside the allowed grammar.
	ErrName = errors.New("seal: invalid secret name")
)

// File format (schema 1):
//
//	magic "mydc-web-seal\x00" | version 1 | key id (8) | nonce (12) | ciphertext
//
// The additional data is the header plus the secret name, so a file copied
// to another name does not open. The key id is the first 8 bytes of
// SHA-256("mydc-web-seal-key-1\x00" || key) and tells a wrong key from a
// damaged file.
const (
	magic     = "mydc-web-seal\x00"
	version   = 1
	idLen     = 8
	headerLen = len(magic) + 1 + idLen
	checkName = "_check"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`)

// ValidName reports whether name is a valid secret name: lowercase letters,
// digits, '.', '-', at most 128 characters, starting with a letter or digit
// (for example "ai-claude", "dns-cf1", "acme-le.account").
func ValidName(name string) bool { return nameRE.MatchString(name) && !strings.Contains(name, "..") }

// Box is the sealed file store.
type Box struct {
	dir    string
	state  State
	reason string
	keyID  [idLen]byte // key new files are written with
	aead   cipher.AEAD
	old    map[[idLen]byte]cipher.AEAD // keys still accepted for reading (during a key change)
	key    []byte                      // the write key, kept for Reset
	given  [idLen]byte                 // ID of MYDC_WEB_SEAL_KEY
	nextID [idLen]byte                 // ID of MYDC_WEB_SEAL_KEY_NEXT (zero: none)
	mu     sync.RWMutex                // guards the key state; writes take it exclusively
}

// ParseKey reads a seal key: 64 hex characters or standard/URL base64 of 32
// bytes. Surrounding white space (a trailing newline in a secret file) is
// ignored.
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	if len(s) == 2*KeySize {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := enc.DecodeString(s); err == nil && len(k) == KeySize {
			return k, nil
		}
	}
	return nil, fmt.Errorf("seal key must be %d bytes as hex or base64", KeySize)
}

// Open opens the sealed folder dir with key. A nil or empty key gives a box
// in state no-key. Open fails only for a key of the wrong size; every other
// problem gives a box that is not ready, with the reason in Status.
//
// On first use with a key, Open creates dir (0700) and a check file, so a
// later start with another key is reported as wrong-key instead of each
// secret failing on its own.
func Open(dir string, key []byte) (*Box, error) { return OpenRekey(dir, key, nil) }

// OpenRekey opens dir with key and, when next is set, seals every file
// again with next (MYDC_WEB_SEAL_KEY_NEXT). Files already sealed with next
// are left as they are, so a key change cut short by a crash finishes on the
// next start with the same two keys. After it the box writes with next, and
// the operator replaces MYDC_WEB_SEAL_KEY with next.
func OpenRekey(dir string, key, next []byte) (*Box, error) {
	b := &Box{dir: dir}
	if len(key) == 0 {
		b.state, b.reason = StateNoKey, "MYDC_WEB_SEAL_KEY is not set"
		return b, nil
	}
	cur, curID, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	b.aead, b.keyID, b.key, b.given = cur, curID, append([]byte(nil), key...), curID
	if len(next) > 0 {
		na, nid, err := newAEAD(next)
		if err != nil {
			return nil, fmt.Errorf("next %w", err)
		}
		b.nextID = nid
		if nid != curID {
			// read with both keys while files are being sealed again
			b.old = map[[idLen]byte]cipher.AEAD{curID: cur}
			b.aead, b.keyID, b.key = na, nid, append([]byte(nil), next...)
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		b.state, b.reason = StateBroken, err.Error()
		return b, nil
	}
	_ = os.Chmod(dir, 0o700)
	b.state = StateReady
	switch _, err := b.get(checkName); {
	case errors.Is(err, ErrNotFound):
		if err := b.put(checkName, []byte(checkValue)); err != nil {
			b.state, b.reason = StateBroken, err.Error()
		}
	case err != nil:
		var we *wrongKeyError
		if errors.As(err, &we) {
			b.state, b.reason = StateWrongKey, "MYDC_WEB_SEAL_KEY does not match the key the sealed files were written with"
		} else {
			b.state, b.reason = StateBroken, err.Error()
		}
	}
	if b.state == StateReady && b.old != nil {
		if err := b.rekey(); err != nil {
			b.state, b.reason = StateBroken, "key change: "+err.Error()
		}
		b.old = nil
	}
	if b.state != StateReady {
		b.aead = nil
	}
	return b, nil
}

const checkValue = "mydc-web-seal-check-1"

func newAEAD(key []byte) (cipher.AEAD, [idLen]byte, error) {
	var id [idLen]byte
	if len(key) != KeySize {
		return nil, id, fmt.Errorf("seal key must be %d bytes", KeySize)
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, id, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, id, err
	}
	h := sha256.Sum256(append([]byte("mydc-web-seal-key-1\x00"), key...))
	copy(id[:], h[:idLen])
	return a, id, nil
}

// rekey seals every file not yet under the write key again, the check file
// last.
func (b *Box) rekey() error {
	names, err := b.list()
	if err != nil {
		return err
	}
	for _, n := range append(names, checkName) {
		raw, err := os.ReadFile(b.path(n))
		if err != nil {
			return err
		}
		if len(raw) >= headerLen && bytes.Equal(raw[len(magic)+1:headerLen], b.keyID[:]) {
			continue
		}
		v, err := b.get(n)
		if err != nil {
			return err
		}
		if err := b.put(n, v); err != nil {
			return err
		}
	}
	return nil
}

// Reset deletes every sealed file and starts over with the key the box was
// opened with. It is the way out when the old key is lost (state wrong-key
// or broken): the secrets cannot be recovered and must be entered again. A
// box without a key cannot be reset, and a ready box is refused (ErrReady).
func (b *Box) Reset() error {
	if b == nil || len(b.key) == 0 {
		return ErrUnavailable
	}
	a, id, err := newAEAD(b.key)
	if err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == StateReady {
		return ErrReady
	}
	ents, err := os.ReadDir(b.dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, e := range ents {
		if e.Type().IsRegular() {
			if err := os.Remove(filepath.Join(b.dir, e.Name())); err != nil {
				return err
			}
		}
	}
	if err := os.MkdirAll(b.dir, 0o700); err != nil {
		return err
	}
	b.aead, b.keyID, b.old = a, id, nil
	if err := b.put(checkName, []byte(checkValue)); err != nil {
		b.state, b.reason, b.aead = StateBroken, err.Error(), nil
		return err
	}
	b.state, b.reason = StateReady, ""
	return nil
}

// Entry describes a stored secret without its value.
type Entry struct {
	Name     string
	Kind     string // the part before the first '-' or '.' ("ai", "dns", "acme")
	Modified time.Time
}

// Entries lists stored secrets with their kind and modification time.
func (b *Box) Entries() ([]Entry, error) {
	if b == nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	names, err := b.list()
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		fi, err := os.Stat(b.path(n))
		if err != nil {
			continue
		}
		kind := n
		if i := strings.IndexAny(n, "-."); i > 0 {
			kind = n[:i]
		}
		out = append(out, Entry{Name: n, Kind: kind, Modified: fi.ModTime()})
	}
	return out, nil
}

// KeyInfo describes the box for the settings screen. Fingerprints are the
// key IDs every sealed file already carries in its header (a hash of the
// key), shortened to "abcd…wxyz"; they never reveal the key.
type KeyInfo struct {
	Dir  string
	Key  string // MYDC_WEB_SEAL_KEY (empty without a key)
	Next string // MYDC_WEB_SEAL_KEY_NEXT (empty without one)
}

func fingerprint(id [idLen]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:4] + "…" + h[len(h)-4:]
}

// Keys returns the folder and key fingerprints.
func (b *Box) Keys() KeyInfo {
	if b == nil {
		return KeyInfo{}
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	k := KeyInfo{Dir: b.dir}
	if b.state != StateNoKey {
		k.Key = fingerprint(b.given)
	}
	if b.nextID != ([idLen]byte{}) {
		k.Next = fingerprint(b.nextID)
	}
	return k
}

// Status returns the box state and, when not ready, why.
func (b *Box) Status() (State, string) {
	if b == nil {
		return StateNoKey, "sealed storage is not configured"
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.state, b.reason
}

// Ready reports whether the box can be used.
func (b *Box) Ready() bool {
	if b == nil {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ready()
}

func (b *Box) ready() bool { return b.state == StateReady }

// Put stores value under name, replacing any previous value. The write is
// atomic: a crash leaves either the old or the new file.
func (b *Box) Put(name string, value []byte) error {
	if b == nil {
		return ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready() {
		return ErrUnavailable
	}
	if !ValidName(name) {
		return ErrName
	}
	return b.put(name, value)
}

// Get returns the value stored under name.
func (b *Box) Get(name string) ([]byte, error) {
	if b == nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.ready() {
		return nil, ErrUnavailable
	}
	if !ValidName(name) {
		return nil, ErrName
	}
	return b.get(name)
}

// Delete removes the secret. Deleting a missing secret is not an error.
func (b *Box) Delete(name string) error {
	if b == nil {
		return ErrUnavailable
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.ready() {
		return ErrUnavailable
	}
	if !ValidName(name) {
		return ErrName
	}
	err := os.Remove(b.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		err = syncDir(b.dir)
	}
	return err
}

// List returns the stored secret names, sorted. Values are not read.
func (b *Box) List() ([]string, error) {
	if b == nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.list()
}

func (b *Box) list() ([]string, error) {
	if !b.ready() {
		return nil, ErrUnavailable
	}
	ents, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.Type().IsRegular() && ValidName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (b *Box) path(name string) string { return filepath.Join(b.dir, name) }

func (b *Box) header() []byte {
	h := make([]byte, 0, headerLen)
	h = append(h, magic...)
	h = append(h, version)
	return append(h, b.keyID[:]...)
}

func aad(header []byte, name string) []byte {
	return append(append(append([]byte(nil), header...), 0), name...)
}

func (b *Box) put(name string, value []byte) error {
	hdr := b.header()
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := append(append(hdr, nonce...), b.aead.Seal(nil, nonce, value, aad(hdr, name))...)

	f, err := os.CreateTemp(b.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(out); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path(name)); err != nil {
		return err
	}
	return syncDir(b.dir)
}

type wrongKeyError struct{ name string }

func (e *wrongKeyError) Error() string { return "seal: " + e.name + " was sealed with another key" }

func (b *Box) get(name string) ([]byte, error) {
	raw, err := os.ReadFile(b.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	ns := b.aead.NonceSize()
	if len(raw) < headerLen+ns+b.aead.Overhead() || !bytes.HasPrefix(raw, []byte(magic)) {
		return nil, fmt.Errorf("seal: %s is not a sealed file", name)
	}
	if raw[len(magic)] != version {
		return nil, fmt.Errorf("seal: %s has unsupported version %d", name, raw[len(magic)])
	}
	hdr := raw[:headerLen]
	var id [idLen]byte
	copy(id[:], hdr[len(magic)+1:])
	a := b.aead
	if id != b.keyID {
		if a = b.old[id]; a == nil {
			return nil, &wrongKeyError{name}
		}
	}
	nonce := raw[headerLen : headerLen+ns]
	v, err := a.Open(nil, nonce, raw[headerLen+ns:], aad(hdr, name))
	if err != nil {
		return nil, fmt.Errorf("seal: %s is damaged or was renamed", name)
	}
	return v, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Hint returns the last four characters of a secret for display ("…abcd"),
// or "" when it is too short to show any part safely.
func Hint(value []byte) string {
	if len(value) < 12 {
		return ""
	}
	return "…" + string(value[len(value)-4:])
}

// SealBlob encrypts value for storage outside the sealed folder (e.g. a
// web data backup written to a volume) with the write key. purpose is
// bound as associated data, so a blob opens only for the same purpose.
func (b *Box) SealBlob(purpose string, value []byte) ([]byte, error) {
	if b == nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.ready() {
		return nil, ErrUnavailable
	}
	hdr := b.header()
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(append(hdr, nonce...), b.aead.Seal(nil, nonce, value, aad(hdr, "blob:"+purpose))...), nil
}

// OpenBlob decrypts a SealBlob result. A blob sealed with a key this box
// no longer holds fails with "was sealed with another key".
func (b *Box) OpenBlob(purpose string, raw []byte) ([]byte, error) {
	if b == nil {
		return nil, ErrUnavailable
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if !b.ready() {
		return nil, ErrUnavailable
	}
	ns := b.aead.NonceSize()
	if len(raw) < headerLen+ns+b.aead.Overhead() || !bytes.HasPrefix(raw, []byte(magic)) || raw[len(magic)] != version {
		return nil, errors.New("seal: not a sealed blob")
	}
	hdr := raw[:headerLen]
	var id [idLen]byte
	copy(id[:], hdr[len(magic)+1:])
	a := b.aead
	if id != b.keyID {
		if a = b.old[id]; a == nil {
			return nil, &wrongKeyError{"the blob"}
		}
	}
	v, err := a.Open(nil, raw[headerLen:headerLen+ns], raw[headerLen+ns:], aad(hdr, "blob:"+purpose))
	if err != nil {
		return nil, errors.New("seal: the blob is damaged or is not for " + purpose)
	}
	return v, nil
}
