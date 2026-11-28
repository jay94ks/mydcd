// SPDX-License-Identifier: Apache-2.0

// Package clusterbackup is the cluster backup file: one FSM snapshot and the
// cluster master key, encrypted as a whole with a key the administrator keeps
// (devel/design/cluster-backup-and-recovery.md B1). The backup key is only
// ever used here, in the CLI; servers never see it.
package clusterbackup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrBackup is every failure to read a backup file: a wrong key, a damaged
// or truncated file, or a format this build does not know.
var ErrBackup = errors.New("invalid cluster backup file")

const (
	magic       = "MDBK"
	headerSize  = 4 + 4 + 1 + 16 + 4 + 4 + 1 + 8
	chunkSize   = 64 << 10
	kdfKeyFile  = 1
	kdfPassword = 2

	// Password KDF cost, the same as the wallet's.
	argonMemoryKiB  = 64 << 10
	argonIterations = 3
	argonThreads    = 4
)

// Key is the administrator's backup key: a 32-byte key file or a password.
type Key struct {
	kind   uint8
	secret []byte
}

// KeyFromFile reads a key file: 32 raw bytes, or 64 hex digits with an
// optional trailing newline.
func KeyFromFile(raw []byte) (Key, error) {
	if len(raw) == 32 {
		return Key{kind: kdfKeyFile, secret: bytes.Clone(raw)}, nil
	}
	text := strings.TrimRight(string(raw), "\r\n")
	if len(text) == 64 {
		if b, err := hex.DecodeString(text); err == nil {
			return Key{kind: kdfKeyFile, secret: b}, nil
		}
	}
	return Key{}, errors.New("backup key file must hold 32 bytes or 64 hex digits")
}

// Recipient derives the long-lived recipient key of label from a key
// file's secret (RecipientFromSeed). Password keys have none.
func (k Key) Recipient(label string) (Recipient, error) {
	if k.kind != kdfKeyFile {
		return Recipient{}, ErrBackup
	}
	return RecipientFromSeed(k.secret, label)
}

// NewKeyFile makes a fresh key file's content (64 hex digits and a newline).
func NewKeyFile() ([]byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b[:]) + "\n"), nil
}

// KeyFromPassword derives the key from a password with Argon2id.
func KeyFromPassword(password []byte) (Key, error) {
	if len(password) < 8 || len(password) > 1024 {
		return Key{}, errors.New("backup password must be 8 to 1024 bytes")
	}
	return Key{kind: kdfPassword, secret: bytes.Clone(password)}, nil
}

// Clear wipes the key from memory.
func (k Key) Clear() { clear(k.secret) }

type header struct {
	kdf     uint8
	salt    [16]byte
	memory  uint32
	iter    uint32
	threads uint8
	nonce   [8]byte
}

func (h header) encode() []byte {
	b := make([]byte, 0, headerSize)
	b = append(b, magic...)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = append(b, h.kdf)
	b = append(b, h.salt[:]...)
	b = binary.LittleEndian.AppendUint32(b, h.memory)
	b = binary.LittleEndian.AppendUint32(b, h.iter)
	b = append(b, h.threads)
	return append(b, h.nonce[:]...)
}

func decodeHeader(b []byte) (header, error) {
	var h header
	if len(b) != headerSize || string(b[:4]) != magic || binary.LittleEndian.Uint32(b[4:8]) != 1 {
		return h, ErrBackup
	}
	h.kdf = b[8]
	copy(h.salt[:], b[9:25])
	h.memory = binary.LittleEndian.Uint32(b[25:29])
	h.iter = binary.LittleEndian.Uint32(b[29:33])
	h.threads = b[33]
	copy(h.nonce[:], b[34:42])
	switch h.kdf {
	case kdfKeyFile, kdfSealed:
		if h.memory != 0 || h.iter != 0 || h.threads != 0 {
			return h, ErrBackup
		}
	case kdfPassword:
		if h.memory != argonMemoryKiB || h.iter != argonIterations || h.threads != argonThreads {
			return h, ErrBackup
		}
	default:
		return h, ErrBackup
	}
	return h, nil
}

func (k Key) aead(h header) (cipher.AEAD, error) {
	if k.kind != h.kdf || len(k.secret) == 0 {
		return nil, ErrBackup
	}
	var secret []byte
	if k.kind == kdfPassword {
		secret = argon2.IDKey(k.secret, h.salt[:], h.iter, h.memory, h.threads, 32)
	} else {
		secret = bytes.Clone(k.secret)
	}
	defer clear(secret)
	key, err := hkdf.Key(sha256.New, secret, h.salt[:], "sfc-cluster-backup-1", 32)
	if err != nil {
		return nil, ErrBackup
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrBackup
	}
	return cipher.NewGCM(block)
}

func nonceFor(h header, counter uint32) []byte {
	n := make([]byte, 12)
	copy(n, h.nonce[:])
	binary.LittleEndian.PutUint32(n[8:], counter)
	return n
}

func chunkAAD(head []byte, counter uint32, last bool) []byte {
	aad := binary.LittleEndian.AppendUint32(bytes.Clone(head), counter)
	if last {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// encryptor encrypts the plaintext stream in chunks; the last chunk is
// marked, so a cut file never decrypts as a whole one.
type encryptor struct {
	w       io.Writer
	aead    cipher.AEAD
	h       header
	head    []byte
	buf     []byte
	counter uint32
}

func (e *encryptor) Write(p []byte) (int, error) {
	n := 0
	for len(p) > 0 {
		// A full chunk is flushed only once more data follows, so Close
		// can mark the final one.
		if len(e.buf) == chunkSize {
			if err := e.flush(false); err != nil {
				return n, err
			}
		}
		take := min(chunkSize-len(e.buf), len(p))
		e.buf = append(e.buf, p[:take]...)
		p, n = p[take:], n+take
	}
	return n, nil
}

func (e *encryptor) flush(last bool) error {
	if e.counter == ^uint32(0) {
		return ErrBackup
	}
	sealed := e.aead.Seal(nil, nonceFor(e.h, e.counter), e.buf, chunkAAD(e.head, e.counter, last))
	clear(e.buf)
	e.buf = e.buf[:0]
	e.counter++
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(sealed)))
	if _, err := e.w.Write(size[:]); err != nil {
		return err
	}
	_, err := e.w.Write(sealed)
	return err
}

func (e *encryptor) Close() error { return e.flush(true) }

type decryptor struct {
	r       *bufio.Reader
	aead    cipher.AEAD
	h       header
	head    []byte
	plain   []byte
	counter uint32
	done    bool
}

func (d *decryptor) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.done {
			return 0, io.EOF
		}
		var size [4]byte
		if _, err := io.ReadFull(d.r, size[:]); err != nil {
			return 0, ErrBackup
		}
		n := binary.LittleEndian.Uint32(size[:])
		if n < 16 || n > chunkSize+16 {
			return 0, ErrBackup
		}
		sealed := make([]byte, n)
		if _, err := io.ReadFull(d.r, sealed); err != nil {
			return 0, ErrBackup
		}
		nonce := nonceFor(d.h, d.counter)
		plain, err := d.aead.Open(nil, nonce, sealed, chunkAAD(d.head, d.counter, false))
		if err != nil {
			plain, err = d.aead.Open(nil, nonce, sealed, chunkAAD(d.head, d.counter, true))
			if err != nil {
				return 0, ErrBackup
			}
			d.done = true
			if _, e := d.r.ReadByte(); e != io.EOF {
				return 0, ErrBackup
			}
		} else if len(plain) != chunkSize {
			return 0, ErrBackup
		}
		d.counter++
		d.plain = plain
	}
	n := copy(p, d.plain)
	clear(d.plain[:n])
	d.plain = d.plain[n:]
	return n, nil
}

// Contents is what a backup file holds, besides the snapshot itself.
type Contents struct {
	Manifest  Manifest
	Signature []byte
	Master    []byte
}

const plainMagic = "MDBP"

// Write encrypts one backup to w: the signed manifest, the master key and
// the MDS1 snapshot read from snapshot (exactly Manifest.SnapshotSize bytes).
func Write(w io.Writer, key Key, c Contents, snapshot io.Reader) error {
	raw, err := c.Manifest.encode()
	if err != nil || len(c.Signature) != 64 || len(c.Master) != 32 {
		return ErrBackup
	}
	h := header{kdf: key.kind}
	if key.kind == kdfPassword {
		h.memory, h.iter, h.threads = argonMemoryKiB, argonIterations, argonThreads
	}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return err
	}
	if _, err := rand.Read(h.nonce[:]); err != nil {
		return err
	}
	aead, err := key.aead(h)
	if err != nil {
		return err
	}
	head := h.encode()
	if _, err := w.Write(head); err != nil {
		return err
	}
	e := &encryptor{w: w, aead: aead, h: h, head: head, buf: make([]byte, 0, chunkSize)}
	defer clear(e.buf[:cap(e.buf)])
	prefix := append([]byte(plainMagic), binary.LittleEndian.AppendUint32(nil, uint32(len(raw)))...)
	for _, part := range [][]byte{prefix, raw, c.Signature, c.Master} {
		if _, err := e.Write(part); err != nil {
			return err
		}
	}
	n, err := io.Copy(e, snapshot)
	if err != nil {
		return err
	}
	if uint64(n) != c.Manifest.SnapshotSize {
		return ErrBackup
	}
	return e.Close()
}

// Open decrypts a backup's head. The returned reader yields the MDS1
// snapshot and returns io.EOF only after the authenticated end of the file.
// Open checks the manifest's shape, not its signature: Verify does that.
func Open(r io.Reader, key Key) (Contents, io.Reader, error) {
	br := bufio.NewReader(r)
	head := make([]byte, headerSize)
	if _, err := io.ReadFull(br, head); err != nil {
		return Contents{}, nil, ErrBackup
	}
	h, err := decodeHeader(head)
	if err != nil {
		return Contents{}, nil, err
	}
	aead, err := key.aead(h)
	if err != nil {
		return Contents{}, nil, err
	}
	d := &decryptor{r: br, aead: aead, h: h, head: head}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(d, prefix); err != nil || string(prefix[:4]) != plainMagic {
		return Contents{}, nil, ErrBackup
	}
	size := binary.LittleEndian.Uint32(prefix[4:])
	if size == 0 || size > maxManifest {
		return Contents{}, nil, ErrBackup
	}
	raw := make([]byte, size)
	sig := make([]byte, 64)
	master := make([]byte, 32)
	for _, part := range [][]byte{raw, sig, master} {
		if _, err := io.ReadFull(d, part); err != nil {
			return Contents{}, nil, ErrBackup
		}
	}
	m, err := decodeManifest(raw)
	if err != nil {
		clear(master)
		return Contents{}, nil, err
	}
	return Contents{Manifest: m, Signature: sig, Master: master}, &exact{r: d, left: m.SnapshotSize}, nil
}

// exact yields exactly left bytes, then requires the stream's end.
type exact struct {
	r    io.Reader
	left uint64
}

func (e *exact) Read(p []byte) (int, error) {
	if e.left == 0 {
		var one [1]byte
		if n, err := e.r.Read(one[:]); n != 0 || err != io.EOF {
			return 0, ErrBackup
		}
		return 0, io.EOF
	}
	if uint64(len(p)) > e.left {
		p = p[:e.left]
	}
	n, err := e.r.Read(p)
	e.left -= uint64(n)
	if err == io.EOF {
		return n, ErrBackup
	}
	return n, err
}
