// SPDX-License-Identifier: Apache-2.0

package clusterbackup

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// kdfSealed is MDBK kdf 3: each file has its own random data key, sealed to
// one or more long-lived X25519 recipients (the cluster key and the
// administrator key, devel/proposals/backup-storage.md 3). The sealed keys
// follow the fixed header and are part of every chunk's AAD, so a swapped
// or removed recipient fails decryption.
const kdfSealed = 3

const (
	maxSealedKeys = 8
	maxSealedBox  = 64
)

// RecipientFromSeed derives a long-lived recipient key from a secret seed,
// such as the cluster key from the cluster master key. label separates uses.
func RecipientFromSeed(seed []byte, label string) (Recipient, error) {
	if len(seed) < 32 || label == "" {
		return Recipient{}, ErrBackup
	}
	raw, err := hkdf.Key(sha256.New, seed, nil, "sfc-recipient-1\x00"+label, 32)
	if err != nil {
		return Recipient{}, err
	}
	defer clear(raw)
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return Recipient{}, ErrBackup
	}
	return Recipient{k}, nil
}

// SealedTo names what a sealed file's data key is bound to: the cluster and
// a context string (for example "volume-archive/<id>"). The same pair must
// be given to open it.
type SealedTo struct {
	Cluster [32]byte
	Context string
}

func (s SealedTo) valid() bool { return s.Context != "" && len(s.Context) <= 1024 }

func encodeSealedKeys(keys []SealedMaster) ([]byte, bool) {
	if len(keys) == 0 || len(keys) > maxSealedKeys {
		return nil, false
	}
	b := []byte{byte(len(keys))}
	for _, k := range keys {
		if len(k.Box) == 0 || len(k.Box) > maxSealedBox {
			return nil, false
		}
		b = append(b, k.Ephemeral[:]...)
		b = append(b, byte(len(k.Box)))
		b = append(b, k.Box...)
	}
	return b, true
}

// readSealedHead reads the fixed header and the sealed keys; head is every
// byte read, the AAD prefix of each chunk.
func readSealedHead(br *bufio.Reader) (header, []byte, []SealedMaster, error) {
	head := make([]byte, headerSize, headerSize+1+maxSealedKeys*(33+maxSealedBox))
	if _, err := io.ReadFull(br, head); err != nil {
		return header{}, nil, nil, ErrBackup
	}
	h, err := decodeHeader(head)
	if err != nil || h.kdf != kdfSealed {
		return header{}, nil, nil, ErrBackup
	}
	count, err := br.ReadByte()
	if err != nil || count == 0 || count > maxSealedKeys {
		return header{}, nil, nil, ErrBackup
	}
	head = append(head, count)
	keys := make([]SealedMaster, 0, count)
	for range count {
		var eph [33]byte
		if _, err := io.ReadFull(br, eph[:]); err != nil {
			return header{}, nil, nil, ErrBackup
		}
		n := int(eph[32])
		if n == 0 || n > maxSealedBox {
			return header{}, nil, nil, ErrBackup
		}
		box := make([]byte, n)
		if _, err := io.ReadFull(br, box); err != nil {
			return header{}, nil, nil, ErrBackup
		}
		var k SealedMaster
		copy(k.Ephemeral[:], eph[:32])
		k.Box = box
		keys = append(keys, k)
		head = append(head, eph[:]...)
		head = append(head, box...)
	}
	return h, head, keys, nil
}

func dataAEAD(dataKey []byte, h header) (cipher.AEAD, error) {
	if len(dataKey) != 32 {
		return nil, ErrBackup
	}
	key, err := hkdf.Key(sha256.New, dataKey, h.salt[:], "sfc-sealed-data-1", 32)
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

// WriteSealed starts an MDBK kdf 3 file on w: a fresh data key sealed to
// every recipient for to. The plaintext written to the returned writer is
// encrypted in 64 KiB chunks; Close writes the final chunk. Only the
// recipients' public keys are needed, so any node can write one.
func WriteSealed(w io.Writer, recipients [][32]byte, to SealedTo) (io.WriteCloser, error) {
	out, key, err := WriteSealedKey(w, recipients, to)
	clear(key)
	return out, err
}

// WriteSealedKey is WriteSealed that also returns the file's data key, so the
// writer can read its own file back once before forgetting the key. The
// caller clears it.
func WriteSealedKey(w io.Writer, recipients [][32]byte, to SealedTo) (io.WriteCloser, []byte, error) {
	if !to.valid() || len(recipients) == 0 || len(recipients) > maxSealedKeys {
		return nil, nil, ErrBackup
	}
	dataKey := make([]byte, 32)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, nil, err
	}
	out, err := writeSealed(w, recipients, to, dataKey)
	if err != nil {
		clear(dataKey)
		return nil, nil, err
	}
	return out, dataKey, nil
}

func writeSealed(w io.Writer, recipients [][32]byte, to SealedTo, dataKey []byte) (io.WriteCloser, error) {
	keys := make([]SealedMaster, 0, len(recipients))
	for _, r := range recipients {
		k, err := SealMaster(r, to.Cluster, to.Context, dataKey)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	encoded, ok := encodeSealedKeys(keys)
	if !ok {
		return nil, ErrBackup
	}
	h := header{kdf: kdfSealed}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(h.nonce[:]); err != nil {
		return nil, err
	}
	aead, err := dataAEAD(dataKey, h)
	if err != nil {
		return nil, err
	}
	head := append(h.encode(), encoded...)
	if _, err := w.Write(head); err != nil {
		return nil, err
	}
	return &encryptor{w: w, aead: aead, h: h, head: head, buf: make([]byte, 0, chunkSize)}, nil
}

// SealedKeys reads only the sealed data keys of a kdf 3 file, so the key can
// be unsealed elsewhere (a voter holds the cluster key) before OpenSealed.
func SealedKeys(r io.Reader) ([]SealedMaster, error) {
	_, _, keys, err := readSealedHead(bufio.NewReader(r))
	return keys, err
}

// UnsealDataKey opens the data key sealed to r among keys.
func (r Recipient) UnsealDataKey(to SealedTo, keys []SealedMaster) ([]byte, error) {
	if !to.valid() {
		return nil, ErrBackup
	}
	for _, k := range keys {
		if key, err := r.Open(to.Cluster, to.Context, k); err == nil {
			return key, nil
		}
	}
	return nil, ErrBackup
}

// OpenSealed decrypts a kdf 3 file with its unsealed data key. The returned
// reader yields the plaintext and returns io.EOF only after the
// authenticated last chunk and the end of r.
func OpenSealed(r io.Reader, dataKey []byte) (io.Reader, error) {
	br := bufio.NewReader(r)
	h, head, _, err := readSealedHead(br)
	if err != nil {
		return nil, err
	}
	aead, err := dataAEAD(dataKey, h)
	if err != nil {
		return nil, err
	}
	return &decryptor{r: br, aead: aead, h: h, head: bytes.Clone(head)}, nil
}
