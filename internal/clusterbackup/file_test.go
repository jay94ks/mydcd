// SPDX-License-Identifier: Apache-2.0

package clusterbackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/jay94ks/seafield/internal/config"
)

func testContents(t *testing.T, size uint64) (Contents, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var voter [32]byte
	copy(voter[:], pub)
	master := bytes.Repeat([]byte{7}, 32)
	m := Manifest{Schema: 1, Cluster: [32]byte{1}, Version: "0.1.0", Operation: "backup-1", User: "admin", CreatedAt: 5,
		RaftIndex: 10, Term: 2, Index: 4, SnapshotSize: size, SnapshotDigest: [32]byte{2}, StateDigest: [32]byte{3},
		Members: []Member{{ID: "node-0", Key: voter, Voter: true}}, Voter: "node-0", VoterKey: voter, MasterCheck: MasterCheck([32]byte{1}, master),
		Admin: [32]byte{4}, TrustRoot: voter, Genesis: config.Peer{ID: "node-0", Key: "aa", Endpoint: "127.0.0.1:7000", Voter: true}}
	sig, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	return Contents{Manifest: m, Signature: sig, Master: master}, priv
}

func roundTrip(t *testing.T, key Key, c Contents, snapshot []byte) []byte {
	t.Helper()
	var file bytes.Buffer
	if err := Write(&file, key, c, bytes.NewReader(snapshot)); err != nil {
		t.Fatal(err)
	}
	got, r, err := Open(bytes.NewReader(file.Bytes()), key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(body, snapshot) || !bytes.Equal(got.Master, c.Master) || VerifySignature(got.Manifest, got.Signature) != nil {
		t.Fatalf("round trip: %v", err)
	}
	return file.Bytes()
}

// Every snapshot size round-trips, including ones that end exactly on a
// chunk boundary.
func TestFileRoundTripsAcrossChunkBoundaries(t *testing.T) {
	key, _ := KeyFromFile(bytes.Repeat([]byte{9}, 32))
	c, _ := testContents(t, 1)
	raw, _ := c.Manifest.encode()
	prefix := 8 + len(raw) + 64 + 32
	for _, size := range []int{1, 100, chunkSize - prefix, chunkSize - prefix + 1, 2*chunkSize - prefix, 3*chunkSize + 17} {
		c, _ := testContents(t, uint64(size))
		snapshot := make([]byte, size)
		_, _ = rand.Read(snapshot)
		roundTrip(t, key, c, snapshot)
	}
}

func TestFileRejectsWrongKeyDamageAndTruncation(t *testing.T) {
	key, _ := KeyFromFile([]byte("0909090909090909090909090909090909090909090909090909090909090909\n"))
	c, _ := testContents(t, 3*chunkSize)
	snapshot := bytes.Repeat([]byte{5}, 3*chunkSize)
	file := roundTrip(t, key, c, snapshot)
	read := func(b []byte, k Key) error {
		_, r, err := Open(bytes.NewReader(b), k)
		if err != nil {
			return err
		}
		_, err = io.ReadAll(r)
		return err
	}
	other, _ := KeyFromFile(bytes.Repeat([]byte{8}, 32))
	password, _ := KeyFromPassword([]byte("correct horse"))
	damaged := bytes.Clone(file)
	damaged[len(damaged)/2] ^= 1
	header := bytes.Clone(file)
	header[20] ^= 1
	for name, err := range map[string]error{
		"other key":      read(file, other),
		"password key":   read(file, password),
		"damaged body":   read(damaged, key),
		"damaged header": read(header, key),
		"cut chunk":      read(file[:len(file)-1], key),
		"dropped chunk":  read(file[:len(file)-(4+16+chunkSize)], key),
		"trailing bytes": read(append(bytes.Clone(file), 0), key),
		"empty file":     read(nil, key),
		"header only":    read(file[:headerSize], key),
	} {
		if !errors.Is(err, ErrBackup) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPasswordKeyRoundTrips(t *testing.T) {
	key, err := KeyFromPassword([]byte("correct horse battery"))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := testContents(t, 10)
	file := roundTrip(t, key, c, bytes.Repeat([]byte{1}, 10))
	wrong, _ := KeyFromPassword([]byte("correct horse battery!"))
	if _, _, err := Open(bytes.NewReader(file), wrong); !errors.Is(err, ErrBackup) {
		t.Fatal(err)
	}
	if _, err := KeyFromPassword([]byte("short")); err == nil {
		t.Fatal("short password accepted")
	}
}

func TestManifestSignatureCoversEveryField(t *testing.T) {
	c, _ := testContents(t, 10)
	m := c.Manifest
	m.RaftIndex++
	if VerifySignature(m, c.Signature) == nil {
		t.Fatal("changed manifest verified")
	}
	m = c.Manifest
	m.Admin[0]++
	if VerifySignature(m, c.Signature) == nil {
		t.Fatal("changed administrator key verified")
	}
	m = c.Manifest
	m.Voter = "node-1"
	if m.Valid() {
		t.Fatal("manifest whose signer is not a listed voter is valid")
	}
}

func TestSealedMasterOpensOnlyForItsRecipientAndOperation(t *testing.T) {
	r, _ := NewRecipient()
	other, _ := NewRecipient()
	master := bytes.Repeat([]byte{4}, 32)
	s, err := SealMaster(r.Public(), [32]byte{1}, "backup-1", master)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Open([32]byte{1}, "backup-1", s); err != nil || !bytes.Equal(got, master) {
		t.Fatal(err)
	}
	for name, open := range map[string]func() ([]byte, error){
		"other recipient": func() ([]byte, error) { return other.Open([32]byte{1}, "backup-1", s) },
		"other operation": func() ([]byte, error) { return r.Open([32]byte{1}, "backup-2", s) },
		"other cluster":   func() ([]byte, error) { return r.Open([32]byte{2}, "backup-1", s) },
	} {
		if _, err := open(); err == nil {
			t.Fatal(name, "opened")
		}
	}
}
