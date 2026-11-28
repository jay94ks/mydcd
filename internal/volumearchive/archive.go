// SPDX-License-Identifier: Apache-2.0

// Package volumearchive describes a Volume archive package: a taken-down
// app's Volume as one file, data.mdbk = tar (volumes.WriteArchive) →
// optional zstd → MDBK kdf 3 sealed to the cluster key and the
// administrator key, plus a signed manifest written last
// (devel/proposals/volume-archive-packages.md 4). This package holds the
// manifest and names, which the control state checks; package pack writes
// and reads the file.
package volumearchive

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"regexp"

	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// ErrPackage is every failure to read or check a package: wrong key,
// damaged or truncated data, a manifest that does not match, or a format
// this build does not know.
var ErrPackage = errors.New("invalid volume archive package")

// Compression is how the tar stream is stored inside the sealed file.
type Compression string

const (
	Zstd Compression = "zstd" // the default (Jay 2026-11-28 09:38 KST)
	None Compression = "none"
)

// Valid reports whether c is a known compression.
func (c Compression) Valid() bool { return c == Zstd || c == None }

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidID reports whether id can name an archive (and its directory).
func ValidID(id string) bool { return idPattern.MatchString(id) }

// AdminKeyLabel derives the administrator's recipient key from a key file
// (sfcli cluster backup keygen); set-volume-archive-admin-key sends its
// public half.
const AdminKeyLabel = "volume-archive-admin"

// Context is the sealing context of archive id: its data key opens only for
// this archive in this cluster.
func Context(id string) string { return "volume-archive/" + id }

// Manifest describes one package. It holds no file names or data.
type Manifest struct {
	Schema      uint8
	ID          string
	Scope       volumes.Scope
	Compression Compression
	Tar         volumes.ArchiveReceipt
	DataBytes   uint64   // size of data.mdbk
	DataDigest  [32]byte // SHA-256 of data.mdbk
	Node        [32]byte // the node that wrote it
	At          int64
	Signature   []byte `json:",omitempty"`
}

// ManifestBytes is what the writing node signs.
func ManifestBytes(m Manifest) []byte {
	m.Signature = nil
	raw, _ := json.Marshal(m)
	return append([]byte("sfc-volume-archive-manifest-1\x00"), raw...)
}

// Sign signs m with the writing node's key.
func Sign(m Manifest, key ed25519.PrivateKey) Manifest {
	m.Signature = ed25519.Sign(key, ManifestBytes(m))
	return m
}

// Check validates m's shape and its signature by m.Node.
func (m Manifest) Check(o volumes.ArchiveOptions) error {
	if m.Schema != 1 || !ValidID(m.ID) || !m.Compression.Valid() || m.Tar.Validate(o) != nil || m.DataBytes == 0 || m.DataDigest == ([32]byte{}) || m.At <= 0 || len(m.Signature) != ed25519.SignatureSize {
		return ErrPackage
	}
	if !ed25519.Verify(ed25519.PublicKey(m.Node[:]), ManifestBytes(m), m.Signature) {
		return ErrPackage
	}
	return nil
}
