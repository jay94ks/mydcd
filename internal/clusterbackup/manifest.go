// SPDX-License-Identifier: Apache-2.0

package clusterbackup

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/config"
)

const maxManifest = 64 << 10

// Member is one cluster member as the backed-up state lists it.
type Member struct {
	ID    string
	Key   [32]byte
	Voter bool
}

// Manifest describes one backup. The voter that made it signs it.
type Manifest struct {
	Schema    uint8
	Cluster   [32]byte
	Version   string // sfcd build that made it (major.minor.build)
	Operation string // the recorded cluster-backup operation
	User      string // the administrator who asked
	CreatedAt int64  // Unix seconds, the voter's clock

	RaftIndex, Term, Index uint64 // where the snapshot stands
	SnapshotSize           uint64
	SnapshotDigest         [32]byte // SHA-256 of the whole MDS1 snapshot
	StateDigest            [32]byte // the MDS1 header's state digest

	Members  []Member
	Voter    string   // member that made the backup
	VoterKey [32]byte // its identity key, which signs the manifest

	// MasterCheck commits to the master key without revealing it.
	MasterCheck [32]byte

	// The cluster's fixed policy, which `sfcd restore` needs to rebuild a
	// server from this file: the bootstrap administrator key, the trust root
	// that binds every stored record, and the original genesis server.
	Admin, TrustRoot [32]byte
	Genesis          config.Peer
}

// Valid checks the manifest's own shape.
func (m Manifest) Valid() bool {
	if m.Schema != 1 || m.Cluster == ([32]byte{}) || !text(m.Version, 64) || !text(m.Operation, 64) || !text(m.User, 128) || m.CreatedAt <= 0 || m.RaftIndex == 0 || m.Index == 0 || m.SnapshotSize == 0 || m.SnapshotDigest == ([32]byte{}) || m.StateDigest == ([32]byte{}) || len(m.Members) == 0 || len(m.Members) > 512 || !text(m.Voter, 128) || m.VoterKey == ([32]byte{}) || m.MasterCheck == ([32]byte{}) || m.Admin == ([32]byte{}) || m.TrustRoot == ([32]byte{}) || !text(m.Genesis.ID, 128) || !text(m.Genesis.Key, 128) || !text(m.Genesis.Endpoint, 255) || !m.Genesis.Voter {
		return false
	}
	seen := map[string]bool{}
	voter := false
	for _, e := range m.Members {
		if !text(e.ID, 128) || e.Key == ([32]byte{}) || seen[e.ID] {
			return false
		}
		seen[e.ID] = true
		if e.ID == m.Voter {
			voter = e.Voter && e.Key == m.VoterKey
		}
	}
	return voter
}

func text(s string, max int) bool { return s != "" && len(s) <= max && utf8.ValidString(s) }

func (m Manifest) encode() ([]byte, error) {
	if !m.Valid() {
		return nil, ErrBackup
	}
	raw, err := json.Marshal(m)
	if err != nil || len(raw) > maxManifest {
		return nil, ErrBackup
	}
	return raw, nil
}

func decodeManifest(raw []byte) (Manifest, error) {
	var m Manifest
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || d.More() || !m.Valid() {
		return Manifest{}, ErrBackup
	}
	if again, err := json.Marshal(m); err != nil || !bytes.Equal(again, raw) {
		return Manifest{}, ErrBackup
	}
	return m, nil
}

// SigningBytes is what the voter signs for m.
func SigningBytes(m Manifest) ([]byte, error) {
	raw, err := m.encode()
	if err != nil {
		return nil, err
	}
	return append([]byte("sfc-cluster-backup-manifest-1\x00"), raw...), nil
}

// Sign signs m with the voter's identity key.
func Sign(m Manifest, private ed25519.PrivateKey) ([]byte, error) {
	b, err := SigningBytes(m)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(private.Public().(ed25519.PublicKey), m.VoterKey[:]) {
		return nil, ErrBackup
	}
	return ed25519.Sign(private, b), nil
}

// VerifySignature checks the voter's signature on m.
func VerifySignature(m Manifest, signature []byte) error {
	b, err := SigningBytes(m)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(m.VoterKey[:], b, signature) {
		return ErrBackup
	}
	return nil
}

// MasterCheck is the manifest's commitment to a master key.
func MasterCheck(cluster [32]byte, master []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("sfc-cluster-backup-master-1\x00"))
	h.Write(cluster[:])
	h.Write(master)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
