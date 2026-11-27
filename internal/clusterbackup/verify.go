// SPDX-License-Identifier: Apache-2.0

package clusterbackup

import (
	"crypto/sha256"
	"io"

	"github.com/jay94ks/seafield/internal/cluster"
)

// Verify reads a whole backup file with key and checks everything it can
// without a running cluster: the file decrypts to its authenticated end, the
// voter's signature, the snapshot's binding, digest and strict decoding, and
// the master key's commitment. It returns the manifest.
func Verify(r io.Reader, key Key) (Manifest, error) {
	c, snapshot, err := Open(r, key)
	if err != nil {
		return Manifest{}, err
	}
	defer clear(c.Master)
	m := c.Manifest
	if VerifySignature(m, c.Signature) != nil || MasterCheck(m.Cluster, c.Master) != m.MasterCheck {
		return Manifest{}, ErrBackup
	}
	h := sha256.New()
	point, _, err := cluster.ReadSnapshot(m.Cluster, io.TeeReader(snapshot, h))
	if err != nil {
		return Manifest{}, ErrBackup
	}
	// Drain to the authenticated end: trailing bytes or a cut file fail here.
	if _, err := io.Copy(h, snapshot); err != nil {
		return Manifest{}, ErrBackup
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if digest != m.SnapshotDigest || point.RaftIndex != m.RaftIndex || point.Term != m.Term || point.Index != m.Index || point.StateDigest != m.StateDigest {
		return Manifest{}, ErrBackup
	}
	return m, nil
}
