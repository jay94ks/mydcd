// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/config"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/storage"
)

// Policy is a cluster's fixed policy as a cluster backup carries it.
type Policy struct {
	Cluster, Admin, TrustRoot [32]byte
	Genesis                   config.Peer
}

// PrepareRestore writes the local intent of `sfcd restore` (design B4): this
// new server takes over policy.Cluster as its only voter. Like PrepareInit it
// needs an empty state root, creates the identity when the directory is
// empty, and resumes an interrupted restore of the same request.
func PrepareRestore(c config.Node, policy Policy, operation string) (Record, error) {
	if checkManaged(c) != nil || policy.Cluster == ([32]byte{}) || policy.Admin == ([32]byte{}) || policy.TrustRoot == ([32]byte{}) || !lifecycle.ValidID(operation) {
		return Record{}, ErrInstallation
	}
	if c.Common.Cluster != "" && c.Common.Cluster != hex.EncodeToString(policy.Cluster[:]) || c.Common.Admin != "" && c.Common.Admin != hex.EncodeToString(policy.Admin[:]) {
		return Record{}, ErrInstallation
	}
	if info, err := os.Lstat(c.Node.StateDir); err == nil && !private(info, true) {
		return Record{}, ErrInstallation
	} else if err != nil && !os.IsNotExist(err) {
		return Record{}, err
	}
	lock, err := storage.LockRoot(c.Node.StateDir)
	if err != nil {
		return Record{}, err
	}
	defer lock.Close()
	if _, err = os.Lstat(filepath.Join(c.Node.StateDir, filename)); err == nil {
		r, err := Read(c)
		if err != nil || r.Root.Intent != lifecycle.RestoreIntent || r.Root.Operation != operation || r.Root.Cluster != policy.Cluster || r.Admin != policy.Admin || r.Genesis != policy.Genesis {
			return Record{}, ErrInstallation
		}
		return r, nil
	} else if !os.IsNotExist(err) {
		return Record{}, err
	}
	if err = emptyRoot(c); err != nil {
		return Record{}, errors.New("state root contains existing data; restore needs a new server")
	}
	var self *identity.Identity
	entries, err := os.ReadDir(c.Node.IdentityDir)
	if os.IsNotExist(err) || err == nil && len(entries) == 0 {
		self, err = identity.Create(c.Node.IdentityDir)
	} else if err == nil {
		self, err = identity.Load(c.Node.IdentityDir)
	}
	if err != nil {
		return Record{}, err
	}
	defer clear(self.Private)
	prepared, err := lifecycle.Prepare(lifecycle.RestoreIntent, policy.Cluster, policy.TrustRoot, lifecycle.Member{ID: c.Node.ID, Key: self.Public, Voter: true}, operation)
	if err != nil {
		return Record{}, err
	}
	r := Record{Schema: 1, Root: prepared, Admin: policy.Admin, Endpoint: c.Node.Listen, Genesis: policy.Genesis}
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	if err = write(c.Node.StateDir, r); err != nil {
		return Record{}, err
	}
	for _, path := range []string{filepath.Dir(c.Node.StateDir), filepath.Dir(c.Node.IdentityDir)} {
		if err = syncDirectory(path); err != nil {
			return Record{}, err
		}
	}
	return r, nil
}
