// SPDX-License-Identifier: Apache-2.0

package bootstrap

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/membership"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

// PrepareJoin loads the existing target key and persists its original approved
// Join. It never creates a new cluster/key or replaces another installation.
func PrepareJoin(c config.Node, inv membership.Invitation, cluster, source [32]byte) (Record, error) {
	if checkManaged(c) != nil || inv.Verify(cluster, source) != nil || c.Node.ID != inv.Target.ID || c.Node.Listen != inv.Target.Endpoint || c.Common.Cluster != "" && c.Common.Cluster != hex.EncodeToString(cluster[:]) || c.Common.Admin != "" && c.Common.Admin != hex.EncodeToString(inv.Admin[:]) {
		return Record{}, ErrInstallation
	}
	self, err := identity.Load(c.Node.IdentityDir)
	if err != nil {
		return Record{}, err
	}
	defer clear(self.Private)
	if self.Actor() != inv.Target.Key {
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
		if err != nil || r.Root.Intent != lifecycle.Join || r.Join == nil {
			return Record{}, ErrInstallation
		}
		old, _ := r.Join.Encode()
		want, _ := inv.Encode()
		if string(old) != string(want) {
			return Record{}, ErrInstallation
		}
		return r, nil
	} else if !os.IsNotExist(err) {
		return Record{}, err
	}
	if err = emptyRoot(c); err != nil {
		return Record{}, err
	}
	prepared, err := lifecycle.Prepare(lifecycle.Join, cluster, mustKey(inv.Genesis.Key), lifecycle.Member{ID: c.Node.ID, Key: self.Public}, inv.JoinID)
	if err != nil {
		return Record{}, err
	}
	r := Record{Schema: 1, Root: prepared, Admin: inv.Admin, Endpoint: c.Node.Listen, Genesis: inv.Genesis, Join: &inv}
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	if err = write(c.Node.StateDir, r); err != nil {
		return Record{}, err
	}
	if err = syncDirectory(filepath.Dir(c.Node.StateDir)); err != nil {
		return Record{}, err
	}
	return r, nil
}
func mustKey(text string) [32]byte { key, _ := identity.ParseKey(text); return key }

// PrepareAck persists the ORIGINAL proof before its first send. Reopening a
// newer local prefix returns that same ACK, never another signed request body.
// The runtime's state-root lock must be held, as for Install.
func PrepareAck(c config.Node) (Record, error) {
	r, err := Read(c)
	if err != nil {
		return r, err
	}
	if r.Join == nil || r.Root.Installed.Index == 0 {
		return r, ErrInstallation
	}
	if r.Ack != nil {
		return r, nil
	}
	self, err := identity.Load(c.Node.IdentityDir)
	if err != nil {
		return r, err
	}
	defer clear(self.Private)
	ack := membership.Ack{Schema: 1, Cluster: r.Root.Cluster, Node: r.Root.Self.ID, JoinID: r.Root.Operation, Key: self.Public, ConfigurationIndex: r.Root.Installed.Index, AppliedIndex: r.Root.AppliedIndex}
	ack.Signature = ed25519.Sign(self.Private, membership.AckBytes(ack))
	r.Ack = &ack
	r.Signature = ed25519.Sign(self.Private, signingBytes(r))
	err = write(c.Node.StateDir, r)
	return r, err
}
