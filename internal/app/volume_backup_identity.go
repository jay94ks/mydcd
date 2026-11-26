// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/schema"
)

type backupDirectoryIdentity struct {
	Schema        uint8
	Binding       [32]byte
	Device, Inode uint64
}

func validateBackupDirectoryCheckpoint(b control.VolumeBackupBinding, c *reconcile.EffectCheckpoint) error {
	if c == nil || c.Operation != 1 || !c.Target.Present || c.Target.Generation != 1 {
		return errBackupArtifact
	}
	identity, err := schema.Decode[backupDirectoryIdentity](c.Data)
	if err != nil || identity.Schema != 1 || identity.Binding != b.Digest() || identity.Inode == 0 {
		return errBackupArtifact
	}
	raw, _ := json.Marshal(b)
	if c.Target.Spec != string(raw) {
		return errBackupArtifact
	}
	return nil
}
func sameBackupDirectory(info os.FileInfo, identity backupDirectoryIdentity) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && backupPrivate(info, true) && uint64(stat.Dev) == identity.Device && stat.Ino == identity.Inode
}
func (m *backupArtifacts) captureDirectoryIdentity(b control.VolumeBackupBinding, dir *os.Root) ([]byte, error) {
	before, err := m.root.Lstat(backupArtifactName(b))
	if err != nil || !backupPrivate(before, true) {
		return nil, errBackupArtifact
	}
	current, err := dir.Stat(".")
	if err != nil || !os.SameFile(before, current) {
		return nil, errBackupArtifact
	}
	stat, ok := current.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return nil, errBackupArtifact
	}
	return json.Marshal(backupDirectoryIdentity{Schema: 1, Binding: b.Digest(), Device: uint64(stat.Dev), Inode: stat.Ino})
}
func (m *backupArtifacts) checkDirectoryIdentity(b control.VolumeBackupBinding, proof []byte) error {
	identity, err := schema.Decode[backupDirectoryIdentity](proof)
	if err != nil || identity.Schema != 1 || identity.Binding != b.Digest() || identity.Inode == 0 {
		return errBackupArtifact
	}
	info, err := m.root.Lstat(backupArtifactName(b))
	if err != nil {
		return err
	}
	if !sameBackupDirectory(info, identity) {
		return errBackupArtifact
	}
	return nil
}

// Only the original persisted inode can authorize cleanup of partial metadata.
// A valid original intent is handled by normal cleanup. No archive/data or
// unknown file can be removed through this incomplete-intent path.
func (m *backupArtifacts) removeIncompleteIntent(b control.VolumeBackupBinding, proof []byte) error {
	if err := m.checkDirectoryIdentity(b, proof); err != nil {
		return err
	}
	dir, err := m.root.OpenRoot(backupArtifactName(b))
	if err != nil {
		return err
	}
	defer dir.Close()
	before, err := m.root.Lstat(backupArtifactName(b))
	if err != nil {
		return err
	}
	after, err := dir.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return errBackupArtifact
	}
	file, err := dir.Open(".")
	if err != nil {
		return err
	}
	names, err := file.Readdirnames(2)
	_ = file.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > 1 || len(names) == 1 && names[0] != "intent.json" {
		return errBackupArtifact
	}
	if len(names) == 1 {
		expected, _ := json.Marshal(b)
		partial, err := backupRead(dir, "intent.json", int64(len(expected)))
		if err != nil || len(partial) >= len(expected) || !bytes.HasPrefix(expected, partial) {
			return errBackupArtifact
		}
		if err = dir.Remove("intent.json"); err != nil {
			return err
		}
	}
	if err = m.syncDirectory(dir); err != nil {
		return err
	}
	if err = m.checkDirectoryIdentity(b, proof); err != nil {
		return err
	}
	if err = m.root.Remove(backupArtifactName(b)); err != nil {
		return err
	}
	return m.syncDirectory(m.root)
}
