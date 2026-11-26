// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"syscall"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func restoreArtifactConsumer(b control.VolumeRestoreBinding) string {
	d := b.Digest()
	return "restore/" + hex.EncodeToString(d[:])
}
func restoreArtifactKey(b control.VolumeRestoreBinding) string {
	return "backup/" + hex.EncodeToString(b.BackupBinding[:])
}

// The shared restore holds the artifact in the FSM; this exact A3 consumer
// also holds its original local materialization through uncertainty/restart.
// The callback owns no asynchronous child: all file reads finish before return.
func (m *backupArtifacts) withRestoreFile(ctx context.Context, b control.VolumeRestoreBinding, read func(*os.File) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || b.Target.NodeKey != m.node || b.Target.Scope.Cluster != m.cluster || read == nil {
		return errBackupArtifact
	}
	key := restoreArtifactKey(b)
	r, err := m.journal.Read(key)
	if err != nil || r.State.Pending != nil || !r.State.Applied.Present {
		return errBackupArtifact
	}
	original, err := m.binding(key, r.State.Applied)
	if err != nil || original.Digest() != b.BackupBinding || original.Scope != b.Backup.Scope || original.ID != b.Backup.ID || original.Compatibility != b.Compatibility {
		return errBackupArtifact
	}
	if err = m.syncCompletion(ctx, original); err != nil {
		return err
	}
	completion, err := m.completion(ctx, original, false)
	if err != nil || completion.Receipt != b.Receipt {
		return errors.Join(errBackupArtifact, err)
	}
	if _, err = m.journal.Borrow(key, restoreArtifactConsumer(b), 1); err != nil {
		return err
	}
	dir, err := m.directory(original)
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := dir.OpenFile("archive.tar", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	// Errors retain the durable original A3 reference. Only successful target
	// verification/explicit original cleanup may call returnRestoreArtifact.
	err = read(f)
	return errors.Join(err, f.Close())
}
func (m *backupArtifacts) returnRestoreArtifact(b control.VolumeRestoreBinding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || b.Target.Scope.Cluster != m.cluster || b.Target.NodeKey != m.node {
		return errBackupArtifact
	}
	r, err := m.journal.Read(restoreArtifactKey(b))
	if err != nil {
		return err
	}
	pin, ok := r.Consumers[restoreArtifactConsumer(b)]
	if !ok {
		return nil
	}
	if pin.Generation != 1 {
		return reconcile.ErrLease
	}
	return m.journal.Return(restoreArtifactKey(b), restoreArtifactConsumer(b), pin)
}
