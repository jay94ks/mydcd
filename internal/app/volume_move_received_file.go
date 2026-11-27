// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/hex"
	"errors"
	"os"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func moveRestoreConsumer(b moveReceiveIntent) string {
	d := b.Job.Digest()
	return "move-restore/" + hex.EncodeToString(d[:])
}

// The same exclusive file-worker lock joins receiver/restore before cleanup.
// A failed native callback keeps this exact durable A3 pin through restart.
func (m *backupArtifacts) withReceivedMoveFile(ctx context.Context, b moveReceiveIntent, backend moveReceiveBackend, read func(*os.File) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || read == nil {
		return errBackupArtifact
	}
	if err := backend.Authorize(ctx, b, false); err != nil {
		return err
	}
	key := moveReceiveKey(b)
	row, err := m.journal.Read(key)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.Checkpoint == nil {
		return errors.Join(errBackupArtifact, err)
	}
	original, err := m.receiveBinding(key, row.State.Applied)
	if err != nil || original.digest() != b.digest() {
		return errBackupArtifact
	}
	sink, err := m.openReceive(ctx, b, row.Checkpoint.Data, backend)
	if err != nil {
		return err
	}
	defer sink.dir.Close()
	defer sink.file.Close()
	if err = sink.Finish(ctx); err != nil {
		return err
	}
	if _, err = m.journal.Borrow(key, moveRestoreConsumer(b), 1); err != nil {
		return err
	}
	if err = read(sink.file); err != nil {
		return err
	}
	return backend.Authorize(ctx, b, false)
}

func (m *backupArtifacts) returnReceivedMoveFile(b moveReceiveIntent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || b.Job.Binding.Scope.Cluster != m.cluster || b.Job.Binding.Target.Key != m.node {
		return errBackupArtifact
	}
	key := moveReceiveKey(b)
	row, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	pin, ok := row.Consumers[moveRestoreConsumer(b)]
	if !ok {
		return nil
	}
	if pin.Generation != 1 {
		return reconcile.ErrLease
	}
	return m.journal.Return(key, moveRestoreConsumer(b), pin)
}
