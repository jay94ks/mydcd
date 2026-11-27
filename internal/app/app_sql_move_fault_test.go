// SPDX-License-Identifier: Apache-2.0

package app

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The product publishes immutable progress records by tmp->rename. A live
// observer can see no published file yet, or race that replacement between
// backupRead's lstat/open identity checks. Neither is a stable corrupt record.
// The paused-process check below still requires a valid exact original record.
func observeSQLReceiveProgress(directory *os.Root, intent moveReceiveIntent, read func(*os.Root, string, int64) ([]byte, error)) (moveReceiveProgress, bool, error) {
	before, err := directory.Lstat("progress.json")
	if os.IsNotExist(err) {
		return moveReceiveProgress{}, false, nil
	}
	if err != nil {
		return moveReceiveProgress{}, false, err
	}
	if !backupPrivate(before, false) || before.Size() > 4096 {
		return moveReceiveProgress{}, false, errBackupArtifact
	}
	raw, readErr := read(directory, "progress.json", 4096)
	if readErr != nil {
		after, afterErr := directory.Lstat("progress.json")
		if errors.Is(readErr, errBackupArtifact) || os.IsNotExist(readErr) {
			if os.IsNotExist(afterErr) || afterErr == nil && !os.SameFile(before, after) && backupPrivate(after, false) {
				return moveReceiveProgress{}, false, nil
			}
		}
		return moveReceiveProgress{}, false, readErr
	}
	p, err := schema.Decode[moveReceiveProgress](raw)
	if err != nil || p.Schema != 1 || p.Binding != intent.digest() {
		return moveReceiveProgress{}, false, errors.Join(errBackupArtifact, err)
	}
	return p, true, nil
}

func sqlMoveArtifactPath(t *testing.T, nodeConfig string) string {
	t.Helper()
	cfg, err := loadTestNode(nodeConfig)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(cfg.Node.StateDir, "workload", "backups")
}

// The receiver is the original product daemon, not a replacement transport or
// store. Freeze all its threads before recording the cut, then inspect its DB
// only after the original process handle has been killed and waited for.
func cutSQLReverseReceive(t *testing.T, a *Runtime, nodeConfig string, selection control.VolumeMoveSelection, read func() cluster.View, observeB func(string) (ModuleObservation, error), wait func(string, func() bool), cutB func(func()), startB func()) *moveProcessCutEvidence {
	t.Helper()
	path := sqlMoveArtifactPath(t, nodeConfig)
	evidence := &moveProcessCutEvidence{}
	original := func() (moveReceiveIntent, volumes.Consumer, bool) {
		t.Helper()
		registry, err := a.controlPolicy.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		job, move, found := registry.Move(selection)
		if !found {
			t.Fatal("original SQL reverse move missing")
		}
		if move.Phase != volumes.Copying {
			if move.Verified != nil || move.CommitRevision != 0 || move.Activated != nil || move.Phase == volumes.Cancelled {
				t.Fatal("SQL receive cut missed its non-final transfer precondition", move.Phase)
			}
			return moveReceiveIntent{}, volumes.Consumer{}, false
		}
		core, exists := registry.Volume(job.Binding.Scope)
		if !exists {
			t.Fatal("SQL receive original Volume missing")
		}
		reader, held := core.MoveReader(job.Binding)
		if !held || move.Manifest == nil || move.Verified != nil || move.CommitRevision != 0 || move.ReaderClosed != nil {
			t.Fatal("SQL receive cut requires original Copying manifest/reader and uncommitted owner")
		}
		return moveReceiveIntent{Schema: 1, Job: job, Manifest: *move.Manifest}, reader, true
	}
	progress := func(intent moveReceiveIntent) (moveReceiveProgress, bool) {
		t.Helper()
		directory, err := os.OpenRoot(filepath.Join(path, moveReceiveName(intent)))
		if os.IsNotExist(err) {
			return moveReceiveProgress{}, false
		}
		if err != nil {
			t.Fatal(err)
		}
		p, published, readErr := observeSQLReceiveProgress(directory, intent, backupRead)
		closeErr := directory.Close()
		if closeErr != nil {
			t.Fatal(closeErr)
		}
		if readErr != nil {
			t.Fatal("SQL receiver original progress binding", readErr)
		}
		return p, published && p.Offset > 0 && p.Offset < intent.Manifest.Bytes && p.Offset%sfcp.VolumeChunkSize == 0
	}
	var observed moveReceiveIntent
	var nextDiagnostic time.Time
	lastDiagnostic := ""
	wait("actual SQL reverse receiver has a non-final original durable offset", func() bool {
		intent, _, copying := original()
		// Do not insert a management round trip in the non-final transfer
		// window where the original receiver must be cut. Diagnose pre-copy
		// preparation only; it does not advance or replace the accepted move.
		if !copying && time.Now().After(nextDiagnostic) {
			now := time.Now()
			nextDiagnostic = now.Add(2 * time.Second)
			// The app's Ingress is intentionally absent during retirement. Its
			// borrowed management bridge survives and exposes the same worker
			// diagnostics without mistaking that absence for a native failure.
			o, err := observeB("control/network-sources/bridge/tenant/app-services/node-b")
			diagnostic := o.ModuleError + "; volume: " + o.VolumeError
			if err != nil {
				diagnostic = "original target observation: " + err.Error()
			}
			if (err != nil || o.ModuleError != "" || o.VolumeError != "") && diagnostic != lastDiagnostic {
				lastDiagnostic = diagnostic
				t.Log("original SQL reverse target waiting", selection.ID, diagnostic)
			}
		}
		if !copying {
			return false
		}
		_, partial := progress(intent)
		if partial {
			observed = intent
		}
		return partial
	})
	cutB(func() {
		intent, reader, copying := original()
		if !copying || intent.digest() != observed.digest() {
			t.Fatal("SQL daemon advanced past the original receive before SIGSTOP")
		}
		p, partial := progress(intent)
		if !partial {
			t.Fatal("SQL SIGSTOP missed non-final durable receive offset")
		}
		evidence.checkpoint = moveProcessCutCheckpoint{Schema: 1, Intent: intent, Progress: p}
		evidence.reader = reader
	})
	inspectMoveProcessCutRecord(t, path, evidence, true)
	startB()
	t.Log("original SQL reverse daemon SIGSTOP -> original Copying reader/non-final offset -> SIGKILL/Wait -> same Apply1/checkpoint/inode/prefix with at most one unacknowledged chunk -> same config/DB/key daemon restart")
	return evidence
}

// Called after app down and positive DNS closure, with the daemon stopped.
// This shares the fixture's final shutdown instead of adding another restart.
func inspectSQLReverseReceiveTerminal(t *testing.T, nodeConfig string, evidence *moveProcessCutEvidence) {
	t.Helper()
	if evidence == nil || evidence.operation != 1 {
		t.Fatal("original SQL process-cut operation evidence required")
	}
	path := sqlMoveArtifactPath(t, nodeConfig)
	journal, err := reconcile.OpenJournal(filepath.Join(path, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	row, readErr := journal.Read(moveReceiveKey(evidence.checkpoint.Intent))
	closeErr := journal.Close()
	if readErr != nil || closeErr != nil || row.State.Pending != nil || row.State.LastID != evidence.operation+1 || row.State.GenerationFloor != 1 || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 || row.Checkpoint != nil {
		t.Fatal("SQL process recovery lost original terminal receive Apply1/Remove2 or retained pins", readErr, closeErr)
	}
	if _, err := os.Lstat(filepath.Join(path, moveReceiveName(evidence.checkpoint.Intent))); !os.IsNotExist(err) {
		t.Fatal("SQL completed reverse receive directory remains or cannot be observed", err)
	}
}
