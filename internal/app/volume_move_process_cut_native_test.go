// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/workload/volumes"
	"github.com/moby/moby/client"
	"gopkg.in/yaml.v3"
)

type moveProcessCutCheckpoint struct {
	Schema   uint8
	Intent   moveReceiveIntent
	Progress moveReceiveProgress
}

type moveProcessCutEvidence struct {
	checkpoint moveProcessCutCheckpoint
	reader     volumes.Consumer
	operation  uint64
}

func moveProcessCutData() []byte {
	data := make([]byte, 2*sfcp.VolumeChunkSize+4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	return data
}

func seedMoveProcessCutData(t *testing.T, root *os.Root, uid, gid uint32) {
	t.Helper()
	file, err := root.OpenFile("process-cut-data", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	data := moveProcessCutData()
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Chown(int(uid), int(gid))
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	directory, openErr := root.Open(".")
	if openErr == nil {
		err = errors.Join(err, directory.Sync(), directory.Close())
	}
	if err = errors.Join(err, openErr); err != nil {
		t.Fatal("owned bounded process-cut input", err)
	}
}

// These files coordinate only this owned child. They are never consumed as
// control/native proof; the parent also inspects the actual DB and inode.
func writeMoveCrashJSON(file string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file+".tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err = os.Rename(file+".tmp", file); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(file))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func TestManagedVolumeMoveProcessCutWorker(t *testing.T) {
	file, directory := os.Getenv("SFC_MOVE_CRASH_CONFIG"), os.Getenv("SFC_MOVE_CRASH_DIRECTORY")
	if file == "" && directory == "" {
		t.Skip("owned receive process-cut parent required")
	}
	if !filepath.IsAbs(file) || !filepath.IsAbs(directory) {
		t.Fatal("absolute original worker inputs required")
	}
	cfg, err := loadTestNode(file)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "job.json"))
	if err != nil {
		t.Fatal(err)
	}
	job, err := schema.Decode[control.VolumeMove](raw)
	if err != nil || job.Verify() != nil {
		t.Fatal("original signed move required", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	runtime, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	if runtime.Identity.Public != job.Binding.Target.Key || runtime.backupArtifacts == nil {
		t.Fatal("worker must reopen original target native Runtime")
	}
	failures := make(chan error, 1)
	fail := func(err error) error {
		select {
		case failures <- err:
		default:
		}
		return err
	}
	store := runtime.backupArtifacts
	store.mu.Lock()
	syncFile := store.syncFile
	paused := false
	store.syncFile = func(file *os.File) error {
		if err := syncFile(file); err != nil {
			return fail(err)
		}
		name := filepath.Clean(file.Name())
		if paused || !bytes.HasPrefix([]byte(filepath.Base(name)), []byte("receive-")) {
			return nil
		}
		info, err := file.Stat()
		if err != nil {
			return fail(err)
		}
		if !info.IsDir() {
			return nil
		}
		dir, err := os.OpenRoot(name)
		if err != nil {
			return fail(err)
		}
		defer dir.Close()
		raw, err := backupRead(dir, "progress.json", 4096)
		if err != nil {
			return fail(err)
		}
		progress, err := schema.Decode[moveReceiveProgress](raw)
		if err != nil {
			return fail(err)
		}
		if progress.Offset == 0 {
			return nil
		}
		raw, err = backupRead(dir, "intent.json", 256<<10)
		if err != nil {
			return fail(err)
		}
		intent, err := schema.Decode[moveReceiveIntent](raw)
		if err != nil || intent.Job.Digest() != job.Digest() || progress.Binding != intent.digest() || progress.Offset != sfcp.VolumeChunkSize || progress.Offset >= intent.Manifest.Bytes {
			return fail(errors.New("first durable non-final original chunk required"))
		}
		paused = true
		if err = writeMoveCrashJSON(filepath.Join(directory, "checkpoint.json"), moveProcessCutCheckpoint{Schema: 1, Intent: intent, Progress: progress}); err != nil {
			return fail(err)
		}
		// saveReceiveProgress has synced data/progress/this directory. Do not
		// return to Put, which is the boundary before the offset ACK is sent.
		<-ctx.Done()
		return ctx.Err()
	}
	store.mu.Unlock()
	if _, err = runtime.InstallConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	if err = writeMoveCrashJSON(filepath.Join(directory, "ready.json"), struct{ Schema uint8 }{1}); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastError, diagnostics := "", 0
	for {
		select {
		case err := <-failures:
			t.Fatal("original receive worker", err)
		case <-ticker.C:
			runtime.mu.RLock()
			current := runtime.volumeBackupError
			runtime.mu.RUnlock()
			if current != nil && current.Error() != lastError && diagnostics < 16 {
				lastError = current.Error()
				diagnostics++
				t.Log("original receive phase", current)
			}
		case <-ctx.Done():
			t.Fatal("owned worker was not killed at its durable checkpoint", ctx.Err())
		}
	}
}

func runMoveReceiverProcessCut(t *testing.T, ctx context.Context, target *Runtime, root string, job control.VolumeMove, p control.Policy, read func() cluster.View, approve func(control.UserOperation), wait func(string, func() bool), controls managedMoveNativeControls) (*Runtime, *moveProcessCutEvidence) {
	t.Helper()
	if controls.reopenTarget == nil || target.backupArtifacts == nil {
		t.Fatal("original target DB/key and source-managed reopen required")
	}
	directory := filepath.Join(root, "receiver-process-cut")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(directory, "node.yaml")
	// Module.Body retains the actual module YAML; serializing Module as an
	// ordinary Go struct would introduce an unsupported "body" wrapper.
	originalConfig := target.installation.config
	var document yaml.Node
	err := document.Encode(originalConfig)
	if err != nil {
		t.Fatal(err)
	}
	mapping := &document
	if mapping.Kind == yaml.DocumentNode && len(mapping.Content) == 1 {
		mapping = mapping.Content[0]
	}
	if mapping.Kind != yaml.MappingNode {
		t.Fatal("original node configuration must be a mapping")
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value != "modules" {
			continue
		}
		modules := mapping.Content[i+1]
		for j := 0; j+1 < len(modules.Content); j += 2 {
			module, ok := originalConfig.Modules[modules.Content[j].Value]
			if !ok {
				t.Fatal("original module absent from child configuration")
			}
			body := module.Body
			modules.Content[j+1] = &body
		}
	}
	raw, err := yaml.Marshal(&document)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configFile, raw, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadTestNode(configFile)
	if err != nil || loaded.Node != originalConfig.Node {
		t.Fatal("child must use original validated node configuration", err)
	}
	if err = writeMoveCrashJSON(filepath.Join(directory, "job.json"), job); err != nil {
		t.Fatal(err)
	}
	artifactPath := target.backupArtifacts.root.Name()
	evidence := &moveProcessCutEvidence{}
	target = controls.reopenTarget(func() {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		log, err := os.OpenFile(filepath.Join(directory, "worker.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		defer log.Close()
		child := exec.CommandContext(ctx, self, "-test.run=^TestManagedVolumeMoveProcessCutWorker$", "-test.v", "-test.timeout=160s")
		child.Env = append(os.Environ(), "SFC_MOVE_CRASH_CONFIG="+configFile, "SFC_MOVE_CRASH_DIRECTORY="+directory)
		child.Stdout, child.Stderr = log, log
		if err = child.Start(); err != nil {
			t.Fatal(err)
		}
		finished := make(chan struct{})
		var waitErr error
		go func() { waitErr = child.Wait(); close(finished) }()
		stop := func() {
			select {
			case <-finished:
				return
			default:
				_ = child.Process.Kill()
				<-finished
			}
		}
		defer stop() // Join before the parent reopens this DB, including failure.
		logFailure := func() {
			file, err := os.Open(log.Name())
			if err != nil {
				t.Log("owned child log", err)
				return
			}
			defer file.Close()
			if info, err := file.Stat(); err == nil && info.Size() > 64<<10 {
				_, _ = file.Seek(info.Size()-(64<<10), io.SeekStart)
			}
			raw, err := io.ReadAll(io.LimitReader(file, 64<<10))
			t.Log("owned child log", string(raw), err)
		}
		marker := func(name string) ([]byte, bool) {
			t.Helper()
			select {
			case <-finished:
				logFailure()
				t.Fatal("owned receive child exited before checkpoint", waitErr, filepath.Join(directory, "worker.log"))
			default:
			}
			if ctx.Err() != nil {
				logFailure()
				t.Fatal("owned receive process checkpoint", ctx.Err())
			}
			raw, err := os.ReadFile(filepath.Join(directory, name))
			if os.IsNotExist(err) {
				return nil, false
			}
			if err != nil {
				t.Fatal(err)
			}
			return raw, true
		}
		wait("actual target child reopens original DB/provider before Group approval", func() bool { _, ok := marker("ready.json"); return ok })
		approve(job.Origin)
		wait("actual child pauses after first synced non-final receive chunk", func() bool {
			raw, ok := marker("checkpoint.json")
			if !ok {
				return false
			}
			checkpoint, err := schema.Decode[moveProcessCutCheckpoint](raw)
			if err != nil || checkpoint.Schema != 1 || checkpoint.Intent.Job.Digest() != job.Digest() || checkpoint.Progress.Binding != checkpoint.Intent.digest() {
				t.Fatal("invalid original worker checkpoint", err)
			}
			evidence.checkpoint = checkpoint
			return true
		})
		// Actual authenticated management remains available beside the paused
		// file worker; it is not a local replica or replacement control path.
		out, diagnostic, err := runManagedCLICommand(ctx, os.Getenv("SFC_TEST_CLI"), filepath.Join(root, "cli-home"), filepath.Join(root, "cli.yaml"), []string{"--tenant", job.Binding.Scope.Tenant, "volume", "show", job.Binding.Scope.App + "/" + job.Binding.Scope.ID}, nil)
		if err != nil {
			t.Fatal("management during paused actual transfer", err, string(diagnostic), string(out))
		}
		registry, err := p.Volumes(read().State)
		if err != nil {
			t.Fatal(err)
		}
		stored, move, ok := registry.Move(job.Selection())
		core, haveCore := registry.Volume(job.Binding.Scope)
		reader, haveReader := core.MoveReader(job.Binding)
		if !ok || !haveCore || !haveReader || stored.Digest() != job.Digest() || move.Phase != volumes.Copying || move.Manifest == nil || move.Manifest.Artifact != evidence.checkpoint.Intent.Manifest.Artifact || move.Verified != nil || move.CommitRevision != 0 {
			t.Fatal("paused receive lost original shared job/reader or committed early")
		}
		evidence.reader = reader
		if err = child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		<-finished
		var exit *exec.ExitError
		if ctx.Err() != nil || !errors.As(waitErr, &exit) {
			t.Fatal("expected explicit owned SIGKILL", waitErr, ctx.Err())
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatal("actual child was not terminated by SIGKILL", waitErr)
		}
		inspectMoveProcessCutRecord(t, artifactPath, evidence, false)
	})
	t.Log("actual original target Runtime child -> current Group approval/normal SFCP receive -> durable non-final offset before ACK/management still available -> explicit SIGKILL and Wait -> actual original DB/Apply/checkpoint/inode/prefix -> same DB/key normal Runtime resume")
	return target, evidence
}

func inspectMoveProcessCutRecord(t *testing.T, path string, evidence *moveProcessCutEvidence, allowTail bool) {
	t.Helper()
	checkpoint := evidence.checkpoint
	journal, err := reconcile.OpenJournal(filepath.Join(path, "journal.db"))
	if err != nil {
		t.Fatal(err)
	}
	row, readErr := journal.Read(moveReceiveKey(checkpoint.Intent))
	closeErr := journal.Close()
	if readErr != nil || closeErr != nil || row.State.Pending == nil || row.State.Pending.Kind != reconcile.Apply || row.State.Pending.ID != 1 || row.State.LastID != 1 || row.Checkpoint == nil || row.Checkpoint.Operation != 1 || row.State.Applied.Present {
		t.Fatal("SIGKILL lost original pending receive Apply/checkpoint", readErr, closeErr)
	}
	evidence.operation = row.State.Pending.ID
	proof, err := schema.Decode[backupDirectoryIdentity](row.Checkpoint.Data)
	if err != nil || proof.Binding != checkpoint.Intent.digest() {
		t.Fatal("wrong original receive directory proof", err)
	}
	directory, err := os.OpenRoot(filepath.Join(path, moveReceiveName(checkpoint.Intent)))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	info, err := directory.Stat(".")
	if err != nil || !sameBackupDirectory(info, proof) {
		t.Fatal("SIGKILL replaced original receive directory", err)
	}
	raw, err := backupRead(directory, "progress.json", 4096)
	progress, decodeErr := schema.Decode[moveReceiveProgress](raw)
	if err != nil || decodeErr != nil || progress != checkpoint.Progress || progress.Offset == 0 || progress.Offset%sfcp.VolumeChunkSize != 0 || !allowTail && progress.Offset != sfcp.VolumeChunkSize || progress.Offset >= checkpoint.Intent.Manifest.Bytes {
		t.Fatal("SIGKILL lost original durable non-final offset/prefix", err, decodeErr)
	}
	file, err := directory.Open("archive.tar")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != progress.Device || stat.Ino != progress.Inode || info.Size() < int64(progress.Offset) || info.Size() > int64(min(checkpoint.Intent.Manifest.Bytes, progress.Offset+sfcp.VolumeChunkSize)) || !allowTail && info.Size() != int64(progress.Offset) {
		t.Fatal("SIGKILL replaced original receive file/inode/size")
	}
	hash := sha256.New()
	if _, err = io.CopyN(hash, file, int64(progress.Offset)); err != nil {
		t.Fatal(err)
	}
	var prefix [32]byte
	copy(prefix[:], hash.Sum(nil))
	if prefix != progress.Prefix {
		t.Fatal("SIGKILL changed original synced prefix")
	}
}

func verifyMoveProcessCutData(t *testing.T, ctx context.Context, target *Runtime, ready volumes.NativeReady, job control.VolumeMove, read func() cluster.View, evidence *moveProcessCutEvidence) {
	t.Helper()
	if evidence == nil || evidence.operation != 1 || evidence.checkpoint.Intent.Job.Digest() != job.Digest() {
		t.Fatal("actual process-cut evidence required")
	}
	row, err := target.backupArtifacts.journal.Read(moveReceiveKey(evidence.checkpoint.Intent))
	if err != nil || row.State.Pending != nil || row.State.LastID != evidence.operation+1 || row.State.Applied.Present || row.State.Desired.Present || len(row.Consumers) != 0 {
		t.Fatal("process recovery replaced original receive Apply/Remove", err)
	}
	registry, err := target.controlPolicy.Volumes(read().State)
	if err != nil {
		t.Fatal(err)
	}
	stored, move, ok := registry.Move(job.Selection())
	if !ok || stored.Digest() != job.Digest() || move.Phase != volumes.Completed || move.ReaderClosed == nil || move.ReaderClosed.Consumer != evidence.reader || move.Manifest == nil || move.Manifest.Artifact != evidence.checkpoint.Intent.Manifest.Artifact {
		t.Fatal("process recovery lost original job/artifact/reader closure")
	}
	disk, err := target.docker.API.VolumeInspect(ctx, ready.Owner.Native, client.VolumeInspectOptions{})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(disk.Volume.Mountpoint, "process-cut-data"))
	if err != nil || !bytes.Equal(data, moveProcessCutData()) {
		t.Fatal("actual process-cut recovery lost original multi-chunk data", err)
	}
}
