// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/jay94ks/mydcd/internal/workload"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type backupArtifactFake struct {
	source            volumes.ColdSource
	data              string
	exports, closes   int
	denyCopy, partial bool
	missingSource     bool
}

func (f *backupArtifactFake) Authorize(ctx context.Context, _ control.VolumeBackupBinding, cleanup bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.denyCopy && !cleanup {
		return errors.New("copy grant revoked")
	}
	return nil
}
func (f *backupArtifactFake) Source(context.Context, control.VolumeBackupBinding) (volumes.ColdSource, error) {
	return f.source, nil
}
func (f *backupArtifactFake) Export(ctx context.Context, b control.VolumeBackupBinding, out *os.File) (volumes.ArchiveReceipt, error) {
	f.exports++
	if f.partial {
		_, err := out.WriteString("original partial")
		return volumes.ArchiveReceipt{}, errors.Join(errors.New("original I/O outcome lost"), err)
	}
	r, err := os.OpenRoot(f.data)
	if err != nil {
		return volumes.ArchiveReceipt{}, err
	}
	defer r.Close()
	return volumes.WriteArchive(ctx, r, out, b.Options())
}
func (f *backupArtifactFake) CloseReader(context.Context, control.VolumeBackupBinding) error {
	f.closes++
	if f.missingSource {
		return errors.New("source removed after Ready")
	}
	return nil
}

// reranUnprivileged runs the calling top-level test as an unprivileged user when
// the suite runs as root, and reports whether it did. The volume filesystem
// profile owns its files as the process user, and a volume owned by UID 0 is
// refused. As root it re-executes only this test from the same test binary with
// UID/GID 65534; the caller returns when it did.
func reranUnprivileged(t *testing.T) bool {
	t.Helper()
	if os.Geteuid() != 0 {
		return false
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "mydc-unprivileged-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	tmp := filepath.Join(dir, "tmp")
	if err = os.Mkdir(tmp, 0700); err != nil {
		t.Fatal(err)
	}
	const unprivileged = 65534
	if err = os.Chown(tmp, unprivileged, unprivileged); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "app.test")
	if err = os.Link(exe, binary); err != nil {
		if err = copyExecutable(exe, binary); err != nil {
			t.Fatal(err)
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run", "^"+regexp.QuoteMeta(t.Name())+"$", "-test.count", "1", "-test.v")
	cmd.Dir = wd
	cmd.Env = append(os.Environ(), "TMPDIR="+tmp, "HOME="+tmp)
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: unprivileged, Gid: unprivileged}}
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("--- PASS: "+t.Name()+" ")) {
		// The checkout and every parent directory must be readable and
		// searchable by this UID; a 0700 root-only parent fails with EACCES.
		t.Fatalf("unprivileged run as UID %d failed (the checkout %s must be readable and searchable by that UID): %v\n%s", unprivileged, wd, err, out)
	}
	t.Logf("passed as UID %d", unprivileged)
	return true
}

func copyExecutable(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func TestBackupArtifactsDeletionIndependentOfSource(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	job, f, path := artifactFixture(t)
	m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	c, err := m.Step(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	before := f.closes
	f.missingSource = true
	job.Phase, job.Revision, job.Receipt = "Deleting", 3, &c.Receipt
	if _, err = m.Step(context.Background(), job); err != nil {
		t.Fatal("independent artifact deletion required removed source", err)
	}
	if f.closes != before {
		t.Fatal("deleting Ready touched original source reader")
	}
}

func artifactFixture(t *testing.T) (control.VolumeBackup, *backupArtifactFake, string) {
	t.Helper()
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{61}, 32))
	user := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{62}, 32))
	n, a := [32]byte(node.Public().(ed25519.PublicKey)), [32]byte(user.Public().(ed25519.PublicKey))
	cluster := [32]byte{63}
	scope := volumes.Scope{Cluster: cluster, Tenant: "tenant", App: "app", ID: "data", Generation: 1}
	spec := volumes.NativeSpec{Schema: 1, Scope: scope, Node: "node-a", NodeKey: n, Materialization: "initial", UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Mode: 0700, Retain: true}
	client := &engine.Client{Owner: engine.Owner(cluster, n)}
	raw, _ := json.Marshal(spec)
	id, err := client.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	ready := volumes.NativeReady{Schema: 1, Spec: spec, Generation: 1, Owner: volumes.Owner{Node: "node-a", Key: n, Native: id.Name}}
	ready.Signature = ed25519.Sign(node, volumes.NativeReadyBytes(ready))
	writer := volumes.Consumer{ID: "database", Generation: 1, Writable: true, Owner: ready.Owner, OwnerRevision: 1, Lease: reconcile.Lease{Generation: 1, Token: 1}}
	task := workload.ContainerSpec{Schema: 1, Node: client.Owner, Image: "sha256:" + strings.Repeat("a", 64), Bridge: "network/bridge/tenant/app/net", BridgeGeneration: 1, IPv4: netip.MustParseAddr("10.40.0.2"), Memory: 64 << 20, NanoCPU: 100_000_000, Process: &workload.Process{ImageID: "sha256:" + strings.Repeat("a", 64), User: fmt.Sprintf("%d:%d", spec.UID, spec.GID), Command: []string{"/db"}}, Volumes: []workload.VolumeMount{{Scope: scope, Consumer: writer, NativeKey: volumes.NativeKey(spec), NativeGeneration: 1, Target: "/data"}}}
	raw, _ = json.Marshal(task)
	source := volumes.ColdSource{Writer: volumes.Activation{Scope: scope, Consumer: writer, NativeKey: volumes.NativeKey(spec), NativeGeneration: 1, TaskKey: "workload/task/tenant/app/database", Task: reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}, Operation: 1}, NativeID: strings.Repeat("b", 64), Exit: volumes.ProcessExit{StartedAt: "2026-11-12T00:00:00Z", FinishedAt: "2026-11-12T00:00:01Z", Status: "exited"}}
	b := control.VolumeBackupBinding{Schema: 1, Scope: scope, ID: "one", Principal: "admin", Source: ready, Consumer: volumes.Consumer{ID: "b-one", Generation: 1, Owner: ready.Owner, OwnerRevision: 1, Lease: reconcile.Lease{Generation: 1, Token: 2}}, MaxBytes: 128 << 10, MaxEntries: 16, Compatibility: backupCompatibility(source)}
	session := access.Session{Schema: 1, ID: "session", Cluster: cluster, User: "admin", Key: a, Issuer: n, IssuedAt: 1, ExpiresAt: 1001}
	session.Signature = ed25519.Sign(node, access.SessionBytes(session))
	payload, _ := json.Marshal(control.VolumeBackupBegin{Scope: scope, ID: b.ID, MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, Compatibility: b.Compatibility})
	b.Origin = control.UserOperation{Schema: 1, Session: session, At: 2, Epoch: 1, RequestID: "backup", Change: control.Change{Schema: 1, Action: "begin-volume-backup", Principal: "admin", Payload: payload}}
	b.Origin.Signature = ed25519.Sign(user, control.OperationBytes(b.Origin))
	if !backupSourceMatches(source, b) || b.Origin.VerifyOriginal(cluster) != nil {
		t.Fatal("invalid fixture source/binding")
	}
	data := t.TempDir()
	if err = os.Chmod(data, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(data, "row"), []byte("original cold data"), 0640); err != nil {
		t.Fatal(err)
	}
	return control.VolumeBackup{Revision: 1, Phase: "Reserved", Binding: b}, &backupArtifactFake{source: source, data: data}, filepath.Join(t.TempDir(), "artifacts")
}

func TestBackupArtifactsOriginalCompletionRestartAndDelete(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	job, f, path := artifactFixture(t)
	m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if other, e := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f); e == nil {
		_ = other.Close()
		t.Fatal("second owner opened root")
	}
	c, err := m.Step(context.Background(), job)
	if err != nil || c == nil || f.exports != 1 {
		t.Fatal("original complete", c, err)
	}
	receipt := c.Receipt
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	m, err = openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	c, err = m.Step(context.Background(), job)
	if err != nil || c == nil || c.Receipt != receipt || f.exports != 1 {
		t.Fatal("restarted copy rather than recover", err, f.exports)
	}
	r, _ := m.journal.Read(backupArtifactKey(job.Binding))
	if r.State.LastID != 1 || r.State.Pending != nil {
		t.Fatal("changed original A2")
	}
	job.Phase, job.Revision, job.Receipt = "Deleting", 3, &receipt
	for i := 0; i < 2; i++ {
		if c, err = m.Step(context.Background(), job); err != nil || c != nil {
			t.Fatal("delete/replay", err)
		}
	}
	dir, err := m.directory(job.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if _, err = dir.Stat("archive.tar"); !os.IsNotExist(err) {
		t.Fatal("artifact retained", err)
	}
	if _, err = dir.Stat("intent.json"); err != nil {
		t.Fatal("lost original tombstone", err)
	}
	r, _ = m.journal.Read(backupArtifactKey(job.Binding))
	if r.State.LastID != 2 || r.State.Pending != nil || r.State.Applied.Present {
		t.Fatal("wrong deletion A2")
	}
}

func TestBackupArtifactsPartialUnknownRequiresOriginalCancel(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	job, f, path := artifactFixture(t)
	f.partial = true
	m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	if _, err = m.Step(context.Background(), job); err == nil {
		t.Fatal("partial copy claimed complete")
	}
	before, _ := m.journal.Read(backupArtifactKey(job.Binding))
	if before.State.Pending == nil || before.State.Pending.ID != 1 || before.State.Pending.Phase != reconcile.RecoveryRequired {
		t.Fatal("lost original Unknown")
	}
	_ = m.Close()
	m, err = openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Step(context.Background(), job); err == nil || f.exports != 1 {
		t.Fatal("partial original automatically recopied", err)
	}
	data, err := os.ReadFile(filepath.Join(path, backupArtifactName(job.Binding), "archive.tar"))
	if err != nil || string(data) != "original partial" {
		t.Fatal("original partial replaced", err)
	}
	f.denyCopy = true
	job.Phase, job.Revision = "Cancelling", 2
	if _, err = m.Step(context.Background(), job); err != nil {
		t.Fatal("revoked copy blocked original cleanup", err)
	}
	after, _ := m.journal.Read(backupArtifactKey(job.Binding))
	if after.State.LastID != 1 || after.State.Pending != nil || after.State.Applied.Present {
		t.Fatal("retirement fabricated apply/new ID")
	}
	if _, err = m.Step(context.Background(), job); err != nil {
		t.Fatal("lost cancel reply cannot recover", err)
	}
}

type lostBackupApply struct{ backupArtifactDriver }

func (d lostBackupApply) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	_, err := d.backupArtifactDriver.Execute(ctx, key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectUnknown, errors.New("completion reply lost")
}
func TestBackupArtifactsSyncedReceiptRecoversOriginalUnknown(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	job, f, path := artifactFixture(t)
	m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = m.Close() }()
	raw, _ := json.Marshal(job.Binding)
	key := backupArtifactKey(job.Binding)
	if err = m.journal.Desired(key, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)}}, 1); err != nil {
		t.Fatal(err)
	}
	if err = m.journal.Step(context.Background(), key, lostBackupApply{backupArtifactDriver{m: m}}); err == nil {
		t.Fatal("lost reply claimed known")
	}
	_ = m.Close()
	m, err = openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
	if err != nil {
		t.Fatal(err)
	}
	c, err := m.Step(context.Background(), job)
	if err != nil || c == nil || f.exports != 1 {
		t.Fatal("did not recover synced original receipt", err)
	}
	r, _ := m.journal.Read(key)
	if r.State.LastID != 1 || r.State.Pending != nil || !r.State.Applied.Present {
		t.Fatal("substituted operation")
	}
}

func TestBackupArtifactsRejectForeignTamperedAndUnownedReady(t *testing.T) {
	if reranUnprivileged(t) {
		return
	}
	for _, scenario := range []string{"source", "digest", "foreign", "unowned-ready", "new-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			job, f, path := artifactFixture(t)
			m, err := openBackupArtifacts(path, job.Binding.Scope.Cluster, job.Binding.Source.Owner.Key, f)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if scenario == "source" {
				f.source.Exit.Code = 137
				if _, err = m.Step(context.Background(), job); err == nil || f.exports != 0 {
					t.Fatal("unclean source exported", err)
				}
				return
			}
			if scenario == "new-cancel" {
				job.Phase, job.Revision = "Cancelling", 2
				if _, err = m.Step(context.Background(), job); err != nil || f.exports != 0 {
					t.Fatal("never-started cancel", err)
				}
				return
			}
			if scenario == "unowned-ready" {
				job.Phase, job.Revision = "Deleting", 3
				job.Receipt = &volumes.ArchiveReceipt{}
				if _, err = m.Step(context.Background(), job); err == nil {
					t.Fatal("settled foreign Ready without original local materialization")
				}
				return
			}
			c, err := m.Step(context.Background(), job)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(path, backupArtifactName(job.Binding))
			if scenario == "digest" {
				if err = os.WriteFile(filepath.Join(dir, "archive.tar"), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
				if _, err = m.Step(context.Background(), job); err == nil {
					t.Fatal("tampered bytes returned Ready")
				}
				return
			}
			outside := filepath.Join(t.TempDir(), "foreign")
			_ = os.WriteFile(outside, []byte("foreign"), 0600)
			if err = os.Symlink(outside, filepath.Join(dir, "foreign")); err != nil {
				t.Fatal(err)
			}
			job.Phase, job.Revision, job.Receipt = "Deleting", 3, &c.Receipt
			if _, err = m.Step(context.Background(), job); err == nil {
				t.Fatal("unknown entry deleted")
			}
			if data, _ := os.ReadFile(outside); string(data) != "foreign" {
				t.Fatal("foreign data changed")
			}
		})
	}
}
