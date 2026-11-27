// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

var ErrCompilerOwner = errors.New("original lifecycle compiler job requires recovery")

const compilerPrefix = "checker/compiler/"
const compilerRecordPrefix = compilerPrefix + "job/"

// Intent <=48KiB, policy <=24KiB and at most128 artifact hashes in both
// pre-closure evidence and the signed closure, plus bounded native/A2 fields.
const maxCompilerRecordBytes = 192 << 10

type compilerDirectory struct{ Device, Inode uint64 }
type compilerOwnerIdentity struct {
	Schema        uint8
	Cluster, Node [32]byte
	Path          string
	Directory     compilerDirectory
}

// CompilerGrant is the bounded current quorum answer. Recovery is metadata
// and cleanup authority only; it cannot be reused for Create/Start.
type CompilerGrant struct {
	Schema                       uint8
	Job, Manifest, Policy, Owner [32]byte
	Phase                        string
	Revision, Index              uint64
	DeadlineUnixMilli            int64
	Recovery                     bool
}
type CompilerAuthority func(context.Context, BuildIntent, bool) (CompilerGrant, error)

// CompilerOutput is available only after the exact original container has been
// stopped, waited and removed. Root is borrowed for this callback only.
type CompilerOutput struct {
	Intent    BuildIntent
	Policy    TenantPolicy
	Batch     CompileBatch
	ExitCode  int64
	ExitKnown bool
	Recover   bool
	Root      *os.Root
}

// CompilerCollector must persist/verify the original artifacts idempotently.
// Its digest is an actual durable cache receipt, not the compiler's report.
type CompilerCollector func(context.Context, CompilerOutput) ([32]byte, error)

type compilerDisk struct {
	Schema                              uint8
	Intent                              BuildIntent
	Policy                              TenantPolicy
	State                               reconcile.State
	Directory                           compilerDirectory
	Index, SharedRevision               uint64
	InputReady, Cancel                  bool
	CreateDispatched, CreateNotSent     bool
	NativeID, ImageID                   string
	StartDispatched, Exited             bool
	ExitCode                            int64
	Removed                             bool
	CollectionDispatched, OutputSettled bool
	Output                              [32]byte
	Artifacts                           []BuildArtifact `json:",omitempty"`
	WorkspaceClosed                     bool
	Closure                             *BuildClosure `json:",omitempty"`
}

// CompilerOwner serializes its finite native jobs and uses the existing node
// observations DB plus the SAME A2 state transitions. It has no idle container,
// polling worker, separate database, copied retry algorithm or automatic ID.
type CompilerOwner struct {
	life              sync.RWMutex
	mu                sync.Mutex
	interruptMu       sync.Mutex
	active            map[string]context.CancelFunc
	requested         map[string]bool
	shuttingDown      bool
	db                *storage.DB
	root              *os.Root
	lock              *storage.Lock
	identity          compilerOwnerIdentity
	private           ed25519.PrivateKey
	engine            *engine.Client
	authorize         CompilerAuthority
	collect           CompilerCollector
	known             map[string]bool // all durable IDs; value true only while locally pending
	closed, uncertain bool
}

func directoryIdentity(info os.FileInfo) (compilerDirectory, error) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return compilerDirectory{}, ErrCompilerOwner
	}
	return compilerDirectory{uint64(s.Dev), s.Ino}, nil
}
func compilerOwnership(info os.FileInfo) (int, int, bool) {
	s, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(s.Uid), int(s.Gid), true
}

func OpenCompilerOwner(db *storage.DB, path string, cluster [32]byte, private ed25519.PrivateKey, c *engine.Client, authority CompilerAuthority, collector CompilerCollector) (*CompilerOwner, error) {
	if db == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || cluster == ([32]byte{}) || len(private) != ed25519.PrivateKeySize || c == nil || c.API == nil || authority == nil {
		return nil, ErrCompilerOwner
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	validKey := bytes.Equal(derived, private)
	clear(derived)
	node := [32]byte(private.Public().(ed25519.PublicKey))
	if !validKey || c.Owner != engine.Owner(cluster, node) {
		return nil, ErrCompilerOwner
	}
	stored, readErr := db.GetBounded(compilerPrefix+"identity", 4096)
	if readErr != nil && !errors.Is(readErr, storage.ErrMissing) {
		return nil, readErr
	}
	if errors.Is(readErr, storage.ErrMissing) {
		rows, err := db.SizesBounded(compilerPrefix, maxBuildJobs+1, (maxBuildJobs+1)*256)
		if err != nil || len(rows) != 0 {
			return nil, ErrCompilerOwner
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrCompilerOwner
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, ErrCompilerOwner
	}
	directory, err := directoryIdentity(info)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(info, actual) {
		root.Close()
		return nil, ErrCompilerOwner
	}
	lock, err := storage.LockRoot(path)
	if err != nil {
		root.Close()
		return nil, err
	}
	m := &CompilerOwner{db: db, root: root, lock: lock, identity: compilerOwnerIdentity{1, cluster, node, path, directory}, private: bytes.Clone(private), engine: c, authorize: authority, collect: collector, known: map[string]bool{}, active: map[string]context.CancelFunc{}, requested: map[string]bool{}}
	fail := func(err error) (*CompilerOwner, error) { lock.Close(); root.Close(); clear(m.private); return nil, err }
	if readErr != nil {
		f, err := root.Open(".")
		if err != nil {
			return fail(err)
		}
		entries, err := f.ReadDir(-1)
		f.Close()
		if err != nil {
			return fail(err)
		}
		for _, entry := range entries {
			if entry.Name() != "node.lock" {
				return fail(ErrCompilerOwner)
			}
		}
		parent, err := os.Open(filepath.Dir(path))
		if err != nil {
			return fail(err)
		}
		err = parent.Sync()
		parent.Close()
		if err != nil {
			return fail(err)
		}
	}
	want, _ := json.Marshal(m.identity)
	if readErr == nil && !bytes.Equal(want, stored) {
		return fail(ErrCompilerOwner)
	}
	if readErr != nil {
		if err := db.Write(map[string][]byte{compilerPrefix + "identity": want}); err != nil {
			return fail(err)
		}
	}
	rows, err := db.SizesBounded(compilerRecordPrefix, maxBuildJobs, maxBuildJobs*256)
	if err != nil {
		return fail(err)
	}
	for key, size := range rows {
		if size == 0 || size > maxCompilerRecordBytes {
			return fail(ErrCompilerOwner)
		}
		raw, err := db.GetBounded(key, maxCompilerRecordBytes)
		if err != nil {
			return fail(err)
		}
		r, err := schema.Decode[compilerDisk](raw)
		if err != nil || key != compilerRecordPrefix+compilerJobKey(r.Intent) || m.validate(r) != nil {
			return fail(ErrCompilerOwner)
		}
		m.known[key] = r.Closure == nil
	}
	if err := db.Sync(); err != nil {
		return fail(err)
	}
	return m, nil
}

func compilerJobKey(b BuildIntent) string  { return b.Tenant + "/" + b.ID }
func compilerJobPath(b BuildIntent) string { return "jobs/" + compilerJobKey(b) }
func compilerKey(b BuildIntent) string     { return "checker/build/" + compilerJobKey(b) }
func compilerSpec(b BuildIntent, p TenantPolicy) string {
	raw, _ := json.Marshal(p)
	spec, _ := json.Marshal(struct {
		Schema      uint8
		Job, Policy [32]byte
	}{1, b.Digest(), sha256.Sum256(raw)})
	return string(spec)
}
func (m *CompilerOwner) validate(r compilerDisk) error {
	if r.Schema != 1 || r.Intent.Validate() != nil || r.Intent.Cluster != m.identity.Cluster || r.Intent.Owner != m.identity.Node || r.Policy.Validate() != nil || r.Policy.Tenant != r.Intent.Tenant || r.Policy.Revision != r.Intent.Selection.PolicyRevision || reconcile.Validate(r.State) != nil {
		return ErrCompilerOwner
	}
	want := reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(r.Intent, r.Policy)}}
	if r.State.Desired != want || r.State.LastID > 1 || r.State.Pending != nil && r.State.Pending.Kind != reconcile.Apply || r.State.Applied.Present && r.State.Applied != want.Resource || r.NativeID != "" && !digest(r.NativeID) || r.CreateNotSent && (!r.Cancel || r.NativeID != "" || r.StartDispatched || r.Exited) || r.NativeID != "" && !r.CreateDispatched || r.StartDispatched && r.NativeID == "" || r.Exited && (!r.StartDispatched || r.NativeID == "") || r.Removed && r.NativeID == "" || r.CollectionDispatched && !r.Removed || r.Output != ([32]byte{}) && !r.OutputSettled || r.WorkspaceClosed && !r.OutputSettled {
		return ErrCompilerOwner
	}
	if (r.CreateDispatched || r.NativeID != "") && !r.InputReady {
		return ErrCompilerOwner
	}
	if r.ImageID != "" && (!strings.HasPrefix(r.ImageID, "sha256:") || !digest(strings.TrimPrefix(r.ImageID, "sha256:"))) || r.CreateDispatched && r.ImageID == "" || r.SharedRevision > 3 || (r.Index == 0) != (r.SharedRevision == 0) {
		return ErrCompilerOwner
	}
	if r.InputReady && r.Directory == (compilerDirectory{}) {
		return ErrCompilerOwner
	}
	if r.OutputSettled && !r.Removed && !r.CreateNotSent {
		return ErrCompilerOwner
	}
	if validateBuildArtifacts(r.Intent, r.Artifacts) != nil || len(r.Artifacts) > 0 && (!r.OutputSettled || r.Output == ([32]byte{})) {
		return ErrCompilerOwner
	}
	if r.Closure != nil {
		if !slices.Equal(r.Artifacts, r.Closure.Artifacts) {
			return ErrCompilerOwner
		}
		phase := "dispatched"
		if r.Closure.Disposition == "never-dispatched" {
			phase = "reserved"
		}
		if !r.WorkspaceClosed || r.State.Pending != nil || !r.State.Applied.Present || r.Closure.Verify(r.Intent, phase) != nil || r.Closure.Journal != compilerJournalDigest(r) || r.Closure.Output != r.Output {
			return ErrCompilerOwner
		}
	} else if r.State.Applied.Present {
		return ErrCompilerOwner
	}
	return nil
}
func (m *CompilerOwner) load(tenant, id string) (compilerDisk, error) {
	if !name(tenant) || !digest(id) || m.closed || m.uncertain {
		return compilerDisk{}, ErrCompilerOwner
	}
	raw, err := m.db.GetBounded(compilerRecordPrefix+tenant+"/"+id, maxCompilerRecordBytes)
	if err != nil {
		return compilerDisk{}, err
	}
	r, err := schema.Decode[compilerDisk](raw)
	if err != nil || r.Intent.Tenant != tenant || r.Intent.ID != id || m.validate(r) != nil {
		return compilerDisk{}, ErrCompilerOwner
	}
	return r, nil
}
func (m *CompilerOwner) save(r compilerDisk) error {
	if m.closed || m.uncertain || m.validate(r) != nil {
		return ErrCompilerOwner
	}
	raw, err := json.Marshal(r)
	if err != nil || len(raw) > maxCompilerRecordBytes {
		return ErrCompilerOwner
	}
	key := compilerRecordPrefix + compilerJobKey(r.Intent)
	if err := m.db.Write(map[string][]byte{key: raw}); err != nil {
		m.uncertain = true
		return err
	}
	m.known[key] = r.Closure == nil
	return nil
}

func compilerJournalDigest(r compilerDisk) [32]byte {
	r.Closure = nil
	// A2 settlement does not rewrite the original native-effect evidence.
	r.State = reconcile.State{LastID: r.State.LastID}
	raw, _ := json.Marshal(r)
	return sha256.Sum256(append([]byte("sfc-checker-native-journal-1\x00"), raw...))
}

func (m *CompilerOwner) Cancel(tenant, id string) error {
	m.life.RLock()
	defer m.life.RUnlock()
	if !name(tenant) || !digest(id) {
		return ErrCompilerOwner
	}
	key := tenant + "/" + id
	m.interruptMu.Lock()
	m.requested[key] = true
	stop := m.active[key]
	m.interruptMu.Unlock()
	defer func() { m.interruptMu.Lock(); delete(m.requested, key); m.interruptMu.Unlock() }()
	if stop != nil {
		stop()
	} // unblock SDK Wait BEFORE waiting for the writer
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.load(tenant, id)
	if err != nil {
		return err
	}
	if r.Closure != nil || r.Cancel {
		return nil
	}
	r.Cancel = true
	return m.save(r)
}
func (m *CompilerOwner) Closure(tenant, id string) (BuildClosure, error) {
	m.life.RLock()
	defer m.life.RUnlock()
	// A completed immutable fact must not queue behind another job's SDK Wait.
	// Sync/read the borrowed DB directly; never clear the writer's uncertainty.
	if !name(tenant) || !digest(id) || m.closed {
		return BuildClosure{}, ErrCompilerOwner
	}
	raw, err := m.db.GetBounded(compilerRecordPrefix+tenant+"/"+id, maxCompilerRecordBytes)
	if err != nil {
		return BuildClosure{}, err
	}
	r, err := schema.Decode[compilerDisk](raw)
	if err == nil && (r.Intent.Tenant != tenant || r.Intent.ID != id || m.validate(r) != nil) {
		err = ErrCompilerOwner
	}
	if err != nil {
		return BuildClosure{}, err
	}
	if r.Closure == nil {
		return BuildClosure{}, reconcile.ErrPending
	}
	if err := m.db.Sync(); err != nil {
		return BuildClosure{}, err
	}
	c := *r.Closure
	c.Signature = bytes.Clone(c.Signature)
	c.Artifacts = slices.Clone(c.Artifacts)
	return c, nil
}
func (m *CompilerOwner) Close() error {
	m.life.Lock()
	defer m.life.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	clear(m.private)
	return errors.Join(m.root.Close(), m.lock.Close()) // borrowed DB/external resources stay owned
}

// Shutdown cancels only this owner's finite jobs. It never needs a new Start
// grant and never equates an unknown Create with absence. Closure/pin delivery
// may remain pending for recovery even after the original native is removed.
func (m *CompilerOwner) Shutdown(ctx context.Context) error {
	m.interruptMu.Lock()
	m.shuttingDown = true
	stops := make([]context.CancelFunc, 0, len(m.active))
	for _, stop := range m.active {
		stops = append(stops, stop)
	}
	m.interruptMu.Unlock()
	for _, stop := range stops {
		stop()
	}
	jobs, err := m.Pending()
	if err != nil {
		return err
	}
	var result error
	for _, job := range jobs {
		if err := ctx.Err(); err != nil {
			return errors.Join(result, err)
		}
		if err := m.Cancel(job.Tenant, job.ID); err != nil {
			result = errors.Join(result, err)
			continue
		}
		result = errors.Join(result, m.Step(ctx, job.Tenant, job.ID))
	}
	return result
}
