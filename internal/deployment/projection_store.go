// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/jay94ks/seafield/internal/desired"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/jay94ks/seafield/internal/workload"
)

var ErrProjectionStore = errors.New("private task projection unavailable or inconsistent")

// ProjectionGate must check the current committed recipe/approvals/node/writer
// admission before a new publication or activation. Cleanup never uses it.
type ProjectionGate func(context.Context, Binding) error

type ProjectionStore struct {
	mu   sync.Mutex
	root *os.Root
	path string
	// values holds the private value directories (file-NNNN, manifest).
	// The node daemon puts it on a tmpfs, so plain values never reach a
	// disk; root keeps only the journal and the public scope receipts.
	values     *os.Root
	valuesPath string
	// Each value directory written into values leaves a seen-NAME marker
	// there. An applied generation whose directory and marker are both gone
	// was lost with an earlier boot's tmpfs and may be written again, from a
	// fresh read under current authority; a directory that went missing or
	// changed within one boot stays an error.
	cluster, node [32]byte
	gate          ProjectionGate
	maxBytes      int
	lock          *storage.Lock
	journal       *reconcile.Journal
	closed        bool
}

type projectionScope struct {
	Schema  uint8
	Binding bindingRecord
}

func projectionKey(b Binding) string {
	u := b.d.Needs.Use
	return ResourceKey("inputs", u.Tenant, u.App, bindingTaskID(b.d.Needs))
}
func projectionTask(b Binding) string {
	u := b.d.Needs.Use
	return ResourceKey("task", u.Tenant, u.App, bindingTaskID(b.d.Needs))
}

func bindingTaskID(n Needs) string {
	if n.Instance != nil {
		return n.Instance.ResourceID()
	}
	return n.Use.Service
}
func projectionReference(b Binding) workload.InputRef {
	return workload.InputRef{Key: projectionKey(b), Generation: b.d.Needs.Generation, Binding: b.Digest()}
}
func projectionName(key string, generation uint64) string {
	d := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d", key, generation)))
	return hex.EncodeToString(d[:])
}

func projectionPrivate(info os.FileInfo, dir bool) bool {
	if info == nil {
		return false
	}
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && (dir && info.IsDir() || !dir && info.Mode().IsRegular())
}

func projectionSync(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return ErrProjectionStore
	}
	defer f.Close()
	if f.Sync() != nil {
		return ErrProjectionStore
	}
	return nil
}

// OpenProjections keeps the values next to path, in path+"-values".
func OpenProjections(path string, cluster, node [32]byte, maxBytes int, gate ProjectionGate) (*ProjectionStore, error) {
	return OpenProjectionsWithValues(path, path+"-values", cluster, node, maxBytes, gate)
}

func projectionDirectory(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrProjectionStore
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, ErrProjectionStore
	}
	info, err := os.Lstat(path)
	if err != nil || !projectionPrivate(info, true) {
		return nil, ErrProjectionStore
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, ErrProjectionStore
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrProjectionStore
	}
	return r, nil
}

// OpenProjectionsWithValues keeps the journal and scope receipts in path
// and the private value directories in values (a tmpfs on a node).
func OpenProjectionsWithValues(path, values string, cluster, node [32]byte, maxBytes int, gate ProjectionGate) (*ProjectionStore, error) {
	if path == values || cluster == ([32]byte{}) || node == ([32]byte{}) || gate == nil || maxBytes <= 0 || maxBytes > 64<<20 {
		return nil, ErrProjectionStore
	}
	r, err := projectionDirectory(path)
	if err != nil {
		return nil, err
	}
	v, err := projectionDirectory(values)
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	m := &ProjectionStore{root: r, path: path, values: v, valuesPath: values, cluster: cluster, node: node, maxBytes: maxBytes, gate: gate}
	ok := false
	defer func() {
		if !ok {
			_ = m.Close()
		}
	}()
	m.lock, err = storage.LockRoot(path)
	if err != nil {
		return nil, err
	}
	header, _ := json.Marshal(struct {
		Schema        uint8
		Cluster, Node [32]byte
	}{1, cluster, node})
	if _, err = r.Lstat("owner.json"); os.IsNotExist(err) {
		if projectionMetadata(r, "owner.json", header) != nil {
			return nil, ErrProjectionStore
		}
	} else if err != nil {
		return nil, ErrProjectionStore
	}
	got, err := projectionRead(r, "owner.json", nil, 4096)
	if err != nil || !bytes.Equal(got, header) {
		return nil, ErrProjectionStore
	}
	if _, err = v.Lstat("owner.json"); os.IsNotExist(err) {
		if projectionMetadata(v, "owner.json", header) != nil {
			return nil, ErrProjectionStore
		}
	} else if err != nil {
		return nil, ErrProjectionStore
	}
	if got, err = projectionRead(v, "owner.json", nil, 4096); err != nil || !bytes.Equal(got, header) {
		return nil, ErrProjectionStore
	}
	// Value directories an older daemon kept in path are plain values on a
	// disk: delete them. Their generations are restored as after a reboot.
	if err = m.dropDiskValues(); err != nil {
		return nil, err
	}
	m.journal, err = reconcile.OpenJournal(filepath.Join(path, "journal.db"))
	if err != nil {
		return nil, err
	}
	ok = true
	return m, nil
}

func (m *ProjectionStore) scope(raw string) (Binding, error) {
	var s projectionScope
	if len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &s) != nil || s.Schema != 1 {
		return Binding{}, ErrProjectionStore
	}
	b := Binding{s.Binding}
	canonical, err := json.Marshal(s)
	if err != nil || string(canonical) != raw || !validBinding(b) || b.d.Cluster != m.cluster || b.d.Needs.Use.NodeKey != m.node {
		return Binding{}, ErrProjectionStore
	}
	return b, nil
}

// Publish syncs one complete generation before the existing A2/A3 journal can
// admit a native consumer. It never overwrites a published recipe/value.
func (m *ProjectionStore) Publish(ctx context.Context, b Binding, stage Stage, revision uint64, capacity int) (workload.InputRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := projectionReference(b)
	if m.closed || !validBinding(b) || b.d.Cluster != m.cluster || b.d.Needs.Use.NodeKey != m.node || stage.Binding() != b.Digest() || m.gate(ctx, b) != nil {
		return ref, ErrProjectionStore
	}
	files := stage.Files()
	defer func() {
		for _, f := range files {
			clear(f.Data)
		}
	}()
	if len(files) != len(b.d.Needs.Files) {
		return ref, ErrProjectionStore
	}
	total := 0
	for i, f := range files {
		if f.Projection != b.d.Needs.Files[i] || len(f.Data) > m.maxBytes-total {
			return ref, ErrProjectionStore
		}
		total += len(f.Data)
	}
	raw, _ := json.Marshal(projectionScope{1, ownBinding(b.d)})
	d := reconcile.Desired{Revision: revision, Resource: reconcile.Resource{Generation: ref.Generation, Present: true, Spec: string(raw)}}
	old, err := m.journal.Read(ref.Key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return ref, err
	}
	if err == nil && old.State.Pending != nil {
		if old.State.Desired != d {
			return ref, reconcile.ErrPending
		}
		// A dispatched Apply can only recover its original synced files; absence
		// must not trigger publication/recreation under a new attempt, except
		// a directory lost with an earlier boot's tmpfs.
		if m.lost(b) {
			if err = m.restore(ctx, b, files); err != nil {
				return ref, err
			}
		}
		if err = m.verify(b, files); err != nil {
			return ref, err
		}
		return ref, m.journal.Step(ctx, ref.Key, projectionDriver{m})
	}
	if err == nil && old.State.Applied.Present && old.State.Applied.Generation == ref.Generation {
		if m.lost(b) {
			if err = m.restore(ctx, b, files); err != nil {
				return ref, err
			}
		}
		if m.verify(b, files) != nil {
			return ref, ErrProjectionStore
		}
	}
	if err = m.journal.Desired(ref.Key, d, capacity); err != nil {
		return ref, err
	}
	if err = m.retainScope(b); err != nil {
		return ref, err
	}
	if err = ctx.Err(); err != nil {
		return ref, err
	}
	if err = m.prepare(b, files); err != nil {
		return ref, err
	}
	if err = m.gate(ctx, b); err != nil {
		return ref, err
	}
	return ref, m.journal.Step(ctx, ref.Key, projectionDriver{m})
}

func (m *ProjectionStore) expected(ref workload.InputRef, consumer, key string, generation uint64) (Binding, reconcile.Record, error) {
	r, err := m.journal.Read(ref.Key)
	if err != nil || generation != ref.Generation || !r.State.Applied.Present || r.State.Applied.Generation != generation {
		return Binding{}, r, ErrProjectionStore
	}
	b, err := m.scope(r.State.Applied.Spec)
	if err != nil || projectionReference(b) != ref || projectionTask(b) != key {
		return Binding{}, r, ErrProjectionStore
	}
	native, err := (&engine.Client{Owner: desired.Owner(m.cluster, m.node)}).Identity("container", key, reconcile.Resource{Generation: generation, Present: true, Spec: "input-consumer-name"})
	if err != nil || consumer != "workload/"+native.Name {
		return Binding{}, r, ErrProjectionStore
	}
	return b, r, nil
}

// Ready confirms an already-published original generation and its actual
// private files, through current authority. It never stages/recreates a file.
func (m *ProjectionStore) Ready(ctx context.Context, ref workload.InputRef) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false, ErrProjectionStore
	}
	r, err := m.journal.Read(ref.Key)
	if errors.Is(err, storage.ErrMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !r.State.Applied.Present {
		return false, nil
	}
	b, err := m.scope(r.State.Applied.Spec)
	if err != nil || projectionReference(b) != ref {
		return false, ErrProjectionStore
	}
	if r.State.Pending != nil || !r.State.Desired.Present || r.State.Desired.Resource != r.State.Applied {
		return false, ErrProjectionStore
	}
	if err = m.gate(ctx, b); err != nil {
		return false, err
	}
	if m.lost(b) {
		return false, nil
	}
	if err = m.verify(b, nil); err != nil {
		return false, err
	}
	return true, nil
}

// lost reports whether b's applied value directory went with the tmpfs of
// an earlier boot and has not been written again yet.
func (m *ProjectionStore) lost(b Binding) bool {
	name := projectionName(projectionKey(b), b.d.Needs.Generation)
	_, err := m.values.Lstat(name)
	_, seen := m.values.Lstat("seen-" + name)
	return os.IsNotExist(err) && os.IsNotExist(seen)
}

func (m *ProjectionStore) lease(ref workload.InputRef, b Binding, pin reconcile.Lease, verify bool) (workload.InputLease, error) {
	if verify && m.verify(b, nil) != nil {
		return workload.InputLease{}, ErrProjectionStore
	}
	l := workload.InputLease{Ref: ref, Pin: pin}
	r, err := m.directory(b)
	if err != nil {
		return workload.InputLease{}, err
	}
	raw, err := projectionRead(r, "manifest.json", nil, 1<<20)
	_ = r.Close()
	var manifest projectionManifest
	if err != nil || json.Unmarshal(raw, &manifest) != nil || len(manifest.Sources) != 0 && len(manifest.Sources) != len(b.d.Needs.Files) {
		return workload.InputLease{}, ErrProjectionStore
	}
	for i, p := range b.d.Needs.Files {
		reference := p.Key
		if len(manifest.Sources) != 0 {
			reference = manifest.Sources[i] + "/" + p.Key
		}
		l.Files = append(l.Files, workload.InputFile{Source: filepath.Join(m.valuesPath, projectionName(ref.Key, ref.Generation), fmt.Sprintf("file-%04d", i)), Target: p.Target, UID: p.UID, GID: p.GID, Mode: p.Mode, Kind: p.Kind, Reference: reference})
	}
	return l, nil
}

func (m *ProjectionStore) AcquireInputs(ctx context.Context, ref workload.InputRef, consumer, key string, generation uint64) (workload.InputLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return workload.InputLease{}, ErrProjectionStore
	}
	b, _, err := m.expected(ref, consumer, key, generation)
	if err != nil {
		return workload.InputLease{}, err
	}
	if err = m.gate(ctx, b); err != nil {
		return workload.InputLease{}, err
	}
	if err = m.verify(b, nil); err != nil {
		return workload.InputLease{}, err
	}
	pin, err := m.journal.Borrow(ref.Key, consumer, generation)
	if err != nil {
		return workload.InputLease{}, err
	}
	return m.lease(ref, b, pin, true)
}
func (m *ProjectionStore) InspectInputs(_ context.Context, ref workload.InputRef, consumer, key string, generation uint64) (workload.InputLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return workload.InputLease{}, ErrProjectionStore
	}
	b, r, err := m.expected(ref, consumer, key, generation)
	if err != nil {
		return workload.InputLease{}, err
	}
	pin, ok := r.Consumers[consumer]
	if !ok || pin.Generation != generation {
		return workload.InputLease{}, ErrProjectionStore
	}
	return m.lease(ref, b, pin, true)
}

// RetiringInputs proves the original durable pin/path only. It cannot admit or
// restart a process and permits native Stop/Remove even if source bytes were
// lost or permission revoked. File integrity uncertainty remains in this store.
func (m *ProjectionStore) RetiringInputs(_ context.Context, ref workload.InputRef, consumer, key string, generation uint64) (workload.InputLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return workload.InputLease{}, ErrProjectionStore
	}
	b, r, err := m.expected(ref, consumer, key, generation)
	if err != nil {
		return workload.InputLease{}, err
	}
	pin, ok := r.Consumers[consumer]
	if !ok || pin.Generation != generation {
		return workload.InputLease{}, ErrProjectionStore
	}
	return m.lease(ref, b, pin, false)
}
func (m *ProjectionStore) ReturnInputs(ref workload.InputRef, consumer, key string, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProjectionStore
	}
	current, err := m.journal.Read(ref.Key)
	if err != nil {
		return err
	}
	// A replay after confirmed native absence may arrive after file/shared
	// closure. No stored pin means no mutation; never release a different pin.
	if _, exists := current.Consumers[consumer]; !exists {
		return nil
	}
	_, r, err := m.expected(ref, consumer, key, generation)
	if err != nil {
		return err
	}
	pin, ok := r.Consumers[consumer]
	if !ok {
		return nil
	}
	return m.journal.Return(ref.Key, consumer, pin)
}

func (m *ProjectionStore) Drain(ctx context.Context, ref workload.InputRef, revision uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrProjectionStore
	}
	r, err := m.journal.Read(ref.Key)
	if err != nil {
		return err
	}
	if ref.Generation != r.State.GenerationFloor {
		return ErrProjectionStore
	}
	raw := r.State.Applied.Spec
	if raw == "" {
		raw = r.State.Desired.Spec
	}
	b, err := m.scope(raw)
	if err != nil || projectionReference(b) != ref {
		return ErrProjectionStore
	}
	if err = m.journal.Desired(ref.Key, reconcile.Desired{Revision: revision, Retiring: ref.Generation}, r.Capacity); err != nil {
		return err
	}
	return m.journal.Step(ctx, ref.Key, projectionDriver{m})
}
func (m *ProjectionStore) Gone(ref workload.InputRef) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gone(ref)
}
func (m *ProjectionStore) gone(ref workload.InputRef) (bool, error) {
	if m.closed {
		return false, ErrProjectionStore
	}
	b, err := m.retainedScope(ref)
	if err != nil || projectionReference(b) != ref {
		return false, ErrProjectionStore
	}
	r, err := m.journal.Read(ref.Key)
	if err != nil {
		return false, err
	}
	if r.State.GenerationFloor < ref.Generation || r.State.Pending != nil && r.State.Pending.Target.Generation == ref.Generation || r.State.Applied.Present && r.State.Applied.Generation == ref.Generation || r.State.Desired.Present && r.State.Desired.Generation == ref.Generation {
		return false, nil
	}
	for _, pin := range r.Consumers {
		if pin.Generation == ref.Generation {
			return false, nil
		}
	}
	_, err = m.values.Lstat(projectionName(ref.Key, ref.Generation))
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, ErrProjectionStore
	}
	return false, nil
}

// Forget consumes a current quorum-confirmed binding inventory AFTER shared
// usage release. A blank/missing registry has no generation floor and cannot
// authorize deletion of the retained original scope receipt.
func (m *ProjectionStore) Forget(ref workload.InputRef, inventory Bindings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.forget(ref, inventory)
}
func (m *ProjectionStore) forget(ref workload.InputRef, inventory Bindings) error {
	b, err := m.retainedScope(ref)
	if err != nil {
		return err
	}
	if inventory.cluster != m.cluster || inventory.Owns(b) || inventory.floors[consumerKey(b.d.Needs)] < ref.Generation {
		return ErrProjectionStore
	}
	if gone, err := m.gone(ref); err != nil || !gone {
		return ErrProjectionStore
	}
	if m.root.Remove("scope-"+projectionName(ref.Key, ref.Generation)+".json") != nil || projectionSync(m.root) != nil {
		return ErrProjectionStore
	}
	return nil
}

// ForgetRetired consumes the validated original input removal claim. This
// makes a post-commit metadata cleanup restartable without treating a missing
// scope file as native Gone or issuing another closure proof from absence.
func (m *ProjectionStore) ForgetRetired(ref workload.InputRef, bindings Bindings, app Inventory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || app.d.Cluster != m.cluster || bindings.cluster != m.cluster || app.validate() != nil {
		return ErrProjectionStore
	}
	i := app.claim(ref.Key)
	if i < 0 {
		return ErrProjectionStore
	}
	c := app.d.Claims[i]
	if !c.Removed || c.Step.Kind != "inputs" || c.Step.Owner != m.node || c.Native != "projection/"+hex.EncodeToString(ref.Binding[:]) || c.Removal == nil {
		return ErrProjectionStore
	}
	var goal GoalCommand
	if json.Unmarshal([]byte(c.Command.Value), &goal) != nil {
		return ErrProjectionStore
	}
	matched := false
	for _, dependency := range goal.Dependencies {
		if strings.HasPrefix(dependency.Key, "workload/task/") && dependency.Generation == ref.Generation {
			matched = true
		}
	}
	if !matched {
		return ErrProjectionStore
	}
	for _, b := range bindings.live {
		if projectionReference(b) == ref {
			return ErrProjectionStore
		}
	}
	if _, err := m.root.Lstat("scope-" + projectionName(ref.Key, ref.Generation) + ".json"); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return ErrProjectionStore
	}
	return m.forget(ref, bindings)
}

// SecretClosure proves only this projection lifetime. A combined binding
// still needs every original Volume proof before shared Release can succeed.
func (m *ProjectionStore) SecretClosure(ref workload.InputRef, key ed25519.PrivateKey) (Closure, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key.Public().(ed25519.PublicKey), m.node[:]) {
		return Closure{}, ErrProjectionStore
	}
	b, err := m.retainedScope(ref)
	if err != nil {
		return Closure{}, ErrProjectionStore
	}
	if gone, err := m.gone(ref); err != nil || !gone {
		return Closure{}, ErrProjectionStore
	}
	proof := Closure{}
	for _, g := range b.Grants() {
		u := g.Use
		p := secrets.UseGone{Cluster: m.cluster, Realm: g.Realm, Tenant: u.Tenant, App: u.App, Deployment: u.Deployment, Consumer: g.Consumer, Generation: g.Generation, NodeKey: m.node, Selection: g.Selection, Lifetime: g.Lifetime, Stopped: true, MountsGone: true}
		p.Signature = ed25519.Sign(key, secrets.UseGoneBytes(p))
		proof.Secrets = append(proof.Secrets, p)
	}
	return proof, nil
}
func (m *ProjectionStore) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var err error
	if m.journal != nil {
		err = errors.Join(err, m.journal.Close())
	}
	if m.lock != nil {
		err = errors.Join(err, m.lock.Close())
	}
	if m.root != nil {
		err = errors.Join(err, m.root.Close())
	}
	if m.values != nil {
		err = errors.Join(err, m.values.Close())
	}
	return err
}

type projectionDriver struct{ m *ProjectionStore }

func (d projectionDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	m := d.m
	if ctx.Err() != nil {
		return reconcile.EffectUnknown, ctx.Err()
	}
	b, err := m.scope(op.Target.Spec)
	if err != nil || key != projectionKey(b) || op.Target.Generation != b.d.Needs.Generation {
		return reconcile.EffectUnknown, ErrProjectionStore
	}
	if op.Kind == reconcile.Apply {
		if err = m.verify(b, nil); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectApplied, nil
	}
	if op.Kind != reconcile.Remove {
		return reconcile.EffectUnknown, reconcile.ErrOperation
	}
	name := projectionName(key, op.Target.Generation)
	if _, err = m.values.Lstat(name); !os.IsNotExist(err) {
		if err = m.verify(b, nil); err != nil {
			return reconcile.EffectUnknown, err
		}
		if err = m.values.RemoveAll(name); err != nil || projectionSync(m.values) != nil {
			return reconcile.EffectUnknown, ErrProjectionStore
		}
	}
	// A removed generation is never restored, so its seen marker can go too.
	if err = m.values.Remove("seen-" + name); err != nil && !os.IsNotExist(err) {
		return reconcile.EffectUnknown, ErrProjectionStore
	}
	return reconcile.EffectApplied, nil
}
func (d projectionDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	return d.Execute(ctx, key, op)
}

func projectionRead(root *os.Root, name string, projection *Projection, limit int) ([]byte, error) {
	before, err := root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() {
		return nil, ErrProjectionStore
	}
	if projection == nil || projection.Kind == "env" {
		if !projectionPrivate(before, false) {
			return nil, ErrProjectionStore
		}
	} else {
		s, ok := before.Sys().(*syscall.Stat_t)
		if !ok || s.Uid != projection.UID || s.Gid != projection.GID || before.Mode().Perm() != os.FileMode(projection.Mode) {
			return nil, ErrProjectionStore
		}
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, ErrProjectionStore
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrProjectionStore
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(raw) > limit {
		clear(raw)
		return nil, ErrProjectionStore
	}
	return raw, nil
}
