// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"sync"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

type FixedRootAuthority func(context.Context, nodestorage.Reference) (nodestorage.Root, error)

type fixedDeclaration struct {
	Schema    uint8
	Spec      NativeSpec
	Selection nodestorage.FixedSelection
}
type fixedCheckpoint struct {
	Schema     uint8
	Ready      NativeReady
	RootLease  reconcile.Lease
	Projection projectionOwner
}

// FixedManager adapts the SAME A2/A3 journal to preexisting directory data.
// It is separate from the strict Docker local-volume driver. The private bind
// is a derived view of an original inode, never a new data materialization.
type FixedManager struct {
	mu            sync.Mutex
	journal       *reconcile.Journal
	projector     *fixedProjector
	roots         *nodestorage.RootManager
	engine        *engine.Client
	cluster, node [32]byte
	nodeID        string
	private       ed25519.PrivateKey
	authority     FixedRootAuthority
	closed        bool
}

func OpenFixed(path string, c *engine.Client, roots *nodestorage.RootManager, cluster [32]byte, nodeID string, private ed25519.PrivateKey, authority FixedRootAuthority) (*FixedManager, error) {
	if c == nil || c.API == nil || roots == nil || cluster == ([32]byte{}) || !identifier(nodeID) || len(private) != ed25519.PrivateKeySize || authority == nil {
		return nil, ErrNativeVolume
	}
	node := [32]byte(private.Public().(ed25519.PublicKey))
	if c.Owner != engine.Owner(cluster, node) {
		return nil, ErrNativeVolume
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	p, err := openPrivateProjection(filepath.Join(filepath.Dir(path), "mounts"), private)
	if err != nil {
		_ = j.Close()
		return nil, err
	}
	m := &FixedManager{journal: j, projector: p, roots: roots, engine: c, cluster: cluster, node: node, nodeID: nodeID, private: bytes.Clone(private), authority: authority}
	for _, key := range j.Keys() {
		r, err := j.Read(key)
		if err == nil {
			err = m.validateRecord(key, r)
		}
		if err != nil {
			_ = p.file.Close()
			_ = j.Close()
			return nil, err
		}
	}
	return m, nil
}

func (m *FixedManager) declaration(key string, target reconcile.Resource) (fixedDeclaration, error) {
	d, err := schema.Decode[fixedDeclaration]([]byte(target.Spec))
	raw, _ := json.Marshal(d)
	if err != nil || d.Schema != 1 || d.Spec.Validate() != nil || d.Spec.Kind != "node-fixed" || d.Spec.Scope.Cluster != m.cluster || d.Spec.Node != m.nodeID || d.Spec.NodeKey != m.node || d.Selection.Validate() != nil || d.Selection.Root.Root.Cluster != m.cluster || d.Selection.Root.Root.Node != m.nodeID || d.Selection.Root.Root.Key != m.node || target.Generation != d.Spec.Scope.Generation || !target.Present || key != NativeKey(d.Spec) || target.Spec != string(raw) {
		return d, ErrNativeVolume
	}
	digest := d.Selection.Digest()
	if d.Spec.FixedDigest != hex.EncodeToString(digest[:]) {
		return d, ErrNativeVolume
	}
	return d, nil
}

func (m *FixedManager) original(key string, r reconcile.Record) (fixedCheckpoint, error) {
	if r.Checkpoint == nil {
		return fixedCheckpoint{}, ErrNativeVolume
	}
	d, err := m.declaration(key, r.Checkpoint.Target)
	if err != nil {
		return fixedCheckpoint{}, err
	}
	c, err := schema.Decode[fixedCheckpoint](r.Checkpoint.Data)
	raw, _ := json.Marshal(c)
	if err != nil || !bytes.Equal(raw, r.Checkpoint.Data) || c.Schema != 1 || c.Ready.Verify() != nil || c.Ready.Spec != d.Spec || c.Ready.Fixed == nil || c.Ready.Fixed.Selection().Digest() != d.Selection.Digest() || c.RootLease.Generation != d.Selection.Root.Root.Generation || c.RootLease.Token == 0 || c.Projection.Schema != 1 || c.Projection.Spec != projectionSpec(d.Spec) || c.Projection.Slot.Inode == 0 || c.Projection.Target.Inode == 0 {
		return c, ErrNativeVolume
	}
	return c, nil
}

func (m *FixedManager) validateRecord(key string, r reconcile.Record) error {
	if r.Schema != 1 || reconcile.Validate(r.State) != nil {
		return ErrNativeVolume
	}
	for _, target := range []reconcile.Resource{r.State.Desired.Resource, r.State.Applied} {
		if target.Present {
			if _, err := m.declaration(key, target); err != nil {
				return err
			}
		}
	}
	if op := r.State.Pending; op != nil {
		if _, err := m.declaration(key, op.Target); err != nil {
			return err
		}
	}
	if r.Checkpoint != nil {
		if _, err := m.original(key, r); err != nil {
			return err
		}
	}
	if r.State.Applied.Present && r.Checkpoint == nil {
		return ErrNativeVolume
	}
	return nil
}

func (m *FixedManager) Desired(spec NativeSpec, selection nodestorage.FixedSelection, revision uint64, capacity int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := fixedDeclaration{1, spec, selection.Clone()}
	raw, _ := json.Marshal(d)
	key := NativeKey(spec)
	target := reconcile.Resource{Generation: spec.Scope.Generation, Spec: string(raw), Present: true}
	if _, err := m.declaration(key, target); err != nil {
		return key, err
	}
	old, err := m.journal.Read(key)
	if err != nil && !errors.Is(err, storage.ErrMissing) {
		return key, err
	}
	if err == nil {
		for _, previous := range []reconcile.Resource{old.State.Desired.Resource, old.State.Applied} {
			if previous.Present && previous != target {
				return key, ErrNativeVolume
			}
		}
		if old.State.Pending != nil && old.State.Pending.Target != target {
			return key, ErrNativeVolume
		}
	}
	return key, m.journal.Desired(key, reconcile.Desired{Revision: revision, Resource: target}, capacity)
}

func (m *FixedManager) ValidateIntent(spec NativeSpec, selection nodestorage.FixedSelection, prepared bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := NativeKey(spec)
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(fixedDeclaration{1, spec, selection})
	target := reconcile.Resource{Present: true, Generation: spec.Scope.Generation, Spec: string(raw)}
	s := r.State
	if m.validateRecord(key, r) != nil || !s.Desired.Present || s.Desired.Revision != 1 || s.Desired.Resource != target || s.GenerationFloor != target.Generation || s.LastID > 1 || s.Applied.Present && s.Applied != target || s.Pending != nil && (s.Pending.Kind != reconcile.Apply || s.Pending.ID != 1 || s.Pending.Target != target) {
		return ErrNativeVolume
	}
	if !prepared && (s.LastID != 0 || s.Pending != nil || s.Applied.Present) || prepared && s.LastID == 1 && s.Pending == nil && !s.Applied.Present {
		return ErrNativeVolume
	}
	return nil
}

func (m *FixedManager) openSource(ctx context.Context, key string, d fixedDeclaration, original *fixedCheckpoint) (*nodestorage.DirectoryHandle, nodestorage.RootPin, error) {
	root, err := m.authority(ctx, d.Selection.Root.Root)
	if err != nil {
		return nil, nodestorage.RootPin{}, err
	}
	if root.Reference(m.cluster) != d.Selection.Root.Root || root.Attestation == nil || root.Draining || root.Closed != nil || !slices.Contains(root.Definition.Tenants, d.Spec.Scope.Tenant) {
		return nil, nodestorage.RootPin{}, ErrNativeVolume
	}
	if original != nil {
		pin, ok, err := m.roots.RecordedPin(d.Selection.Root.Root, key)
		if err != nil || !ok || pin.Lease != original.RootLease {
			return nil, pin, errors.Join(ErrNativeVolume, err)
		}
	}
	if err = m.roots.Desired(root); err != nil {
		return nil, nodestorage.RootPin{}, err
	}
	pin, err := m.roots.Pin(ctx, root, key)
	if err != nil {
		return nil, pin, err
	}
	defer pin.Directory.Close()
	if original != nil && pin.Lease != original.RootLease {
		return nil, pin, ErrNativeVolume
	}
	leaf, err := nodestorage.OpenWithin(pin.Directory, d.Selection.Path)
	if err != nil {
		return nil, pin, err
	}
	if original != nil && !leaf.Identity().MatchesOriginal(original.Ready.Fixed.Directory) {
		_ = leaf.Close()
		return nil, pin, ErrNativeVolume
	}
	return leaf, pin, nil
}

func (m *FixedManager) returnRoot(d fixedDeclaration, expected *reconcile.Lease) error {
	pin, ok, err := m.roots.RecordedPin(d.Selection.Root.Root, NativeKey(d.Spec))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	} // authoritative same original root journal; previous exact return or no dispatch
	if expected != nil && pin.Lease != *expected {
		return ErrNativeVolume
	}
	return m.roots.Return(pin)
}

func (m *FixedManager) checkIdle(ctx context.Context, spec NativeSpec) error {
	listed, err := m.engine.API.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		return err
	}
	for _, summary := range listed.Items {
		got, err := m.engine.API.ContainerInspect(ctx, summary.ID, client.ContainerInspectOptions{})
		if cerrdefs.IsNotFound(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, binding := range got.Container.Mounts {
			if binding.Type == mount.TypeVolume && binding.Name == FixedNativeName(spec.Scope) || binding.Type == mount.TypeBind && filepath.Clean(binding.Source) == m.projector.sourcePath(spec) {
				return reconcile.ErrLease
			}
		}
	}
	return nil
}

func (m *FixedManager) cleanup(ctx context.Context, d fixedDeclaration, c *fixedCheckpoint) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if c == nil {
		if err := m.projector.recoverStaging(d.Spec); err != nil {
			return err
		}
		return m.returnRoot(d, nil)
	}
	if err := m.checkIdle(ctx, d.Spec); err != nil {
		return err
	}
	boot, ns, err := nodestorage.NativeContext()
	if err != nil {
		return err
	}
	if boot == c.Ready.Fixed.Directory.Boot && ns != c.Ready.Fixed.Directory.Namespace {
		return ErrNativeVolume
	}
	if err = m.projector.remove(d.Spec, c.Projection, c.Ready.Fixed.Directory, boot == c.Ready.Fixed.Directory.Boot); err != nil {
		return err
	}
	return m.returnRoot(d, &c.RootLease)
}

type fixedDriver struct {
	m        *FixedManager
	original *fixedCheckpoint
}

func (d fixedDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	decl, err := d.m.declaration(key, op.Target)
	if err != nil || op.Kind != reconcile.Remove {
		return reconcile.EffectUnknown, errors.Join(ErrNativeVolume, err)
	}
	if err = d.m.cleanup(ctx, decl, d.original); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

func (d fixedDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	decl, err := d.m.declaration(key, op.Target)
	if err != nil || op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errors.Join(ErrNativeVolume, err)
	}
	leaf, pin, err := d.m.openSource(ctx, key, decl, nil)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer leaf.Close()
	rootIdentity := pin.Directory.Identity() // the SAME retained root used for OpenWithin
	fixed := nodestorage.FixedDirectory{Root: decl.Selection.Root, RootDirectory: rootIdentity, Path: decl.Selection.Path, Directory: leaf.Identity()}
	ready := NativeReady{Schema: 1, Spec: decl.Spec, Generation: decl.Spec.Scope.Generation, Owner: Owner{Node: decl.Spec.Node, Key: decl.Spec.NodeKey, Native: FixedNativeName(decl.Spec.Scope)}, Fixed: &fixed}
	ready.Signature = ed25519.Sign(d.m.private, NativeReadyBytes(ready))
	if ready.Verify() != nil {
		return reconcile.EffectUnknown, ErrNativeVolume
	}
	owner, err := d.m.projector.stage(decl.Spec)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	c := fixedCheckpoint{Schema: 1, Ready: ready, RootLease: pin.Lease, Projection: owner}
	raw, _ := json.Marshal(c)
	if err = save(raw); err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = d.m.projector.ensure(decl.Spec, owner, leaf, leaf.Identity()); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

func (d fixedDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind == reconcile.Remove {
		return d.Execute(ctx, key, op)
	}
	decl, err := d.m.declaration(key, op.Target)
	if err != nil || op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errors.Join(ErrNativeVolume, err)
	}
	if d.original == nil {
		if err = d.m.cleanup(ctx, decl, nil); err != nil {
			return reconcile.EffectUnknown, err
		}
		return reconcile.EffectNotApplied, nil // no mount is dispatched before the original checkpoint
	}
	leaf, _, err := d.m.openSource(ctx, key, decl, d.original)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer leaf.Close()
	if err = d.m.projector.ensure(decl.Spec, d.original.Projection, leaf, d.original.Ready.Fixed.Directory); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

func (d fixedDriver) Retire(ctx context.Context, key string, op reconcile.Operation, receipt []byte, save func([]byte) error) (bool, error) {
	decl, err := d.m.declaration(key, op.Target)
	if err != nil || op.Kind != reconcile.Apply {
		return false, errors.Join(ErrNativeVolume, err)
	}
	err = d.m.cleanup(ctx, decl, d.original)
	return err == nil, err
}

func (m *FixedManager) Step(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	d := fixedDriver{m: m}
	if r.Checkpoint != nil {
		c, err := m.original(key, r)
		if err != nil {
			return err
		}
		d.original = &c
	}
	if r.State.Desired.Present && !r.State.Applied.Present && r.State.Pending == nil && r.State.LastID != 0 {
		return ErrNativeVolume
	}
	return m.journal.Step(ctx, key, d)
}

func (m *FixedManager) DeleteDesired(key string, revision, generation uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	if r.State.GenerationFloor != generation {
		return ErrNativeVolume
	}
	return m.journal.Desired(key, reconcile.Desired{Revision: revision, Retiring: generation}, r.Capacity)
}

func (m *FixedManager) ready(ctx context.Context, key string) (NativeReady, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return NativeReady{}, err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return NativeReady{}, reconcile.ErrPending
	}
	c, err := m.original(key, r)
	if err != nil {
		return NativeReady{}, err
	}
	d, err := m.declaration(key, r.State.Applied)
	if err != nil {
		return NativeReady{}, err
	}
	leaf, _, err := m.openSource(ctx, key, d, &c)
	if err != nil {
		return NativeReady{}, err
	}
	defer leaf.Close()
	if err = m.projector.ensure(d.Spec, c.Projection, leaf, c.Ready.Fixed.Directory); err != nil {
		return NativeReady{}, err
	}
	return c.Ready, nil
}

func (m *FixedManager) Ready(ctx context.Context, key string) (NativeReady, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready(ctx, key)
}
func (m *FixedManager) View(key string) (reconcile.Record, error) { return m.journal.Read(key) }
func (m *FixedManager) Keys() []string                            { return m.journal.Keys() }
func (m *FixedManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	return errors.Join(m.journal.Close(), m.projector.file.Close())
}

func (m *FixedManager) CheckSelection(spec NativeSpec, selection nodestorage.FixedSelection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := NativeKey(spec)
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(fixedDeclaration{1, spec, selection})
	target := reconcile.Resource{Generation: spec.Scope.Generation, Spec: string(raw), Present: true}
	if _, err = m.declaration(key, target); err != nil {
		return err
	}
	if r.State.GenerationFloor != spec.Scope.Generation {
		return ErrNativeVolume
	}
	for _, old := range []reconcile.Resource{r.State.Applied, r.State.Desired.Resource} {
		if old.Present && old != target {
			return ErrNativeVolume
		}
	}
	if r.State.Pending != nil && r.State.Pending.Target != target {
		return ErrNativeVolume
	}
	return m.validateRecord(key, r)
}

func (m *FixedManager) CheckOriginal(ready NativeReady) error {
	if ready.Verify() != nil || ready.Fixed == nil {
		return ErrNativeVolume
	}
	if err := m.CheckSelection(ready.Spec, ready.Fixed.Selection()); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(NativeKey(ready.Spec))
	if err != nil {
		return err
	}
	if r.Checkpoint == nil {
		if r.State.Applied.Present || r.State.Pending != nil || r.State.Desired.Present || r.State.Desired.Retiring != ready.Generation {
			return ErrNativeVolume
		}
		return nil
	}
	c, err := m.original(NativeKey(ready.Spec), r)
	if err != nil {
		return err
	}
	a, _ := json.Marshal(c.Ready)
	b, _ := json.Marshal(ready)
	if !bytes.Equal(a, b) {
		return ErrNativeVolume
	}
	return nil
}

func (m *FixedManager) Pin(ctx context.Context, key, consumer string, generation uint64) (NativeLease, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.ready(ctx, key)
	if err != nil || r.Generation != generation {
		return NativeLease{}, errors.Join(ErrNativeVolume, err)
	}
	pin, err := m.journal.Borrow(key, consumer, generation)
	if err != nil {
		return NativeLease{}, err
	}
	return NativeLease{Key: key, Consumer: consumer, Owner: r.Owner, Scope: r.Spec.Scope, Pin: pin}, nil
}

func (m *FixedManager) Return(l NativeLease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(l.Key)
	if err != nil {
		return err
	}
	c, err := m.original(l.Key, r)
	if err != nil || c.Ready.Owner != l.Owner || c.Ready.Spec.Scope != l.Scope {
		return errors.Join(ErrNativeVolume, err)
	}
	return m.journal.Return(l.Key, l.Consumer, l.Pin)
}

func (m *FixedManager) Gone(ctx context.Context, ready NativeReady, revision uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ready.Verify() != nil || ready.Fixed == nil || ready.Owner.Key != m.node {
		return false, ErrNativeVolume
	}
	return m.closedOriginal(ctx, ready.Spec, ready.Fixed.Selection(), revision)
}

func (m *FixedManager) Closed(ctx context.Context, spec NativeSpec, selection nodestorage.FixedSelection, revision uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.closedOriginal(ctx, spec, selection, revision)
}

func (m *FixedManager) closedOriginal(ctx context.Context, spec NativeSpec, selection nodestorage.FixedSelection, revision uint64) (bool, error) {
	raw, _ := json.Marshal(fixedDeclaration{1, spec, selection})
	key := NativeKey(spec)
	if _, err := m.declaration(key, reconcile.Resource{Generation: spec.Scope.Generation, Spec: string(raw), Present: true}); err != nil {
		return false, err
	}
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if revision == 0 || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || r.State.Desired.Revision < revision || r.State.Desired.Retiring != spec.Scope.Generation || r.State.GenerationFloor != spec.Scope.Generation || len(r.Consumers) != 0 {
		return false, reconcile.ErrPending
	}
	if err = m.checkIdle(ctx, spec); err != nil {
		return false, err
	}
	if err = m.projector.recoverStaging(spec); err != nil {
		return false, err
	}
	_, exists, err := m.roots.RecordedPin(selection.Root.Root, key)
	return err == nil && !exists, err
}

// CancelUndispatched requires a shared pre-dispatch producer proof at the
// caller. An empty local journal alone is never sufficient for a prepared job.
func (m *FixedManager) CancelUndispatched(ctx context.Context, spec NativeSpec, selection nodestorage.FixedSelection) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := NativeKey(spec)
	if _, err := m.journal.Read(key); !errors.Is(err, storage.ErrMissing) {
		return errors.Join(ErrNativeVolume, err)
	}
	raw, _ := json.Marshal(fixedDeclaration{1, spec, selection})
	decl, err := m.declaration(key, reconcile.Resource{Present: true, Generation: spec.Scope.Generation, Spec: string(raw)})
	if err != nil {
		return err
	}
	return m.cleanup(ctx, decl, nil)
}

// BindSource returns a held descriptor with the stable private path. The
// caller must compare Docker's actual namespace view before dispatching a
// bind effect, and retain its native lease until original Task/Wait closure.
func (m *FixedManager) BindSource(ctx context.Context, l NativeLease) (string, *nodestorage.DirectoryHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(l.Key)
	if err != nil || r.Consumers[l.Consumer] != l.Pin {
		return "", nil, errors.Join(ErrNativeVolume, err)
	}
	ready, err := m.ready(ctx, l.Key)
	if err != nil || ready.Owner != l.Owner || ready.Spec.Scope != l.Scope {
		return "", nil, errors.Join(ErrNativeVolume, err)
	}
	h, err := nodestorage.OpenDirectory(m.projector.sourcePath(ready.Spec))
	if err != nil {
		return "", nil, err
	}
	if !h.Identity().SameData(ready.Fixed.Directory) {
		_ = h.Close()
		return "", nil, ErrNativeVolume
	}
	return m.projector.sourcePath(ready.Spec), h, nil
}

// InspectBindSource observes an already borrowed original mount. Unlike
// BindSource it neither requests current creation authority nor repairs a
// projection. The durable root/Volume pins and actual data identity must hold.
func (m *FixedManager) InspectBindSource(ctx context.Context, l NativeLease) (string, *nodestorage.DirectoryHandle, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.journal.Read(l.Key)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.Consumers[l.Consumer] != l.Pin {
		return "", nil, errors.Join(ErrNativeVolume, err)
	}
	c, err := m.original(l.Key, row)
	if err != nil || c.Ready.Owner != l.Owner || c.Ready.Spec.Scope != l.Scope || l.Pin.Generation != c.Ready.Generation || l.Pin.Token == 0 {
		return "", nil, errors.Join(ErrNativeVolume, err)
	}
	pin, ok, err := m.roots.RecordedPin(c.Ready.Fixed.Selection().Root.Root, l.Key)
	if err != nil || !ok || pin.Lease != c.RootLease {
		return "", nil, errors.Join(ErrNativeVolume, err)
	}
	path := m.projector.sourcePath(c.Ready.Spec)
	h, err := nodestorage.OpenDirectory(path)
	if err != nil {
		return "", nil, err
	}
	if !h.Identity().SameData(c.Ready.Fixed.Directory) {
		_ = h.Close()
		return "", nil, ErrNativeVolume
	}
	if err := ctx.Err(); err != nil {
		_ = h.Close()
		return "", nil, err
	}
	return path, h, nil
}

// ServedSource opens the original directory of an applied fixed volume for a
// remote consumer that this home serves over SFCP VolumeFS. It takes no local
// pin: the remote consumer holds the Volume in Raft, and delete and move wait
// for it there. The caller keeps the handle for as long as it serves.
func (m *FixedManager) ServedSource(ctx context.Context, ready NativeReady) (*nodestorage.DirectoryHandle, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := NativeKey(ready.Spec)
	if !fixedNativeKey(key) {
		return nil, ErrNativeVolume
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.journal.Read(key)
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	c, err := m.original(key, row)
	if err != nil || c.Ready.Owner != ready.Owner || c.Ready.Spec.Scope != ready.Spec.Scope || c.Ready.Generation != ready.Generation {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	pin, ok, err := m.roots.RecordedPin(c.Ready.Fixed.Selection().Root.Root, key)
	if err != nil || !ok || pin.Lease != c.RootLease {
		return nil, errors.Join(ErrNativeVolume, err)
	}
	h, err := nodestorage.OpenDirectory(m.projector.sourcePath(c.Ready.Spec))
	if err != nil {
		return nil, err
	}
	if !h.Identity().SameData(c.Ready.Fixed.Directory) {
		_ = h.Close()
		return nil, ErrNativeVolume
	}
	return h, nil
}
