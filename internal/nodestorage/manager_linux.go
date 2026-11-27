// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
)

// RootManager records native directory registration in the SAME A2 journal
// used by other local resources. It never creates, chmods, mounts or deletes a
// declared storage directory. Shared/current permission is the caller's job;
// a signed registration fact alone is never a Start permit.
type RootManager struct {
	mu              sync.Mutex
	journal         *reconcile.Journal
	cluster, public [32]byte
	node            string
	private         ed25519.PrivateKey
}

func RootNativeKey(r Reference) string { return "node-storage/" + r.Node + "/" + r.ID }

func OpenRoots(path string, cluster [32]byte, node string, key ed25519.PrivateKey) (*RootManager, error) {
	if cluster == ([32]byte{}) || !identifier(node) || len(key) != ed25519.PrivateKeySize {
		return nil, ErrStorage
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	m := &RootManager{journal: j, cluster: cluster, node: node, private: bytes.Clone(key), public: [32]byte(key.Public().(ed25519.PublicKey))}
	// An unrelated resource or foreign node journal cannot be adopted just
	// because a path supplied by a caller happens to contain valid JSON.
	for _, key := range j.Keys() {
		r, readErr := j.Read(key)
		if readErr != nil {
			_ = j.Close()
			return nil, readErr
		}
		for _, target := range []reconcile.Resource{r.State.Desired.Resource, r.State.Applied} {
			if target.Present {
				if _, e := m.reference(key, target); e != nil {
					_ = j.Close()
					return nil, e
				}
			}
		}
		if op := r.State.Pending; op != nil {
			if _, e := m.reference(key, op.Target); e != nil {
				_ = j.Close()
				return nil, e
			}
		}
		if r.Checkpoint != nil {
			if _, e := m.original(key, r); e != nil {
				_ = j.Close()
				return nil, e
			}
		}
		if !validRootNativeKey(key, node) {
			_ = j.Close()
			return nil, ErrStorage
		}
	}
	return m, nil
}

func validRootNativeKey(key, node string) bool {
	prefix := "node-storage/" + node + "/"
	return len(key) > len(prefix) && key[:len(prefix)] == prefix && identifier(key[len(prefix):])
}

func (m *RootManager) reference(key string, target reconcile.Resource) (Reference, error) {
	r, err := schema.Decode[Reference]([]byte(target.Spec))
	if err != nil || r.Validate() != nil || r.Cluster != m.cluster || r.Node != m.node || r.Key != m.public || key != RootNativeKey(r) || !target.Present || target.Generation != r.Generation {
		return r, ErrStorage
	}
	raw, err := json.Marshal(r)
	if err != nil || string(raw) != target.Spec {
		return r, ErrStorage
	}
	return r, nil
}

func (m *RootManager) original(key string, r reconcile.Record) (RootFact, error) {
	if r.Checkpoint == nil {
		return RootFact{}, ErrStorage
	}
	f, err := schema.Decode[RootFact](r.Checkpoint.Data)
	ref, refErr := m.reference(key, r.Checkpoint.Target)
	raw, marshalErr := json.Marshal(f)
	if err != nil || refErr != nil || marshalErr != nil || !bytes.Equal(raw, r.Checkpoint.Data) || f.Verify() != nil || f.Root != ref {
		return RootFact{}, ErrStorage
	}
	return f, nil
}

// Desired consumes a committed root, not a user path. Losing an already
// attested registration's local checkpoint requires explicit journal recovery;
// it must not silently re-register whatever now occupies that pathname.
func (m *RootManager) Desired(root Root) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := root.Reference(m.cluster)
	raw, err := json.Marshal(ref)
	if err != nil || ref.Validate() != nil || ref.Node != m.node || ref.Key != m.public || root.Revision == 0 || !validDefinition(root.Definition) {
		return ErrStorage
	}
	key := RootNativeKey(ref)
	r, readErr := m.journal.Read(key)
	if readErr != nil && !errors.Is(readErr, storage.ErrMissing) {
		return readErr
	}
	if root.Attestation != nil {
		if root.Attestation.Verify() != nil || root.Attestation.Root != ref {
			return ErrStorage
		}
		closedLocally := root.Draining && readErr == nil && r.State.Pending == nil && !r.State.Applied.Present && !r.State.Desired.Present && r.State.Desired.Retiring == ref.Generation
		f, e := m.original(key, r)
		if !closedLocally && (e != nil || !bytes.Equal(RootFactBytes(f), RootFactBytes(*root.Attestation))) {
			return ErrStorage
		}
	}
	if r.State.Desired.Present && r.State.Desired.Generation == ref.Generation && r.State.Desired.Spec != string(raw) {
		return ErrStorage
	}
	if root.Draining {
		return m.journal.Desired(key, reconcile.Desired{Revision: root.Revision, Retiring: ref.Generation}, RootPinCapacity)
	}
	if root.Closed != nil {
		return ErrStorage
	}
	return m.journal.Desired(key, reconcile.Desired{Revision: root.Revision, Resource: reconcile.Resource{Generation: ref.Generation, Spec: string(raw), Present: true}}, RootPinCapacity)
}

type rootDriver struct {
	m        *RootManager
	original *RootFact
}

func (d rootDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.EffectUnknown, err
	}
	if _, err := d.m.reference(key, op.Target); err != nil {
		return reconcile.EffectUnknown, err
	}
	if op.Kind != reconcile.Remove {
		return reconcile.EffectUnknown, ErrStorage
	}
	// Registration has no external persistent object. A2 has already
	// drained and checked all root pins before dispatching this Remove.
	return reconcile.EffectApplied, nil
}

func (d rootDriver) ExecuteCheckpoint(ctx context.Context, key string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.EffectUnknown, err
	}
	ref, err := d.m.reference(key, op.Target)
	if err != nil || op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errors.Join(ErrStorage, err)
	}
	h, err := OpenDirectory(ref.Path)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer h.Close()
	f := RootFact{Schema: 1, Root: ref, Directory: h.Identity()}
	f.Signature = ed25519.Sign(d.m.private, RootFactBytes(f))
	raw, err := json.Marshal(f)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if err = save(raw); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}

func (d rootDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	if op.Kind == reconcile.Remove {
		return d.Execute(ctx, key, op)
	}
	if err := ctx.Err(); err != nil {
		return reconcile.EffectUnknown, err
	}
	ref, err := d.m.reference(key, op.Target)
	if err != nil || op.Kind != reconcile.Apply {
		return reconcile.EffectUnknown, errors.Join(ErrStorage, err)
	}
	if d.original == nil {
		// Execute only opens/reads the original directory BEFORE save. No
		// native effect or published fact exists without that checkpoint.
		// Replan rather than inventing a recovery checkpoint or identity.
		return reconcile.EffectNotApplied, nil
	}
	if d.original.Root != ref {
		return reconcile.EffectUnknown, ErrStorage
	}
	h, err := OpenDirectory(ref.Path)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	defer h.Close()
	if !h.Identity().MatchesOriginal(d.original.Directory) {
		return reconcile.EffectUnknown, ErrStorage
	}
	return reconcile.EffectApplied, nil
}

// Retire closes an obsolete readonly registration, without adopting the
// replacement path and without touching any source data. A2 gates all pins.
func (d rootDriver) Retire(ctx context.Context, key string, op reconcile.Operation, receipt []byte, save func([]byte) error) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := d.m.reference(key, op.Target)
	return err == nil && op.Kind == reconcile.Apply, err
}

// Settled observes a previously registered root without granting new work.
// A changed or unresolved desired state must take the caller's current permit
// path. A settled journal still needs the actual original inode on each read.
func (m *RootManager) Settled(ctx context.Context, root Root) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if root.Attestation == nil || root.Draining || root.Closed != nil {
		return false, nil
	}
	ref := root.Reference(m.cluster)
	if ref.Validate() != nil || ref.Node != m.node || ref.Key != m.public {
		return false, ErrStorage
	}
	row, err := m.journal.Read(RootNativeKey(ref))
	if errors.Is(err, storage.ErrMissing) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !settledRootRecord(root, row) {
		return false, nil
	}
	_, err = m.fact(ctx, root)
	return err == nil, err
}

func settledRootRecord(root Root, row reconcile.Record) bool {
	s := row.State
	return root.Attestation != nil && !root.Draining && root.Closed == nil && s.Pending == nil && !s.Stopped && s.Applied.Present && s.Applied == s.Desired.Resource && s.Desired.Revision == root.Revision
}

func (m *RootManager) Step(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	d := rootDriver{m: m}
	if r.Checkpoint != nil {
		f, err := m.original(key, r)
		if err != nil {
			return err
		}
		d.original = &f
	}
	return m.journal.Step(ctx, key, d)
}

func (m *RootManager) fact(ctx context.Context, root Root) (RootFact, error) {
	if err := ctx.Err(); err != nil {
		return RootFact{}, err
	}
	ref := root.Reference(m.cluster)
	r, err := m.journal.Read(RootNativeKey(ref))
	if err != nil || root.Draining || root.Closed != nil || r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource || r.State.Desired.Revision != root.Revision {
		return RootFact{}, errors.Join(ErrStorage, err)
	}
	f, err := m.original(RootNativeKey(ref), r)
	if err != nil || f.Root != ref {
		return RootFact{}, errors.Join(ErrStorage, err)
	}
	if root.Attestation != nil && (root.Attestation.Verify() != nil || !bytes.Equal(RootFactBytes(f), RootFactBytes(*root.Attestation))) {
		return RootFact{}, ErrStorage
	}
	h, err := OpenDirectory(ref.Path)
	if err != nil {
		return RootFact{}, err
	}
	defer h.Close()
	if !h.Identity().MatchesOriginal(f.Directory) {
		return RootFact{}, ErrStorage
	}
	return ownFact(f), nil
}

// Fact reopens and verifies the original native inode on every observation;
// reading a durable initial fact alone is deliberately insufficient.
func (m *RootManager) Fact(ctx context.Context, root Root) (RootFact, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fact(ctx, root)
}

// RootPin is a durable native dependency, not the shared Volume writer lease.
// Return requires the consumer's positive native closure, including Wait and
// projection unmount. Close only closes this process's directory descriptor.
type RootPin struct {
	Root      Reference
	Consumer  string
	Lease     reconcile.Lease
	Directory *DirectoryHandle
}

func (m *RootManager) Pin(ctx context.Context, root Root, consumer string) (RootPin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := m.fact(ctx, root)
	if err != nil {
		return RootPin{}, err
	}
	key := RootNativeKey(f.Root)
	pin, err := m.journal.Borrow(key, consumer, f.Root.Generation)
	if err != nil {
		return RootPin{}, err
	}
	result := RootPin{Root: f.Root, Consumer: consumer, Lease: pin}
	h, err := OpenDirectory(f.Root.Path)
	if err != nil {
		return result, err
	}
	if !h.Identity().MatchesOriginal(f.Directory) {
		_ = h.Close()
		return result, ErrStorage
	}
	result.Directory = h
	// If the open fails, retain and return the original durable pin. The
	// caller must settle its native work before returning it; no rollback
	// guesses that a previous idempotent borrow had no external users.
	return result, nil
}

func (m *RootManager) Return(p RootPin) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.Root.Validate() != nil || p.Root.Cluster != m.cluster || p.Root.Node != m.node || p.Root.Key != m.public || p.Lease.Generation != p.Root.Generation {
		return ErrStorage
	}
	return m.journal.Return(RootNativeKey(p.Root), p.Consumer, p.Lease)
}

// RecordedPin inspects this module's durable original dependency. A missing
// root journal is NOT evidence of no pin. Cleanup may inspect a drained root
// without reopening a missing/replaced data path; it still verifies its exact
// reference/generation and checkpoint or completed original tombstone.
func (m *RootManager) RecordedPin(ref Reference, consumer string) (RootPin, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.recordedPin(ref, consumer)
}
func (m *RootManager) recordedPin(ref Reference, consumer string) (RootPin, bool, error) {
	if ref.Validate() != nil || ref.Cluster != m.cluster || ref.Node != m.node || ref.Key != m.public || consumer == "" {
		return RootPin{}, false, ErrStorage
	}
	r, err := m.journal.Read(RootNativeKey(ref))
	if err != nil {
		return RootPin{}, false, err
	}
	if r.State.GenerationFloor != ref.Generation {
		return RootPin{}, false, ErrStorage
	}
	if r.Checkpoint != nil {
		f, err := m.original(RootNativeKey(ref), r)
		if err != nil || f.Root != ref {
			return RootPin{}, false, errors.Join(ErrStorage, err)
		}
	} else if r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || r.State.Desired.Retiring != ref.Generation {
		return RootPin{}, false, ErrStorage
	}
	lease, ok := r.Consumers[consumer]
	if !ok {
		return RootPin{}, false, nil
	}
	if lease.Generation != ref.Generation || lease.Token == 0 {
		return RootPin{}, false, ErrStorage
	}
	return RootPin{Root: ref, Consumer: consumer, Lease: lease}, true, nil
}

// OpenRecordedPin reopens only an already held original dependency. It does
// not borrow a new consumer or materialize a root while that root is draining.
func (m *RootManager) OpenRecordedPin(ref Reference, consumer string) (RootPin, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pin, ok, err := m.recordedPin(ref, consumer)
	if err != nil || !ok {
		return pin, errors.Join(ErrStorage, err)
	}
	record, err := m.journal.Read(RootNativeKey(ref))
	if err != nil {
		return pin, err
	}
	fact, err := m.original(RootNativeKey(ref), record)
	if err != nil || fact.Root != ref {
		return pin, errors.Join(ErrStorage, err)
	}
	handle, err := OpenDirectory(ref.Path)
	if err != nil {
		return pin, err
	}
	if !handle.Identity().MatchesOriginal(fact.Directory) {
		_ = handle.Close()
		return pin, ErrStorage
	}
	pin.Directory = handle
	return pin, nil
}

func (m *RootManager) Closed(root Root) (RootClosed, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ref := root.Reference(m.cluster)
	if !root.Draining || ref.Validate() != nil || ref.Node != m.node || ref.Key != m.public {
		return RootClosed{}, ErrStorage
	}
	r, err := m.journal.Read(RootNativeKey(ref))
	if err != nil || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || r.State.Desired.Retiring != ref.Generation || r.State.Desired.Revision != root.Revision || len(r.Consumers) != 0 {
		return RootClosed{}, errors.Join(ErrStorage, err)
	}
	f := RootClosed{Schema: 1, Root: ref, NoUsers: true, NoPending: true}
	f.Signature = ed25519.Sign(m.private, RootClosedBytes(f))
	return f, f.Verify()
}

func (m *RootManager) View(key string) (reconcile.Record, error) { return m.journal.Read(key) }
func (m *RootManager) Keys() []string                            { return m.journal.Keys() }
func (m *RootManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.journal.Close()
}
