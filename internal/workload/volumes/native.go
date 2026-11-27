// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/storage"
	"github.com/moby/moby/api/types/volume"
	"github.com/moby/moby/client"
)

var ErrNativeVolume = errors.New("managed local volume unavailable or inconsistent")

// NativeSpec describes one physical materialization, independently of the
// logical volume generation. Reverse migration must use a new materialization.
// Capacity/quota and shared writer authority are not inferred from its creation.
type NativeSpec struct {
	Schema          uint8
	Scope           Scope
	Node            string
	NodeKey         [32]byte
	Materialization string
	UID, GID, Mode  uint32
	Retain          bool
	Kind            string `json:",omitempty"`
	FixedDigest     string `json:",omitempty"`
}

func (s NativeSpec) Validate() error {
	raw, err := json.Marshal(s)
	if err != nil {
		return ErrNativeVolume
	}
	if s.Kind == "node-fixed" {
		digest, e := hex.DecodeString(s.FixedDigest)
		if e != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != s.FixedDigest || s.Schema != 1 || !validScope(s.Scope) || !s.Scope.TenantManaged() || !identifier(s.Node) || s.NodeKey == ([32]byte{}) || s.Materialization != "" || s.UID != 0 || s.GID != 0 || s.Mode != 0 || !s.Retain {
			return ErrNativeVolume
		}
		return nil
	}
	_, err = decodeNative(string(raw))
	return err
}

func NativeKey(s NativeSpec) string {
	if s.Kind == "node-fixed" {
		return FixedNativeKey(s.Scope)
	}
	return "volume/" + s.Scope.Key() + "/" + s.Materialization
}

func decodeNative(raw string) (NativeSpec, error) {
	s, err := schema.Decode[NativeSpec]([]byte(raw))
	if err != nil || s.Kind != "" || s.FixedDigest != "" || s.Schema != 1 || !validScope(s.Scope) || s.Scope.TenantManaged() || !identifier(s.Node) || s.NodeKey == ([32]byte{}) || !identifier(s.Materialization) || !s.Retain || s.UID == 0 || s.GID == 0 || s.UID == ^uint32(0) || s.GID == ^uint32(0) || s.Mode&0700 != 0700 || s.Mode&^uint32(0770) != 0 {
		return s, ErrNativeVolume
	}
	return s, nil
}

type nativeDriver struct{ engine *engine.Client }

func (d nativeDriver) parameters(key string, op reconcile.Operation) (NativeSpec, engine.Identity, error) {
	s, err := decodeNative(op.Target.Spec)
	if err != nil || key != NativeKey(s) || d.engine == nil || d.engine.Owner != engine.Owner(s.Scope.Cluster, s.NodeKey) || !op.Target.Present || op.Target.Generation == 0 || op.Kind != reconcile.Apply && op.Kind != reconcile.Remove {
		return s, engine.Identity{}, ErrNativeVolume
	}
	id, err := d.engine.Identity("volume", key, op.Target)
	return s, id, err
}
func matchNative(v volume.Volume, id engine.Identity) bool {
	return id.Matches(v.Name, v.Labels) && v.Driver == "local" && v.Scope == "local" && len(v.Options) == 0 && v.ClusterVolume == nil && filepath.IsAbs(v.Mountpoint) && filepath.Clean(v.Mountpoint) == v.Mountpoint
}

// The Engine is an explicit local UDS. Only its inspected local-driver root is
// opened; callers never supply host paths. Initial permission preparation is
// restricted to an empty original materialization. Published data is immutable
// to the manager: inspection must fail rather than chmod/chown it into shape.
func nativeDirectory(v volume.Volume, s NativeSpec, prepare bool) error {
	canonical, err := filepath.EvalSymlinks(v.Mountpoint)
	if err != nil || canonical != v.Mountpoint {
		return ErrNativeVolume
	}
	before, err := os.Lstat(v.Mountpoint)
	if err != nil || !before.IsDir() {
		return ErrNativeVolume
	}
	r, err := os.OpenRoot(v.Mountpoint)
	if err != nil {
		return ErrNativeVolume
	}
	defer r.Close()
	f, err := r.Open(".")
	if err != nil {
		return ErrNativeVolume
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return ErrNativeVolume
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrNativeVolume
	}
	if st.Uid == s.UID && st.Gid == s.GID && st.Mode&07777 == s.Mode {
		if prepare && f.Sync() != nil {
			return ErrNativeVolume
		}
		return nil
	}
	if !prepare || st.Uid != 0 && st.Uid != s.UID || st.Gid != 0 && st.Gid != s.GID || st.Mode&07777 != 0755 && st.Mode&07777 != s.Mode {
		return ErrNativeVolume
	}
	entries, err := f.ReadDir(1)
	if !errors.Is(err, io.EOF) || len(entries) != 0 {
		return ErrNativeVolume
	}
	if r.Chown(".", int(s.UID), int(s.GID)) != nil || r.Chmod(".", os.FileMode(s.Mode)) != nil || f.Sync() != nil {
		return ErrNativeVolume
	}
	return nativeDirectory(v, s, false)
}

func (d nativeDriver) inspect(ctx context.Context, key string, op reconcile.Operation, prepare bool) (reconcile.Outcome, error) {
	s, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	got, err := d.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if cerrdefs.IsNotFound(err) {
		if op.Kind == reconcile.Remove {
			return reconcile.EffectApplied, nil
		}
		return reconcile.EffectUnknown, nil
	}
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	if !matchNative(got.Volume, id) {
		return reconcile.EffectUnknown, engine.ErrOwnership
	}
	if op.Kind == reconcile.Remove {
		return reconcile.EffectUnknown, nil
	}
	if err = nativeDirectory(got.Volume, s, prepare); err != nil {
		return reconcile.EffectUnknown, err
	}
	return reconcile.EffectApplied, nil
}
func (d nativeDriver) Execute(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	_, id, err := d.parameters(key, op)
	if err != nil {
		return reconcile.EffectNotApplied, err
	}
	got, err := d.engine.API.VolumeInspect(ctx, id.Name, client.VolumeInspectOptions{})
	if err != nil && !cerrdefs.IsNotFound(err) {
		if op.Kind == reconcile.Apply {
			return reconcile.EffectNotApplied, err
		}
		return reconcile.EffectUnknown, err
	}
	if err == nil && !matchNative(got.Volume, id) {
		// This fresh Apply has not called Create or touched permissions.
		// Recover has a different rule: its original call may have executed.
		if op.Kind == reconcile.Apply {
			return reconcile.EffectNotApplied, engine.ErrOwnership
		}
		return reconcile.EffectUnknown, engine.ErrOwnership
	}
	if op.Kind == reconcile.Remove {
		if cerrdefs.IsNotFound(err) {
			return reconcile.EffectApplied, nil
		}
		if _, err = d.engine.API.VolumeRemove(ctx, id.Name, client.VolumeRemoveOptions{}); err != nil {
			return reconcile.EffectUnknown, err
		}
		return d.inspect(ctx, key, op, false)
	}
	if cerrdefs.IsNotFound(err) {
		if err = ctx.Err(); err != nil {
			return reconcile.EffectNotApplied, err
		}
		if _, err = d.engine.API.VolumeCreate(ctx, client.VolumeCreateOptions{Name: id.Name, Driver: "local", Labels: id.Labels}); err != nil {
			return reconcile.EffectUnknown, err
		}
	}
	return d.inspect(ctx, key, op, true)
}
func (d nativeDriver) Recover(ctx context.Context, key string, op reconcile.Operation) (reconcile.Outcome, error) {
	// Continue only the original, positively matched Remove. Its journal
	// prevents this physical identity's reuse until removal is settled.
	if op.Kind == reconcile.Remove {
		return d.Execute(ctx, key, op)
	}
	return d.inspect(ctx, key, op, true)
}

// NativeManager owns the local A2/A3 materialization journal. Its Desired and
// DeleteDesired inputs must already be committed management intent. Close/down
// do not delete a retained volume. Local pins do not authorize a writer Start.
type NativeManager struct {
	journal      *reconcile.Journal
	driver       nativeDriver
	declarations sync.Map // per-key guards across retained-check + Desired sync
	archiveIO    archiveFiles
	// Attached once during Runtime assembly, before any consumer runs. Runtime
	// owns its lifetime; this manager does not close the fixed adapter.
	fixed *FixedManager
}

func (m *NativeManager) declaration(key string) *sync.Mutex {
	v, _ := m.declarations.LoadOrStore(key, new(sync.Mutex))
	return v.(*sync.Mutex)
}

func OpenNative(path string, c *engine.Client) (*NativeManager, error) {
	if c == nil || c.API == nil {
		return nil, ErrNativeVolume
	}
	j, err := reconcile.OpenJournal(path)
	if err != nil {
		return nil, err
	}
	m := &NativeManager{journal: j, driver: nativeDriver{c}, archiveIO: systemArchiveFiles()}
	for _, key := range j.Keys() {
		r, e := j.Read(key)
		if e != nil {
			_ = j.Close()
			return nil, e
		}
		for _, target := range []reconcile.Resource{r.State.Desired.Resource, r.State.Applied} {
			if target.Present {
				if _, _, e = m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: target}); e != nil {
					_ = j.Close()
					return nil, e
				}
			}
		}
		if r.State.Pending != nil {
			if _, _, e = m.driver.parameters(key, *r.State.Pending); e != nil {
				_ = j.Close()
				return nil, e
			}
		}
	}
	return m, nil
}
func (m *NativeManager) Desired(s NativeSpec, revision, generation uint64, capacity int) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	key := NativeKey(s)
	target := reconcile.Resource{Generation: generation, Spec: string(raw), Present: true}
	if _, _, err = m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: target}); err != nil {
		return key, err
	}
	guard := m.declaration(key)
	guard.Lock()
	defer guard.Unlock()
	old, readErr := m.journal.Read(key)
	if readErr != nil && !errors.Is(readErr, storage.ErrMissing) {
		return key, readErr
	}
	if readErr == nil {
		// A retained physical volume is never replaced by generic A2's
		// Remove-old/Apply-new plan. Replacement needs a fresh materialization.
		for _, resource := range []reconcile.Resource{old.State.Desired.Resource, old.State.Applied} {
			if resource.Present && resource != target {
				return key, ErrNativeVolume
			}
		}
		if old.State.Pending != nil && old.State.Pending.Target != target {
			return key, ErrNativeVolume
		}
	}
	return key, m.journal.Desired(key, reconcile.Desired{Revision: revision, Resource: target}, capacity)
}
func (m *NativeManager) DeleteDesired(key string, revision, generation uint64) error {
	guard := m.declaration(key)
	guard.Lock()
	defer guard.Unlock()
	r, err := m.journal.Read(key)
	if err != nil {
		return err
	}
	return m.journal.Desired(key, reconcile.Desired{Revision: revision, Retiring: generation}, r.Capacity)
}
func (m *NativeManager) Step(ctx context.Context, key string) error {
	return m.journal.Step(ctx, key, m.driver)
}
func (m *NativeManager) View(key string) (reconcile.Record, error) {
	if fixedNativeKey(key) {
		if m.fixed == nil {
			return reconcile.Record{}, ErrNativeVolume
		}
		return m.fixed.View(key)
	}
	return m.journal.Read(key)
}
func (m *NativeManager) Keys() []string {
	keys := m.journal.Keys()
	if m.fixed != nil {
		keys = append(keys, m.fixed.Keys()...)
	}
	return keys
}
func (m *NativeManager) Close() error { return m.journal.Close() }

func (m *NativeManager) Gone(ctx context.Context, key string, revision, generation uint64) (bool, error) {
	r, err := m.journal.Read(key)
	if err != nil {
		return false, err
	}
	if revision == 0 || generation == 0 || r.State.Desired.Revision < revision || r.State.GenerationFloor != generation || r.State.Pending != nil || r.State.Applied.Present || r.State.Desired.Present || len(r.Consumers) != 0 {
		return false, nil
	}
	return m.driver.engine.Gone(ctx, "volume", key)
}

// UnrecordedAbsent observes only an exact native key with no intent in this
// intact journal. It is NOT closure of an Unknown Create. A caller must first
// join its submitting worker and forbid further dispatch under current control
// authority. Recorded operations always use their original retirement/Gone.
func (m *NativeManager) UnrecordedAbsent(ctx context.Context, spec NativeSpec, generation uint64) (bool, error) {
	raw, err := json.Marshal(spec)
	if err != nil || generation == 0 {
		return false, ErrNativeVolume
	}
	key := NativeKey(spec)
	if _, _, err = m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: reconcile.Resource{Present: true, Generation: generation, Spec: string(raw)}}); err != nil {
		return false, err
	}
	if _, err = m.journal.Read(key); !errors.Is(err, storage.ErrMissing) {
		return false, errors.Join(reconcile.ErrPending, err)
	}
	return m.driver.engine.Gone(ctx, "volume", key)
}

type NativeLease struct {
	Key, Consumer string
	Owner         Owner
	Scope         Scope
	Pin           reconcile.Lease
}

func (m *NativeManager) inspect(ctx context.Context, key string, r reconcile.Resource) (Owner, Scope, error) {
	if fixedNativeKey(key) {
		if m.fixed == nil {
			return Owner{}, Scope{}, ErrNativeVolume
		}
		row, err := m.fixed.View(key)
		if err != nil || row.State.Applied != r {
			return Owner{}, Scope{}, errors.Join(ErrNativeVolume, err)
		}
		ready, err := m.fixed.Ready(ctx, key)
		return ready.Owner, ready.Spec.Scope, err
	}
	s, id, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: r})
	if err != nil {
		return Owner{}, Scope{}, err
	}
	outcome, err := m.driver.inspect(ctx, key, reconcile.Operation{Kind: reconcile.Apply, Target: r}, false)
	if err != nil || outcome != reconcile.EffectApplied {
		return Owner{}, Scope{}, errors.Join(ErrNativeVolume, err)
	}
	return Owner{Node: s.Node, Key: s.NodeKey, Native: id.Name}, s.Scope, nil
}
func (m *NativeManager) Owner(ctx context.Context, key string) (Owner, Scope, error) {
	r, err := m.View(key)
	if err != nil {
		return Owner{}, Scope{}, err
	}
	if r.State.Pending != nil || !r.State.Applied.Present || r.State.Applied != r.State.Desired.Resource {
		return Owner{}, Scope{}, reconcile.ErrPending
	}
	return m.inspect(ctx, key, r.State.Applied)
}
func (m *NativeManager) Pin(ctx context.Context, key, consumer string, generation uint64) (NativeLease, error) {
	if fixedNativeKey(key) {
		if m.fixed == nil {
			return NativeLease{}, ErrNativeVolume
		}
		return m.fixed.Pin(ctx, key, consumer, generation)
	}
	pin, err := m.journal.Borrow(key, consumer, generation)
	if err != nil {
		return NativeLease{}, err
	}
	r, err := m.journal.Read(key)
	if err != nil {
		return NativeLease{}, err
	}
	owner, scope, err := m.inspect(ctx, key, r.State.Applied)
	return NativeLease{key, consumer, owner, scope, pin}, err
}

// Return is called only after the original native consumer's positive closure.
func (m *NativeManager) Return(l NativeLease) error {
	if fixedNativeKey(l.Key) {
		if m.fixed == nil {
			return ErrNativeVolume
		}
		return m.fixed.Return(l)
	}
	r, err := m.journal.Read(l.Key)
	if err != nil {
		return err
	}
	pin, exists := r.Consumers[l.Consumer]
	if !exists {
		return nil
	}
	if pin != l.Pin {
		return reconcile.ErrLease
	}
	s, id, err := m.driver.parameters(l.Key, reconcile.Operation{Kind: reconcile.Apply, Target: r.State.Applied})
	if err != nil || l.Scope != s.Scope || l.Owner != (Owner{Node: s.Node, Key: s.NodeKey, Native: id.Name}) {
		return ErrNativeVolume
	}
	return m.journal.Return(l.Key, l.Consumer, l.Pin)
}
