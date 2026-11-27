// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
)

func fixedNativeKey(key string) bool { return strings.HasPrefix(key, "fixed-volume/") }

// AttachFixed is Runtime assembly, before opening Activations or starting its
// module loop. Managed declarations/labels and fixed declarations remain
// strictly separate. Generic Desired must never create an external directory.
func (m *NativeManager) AttachFixed(f *FixedManager) error {
	if m == nil || f == nil || m.fixed != nil || f.engine != m.driver.engine || f.closed {
		return ErrNativeVolume
	}
	m.fixed = f
	return nil
}

// recordedOwner validates an immutable original declaration without observing
// paths or changing native state. Cleanup must keep working after ACL/Drain.
// A new Start separately calls Owner and the shared PermitAuthority.
func (m *NativeManager) recordedOwner(key string, target reconcile.Resource) (Owner, Scope, error) {
	if !fixedNativeKey(key) {
		spec, id, err := m.driver.parameters(key, reconcile.Operation{Kind: reconcile.Apply, Target: target})
		return Owner{Node: spec.Node, Key: spec.NodeKey, Native: id.Name}, spec.Scope, err
	}
	if m.fixed == nil {
		return Owner{}, Scope{}, ErrNativeVolume
	}
	m.fixed.mu.Lock()
	defer m.fixed.mu.Unlock()
	row, err := m.fixed.journal.Read(key)
	if err != nil || row.State.Applied != target || !target.Present {
		return Owner{}, Scope{}, errors.Join(ErrNativeVolume, err)
	}
	checkpoint, err := m.fixed.original(key, row)
	return checkpoint.Ready.Owner, checkpoint.Ready.Spec.Scope, err
}

// MountSource is only the recorded Docker source, never a native readiness or
// writer permission. The fixed path belongs to the daemon's private projection;
// callers cannot supply host paths. Dispatch additionally holds/validates the
// original local lease and checks the Engine peer's actual namespace view.
func (m *NativeManager) MountSource(key string, scope Scope, owner Owner, generation uint64, binding string) (string, bool, error) {
	row, err := m.View(key)
	if err != nil || !row.State.Applied.Present || row.State.Applied.Generation != generation {
		return "", false, errors.Join(ErrNativeVolume, err)
	}
	actual, actualScope, err := m.recordedOwner(key, row.State.Applied)
	if err != nil || actual != owner || actualScope != scope {
		return "", false, errors.Join(ErrNativeVolume, err)
	}
	if fixedNativeKey(key) {
		m.fixed.mu.Lock()
		defer m.fixed.mu.Unlock()
		original, err := m.fixed.original(key, row)
		digest := NativeBindingDigest(original.Ready)
		if err != nil || binding != hex.EncodeToString(digest[:]) {
			return "", false, errors.Join(ErrNativeVolume, err)
		}
		// The engine mounts fixed volumes through its "sfc" driver by this
		// name; the Mount answer hands over the held projection directory.
		return FixedNativeName(scope), true, nil
	}
	if binding != "" {
		return "", false, ErrNativeVolume
	}
	return owner.Native, false, nil
}

func (m *FixedManager) CheckIdle(ctx context.Context, ready NativeReady) error {
	if err := m.CheckOriginal(ready); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	row, err := m.journal.Read(NativeKey(ready.Spec))
	if err != nil || row.State.Pending != nil || !row.State.Applied.Present || row.State.Applied != row.State.Desired.Resource || len(row.Consumers) != 0 {
		return errors.Join(ErrNativeVolume, err)
	}
	if _, err = m.ready(ctx, NativeKey(ready.Spec)); err != nil {
		return err
	}
	return m.checkIdle(ctx, ready.Spec)
}
