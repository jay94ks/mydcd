// SPDX-License-Identifier: Apache-2.0

package ingress

// NativeSource reads the node's original source, not a replacement inferred
// from shared Desired. An owner verifies it against its exact original claim.
func (m *Manager) NativeSource(key string, generation uint64) (Spec, string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.instances[key]
	if i == nil || m.closed {
		return Spec{}, "", false
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.record.Generation != generation || i.record.Gone {
		return Spec{}, "", false
	}
	return i.copyRecord().Spec, i.record.Native, true
}

// BindNative is write-once for one original generation. It cannot select a
// different source, change a generation or manufacture a native operation.
func (m *Manager) BindNative(key string, generation uint64, native string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.instances[key]
	if i == nil || m.closed || native == "" || len(native) > 256 {
		return ErrRoute
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.record.Generation != generation || i.record.Gone {
		return ErrRoute
	}
	if i.record.Native != "" {
		if i.record.Native != native {
			return ErrRoute
		}
		return nil
	}
	r := i.copyRecord()
	r.Native = native
	return i.save(r)
}
