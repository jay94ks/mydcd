// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"

	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// Usage reuses the bounded live scanner. It grants neither a writer nor a
// backup: the original source remains pinned by its registration, the adapter
// lock excludes unregister, and current source identity is checked both sides.
func (m *FixedManager) Usage(ctx context.Context, key string, limits UsageLimits) (Usage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ready, err := m.ready(ctx, key)
	if err != nil {
		return Usage{}, err
	}
	source := m.projector.sourcePath(ready.Spec)
	h, err := nodestorage.OpenDirectory(source)
	if err != nil {
		return Usage{}, err
	}
	defer h.Close()
	if !h.Identity().SameData(ready.Fixed.Directory) {
		return Usage{}, ErrNativeVolume
	}
	value, err := scanUsage(ctx, source, limits)
	if err != nil {
		return Usage{}, err
	}
	after, err := m.ready(ctx, key)
	if err != nil || !after.Fixed.Directory.SameData(ready.Fixed.Directory) {
		return Usage{}, errors.Join(ErrNativeVolume, err)
	}
	value.Scope, value.Owner, value.Generation = ready.Spec.Scope, ready.Owner, ready.Generation
	return value, nil
}
