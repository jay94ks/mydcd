// SPDX-License-Identifier: Apache-2.0

package remote

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"

	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/volumeshare"
	"github.com/jay94ks/seafield/internal/volumeshare/back/localroot"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Grant says whether peer may mount ref now (control.Policy
// VolumeRemoteGrant on a current read) and returns the consumer and the
// Volume's native record on this home.
type Grant func(ctx context.Context, peer [32]byte, ref MountRef) (volumes.Consumer, volumes.NativeReady, error)

// Source opens the Volume's original directory (Activations.ServedSource).
type Source func(ctx context.Context, ready volumes.NativeReady) (*nodestorage.DirectoryHandle, error)

// Home serves this server's shared Volumes to their remote consumers. Its
// Authorize is volumeshare.Server's: one localroot per Volume generation,
// the same Ops value (or its ReadOnly wrapper) for every mount of it.
type Home struct {
	grant  Grant
	source Source
	// seal derives the handle key of a Volume: stable across restarts so
	// remote handles survive one, distinct per Volume generation.
	seal func(volumes.NativeReady) []byte

	mu    sync.Mutex
	roots map[string]*servedRoot
}

type servedRoot struct {
	ready volumes.NativeReady
	root  *localroot.Root
	ro    volumeshare.Ops
}

func NewHome(grant Grant, source Source, seal func(volumes.NativeReady) []byte) *Home {
	return &Home{grant: grant, source: source, seal: seal, roots: map[string]*servedRoot{}}
}

func rootKey(r volumes.NativeReady) string {
	return volumes.NativeKey(r.Spec) + "#" + strconv.FormatUint(r.Generation, 10)
}

// Authorize is the volumeshare.Authorize of the home.
func (h *Home) Authorize(ctx context.Context, peer [32]byte, volume string) (volumeshare.Ops, error) {
	ref, err := ParseMountRef(volume)
	if err != nil {
		return nil, err
	}
	consumer, ready, err := h.grant(ctx, peer, ref)
	if err != nil {
		return nil, err
	}
	if ready.Spec.Scope != ref.Scope {
		return nil, errors.New("remote volume: grant names another Volume")
	}
	r, err := h.served(ctx, ready)
	if err != nil {
		return nil, err
	}
	if consumer.Writable {
		return r.root, nil
	}
	return r.ro, nil
}

func (h *Home) served(ctx context.Context, ready volumes.NativeReady) (*servedRoot, error) {
	key := rootKey(ready)
	h.mu.Lock()
	defer h.mu.Unlock()
	if r := h.roots[key]; r != nil && reflect.DeepEqual(r.ready, ready) {
		return r, nil
	} else if r != nil {
		// The record changed under the same key: never serve the old one.
		_ = r.root.Shutdown()
		delete(h.roots, key)
	}
	d, err := h.source(ctx, ready)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	root, err := localroot.OpenFD(d.FD(), h.seal(ready))
	if err != nil {
		return nil, err
	}
	r := &servedRoot{ready: ready, root: root, ro: volumeshare.ReadOnly(root)}
	h.roots[key] = r
	return r, nil
}

// Close stops serving every Volume.
func (h *Home) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var err error
	for key, r := range h.roots {
		err = errors.Join(err, r.root.Shutdown())
		delete(h.roots, key)
	}
	return err
}
