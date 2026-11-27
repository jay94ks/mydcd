// SPDX-License-Identifier: Apache-2.0

//go:build linux

package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/storage"
)

// CompilerPreparation is local metadata, never shared acceptance, authority,
// native closure or an assertion that an artifact is executable/ready.
type CompilerPreparation struct {
	Intent                        BuildIntent
	InputReady, Cancelled, Closed bool
	NativeDispatched              bool
}

// Accept records a shared RESERVED job before fetching input or dispatching.
// Its caller must never use this to reconstruct a missing DISPATCHED journal.
// No job directory, Docker resource, slot or current Start grant is created.
func (m *CompilerOwner) Accept(ctx context.Context, b BuildIntent, p TenantPolicy) error {
	m.life.RLock()
	defer m.life.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.accept(ctx, b, p)
	return err
}

func (m *CompilerOwner) accept(ctx context.Context, b BuildIntent, p TenantPolicy) (compilerDisk, error) {
	if ctx == nil || ctx.Err() != nil || m.closed || m.uncertain || b.Validate() != nil || b.Owner != m.identity.Node || b.Cluster != m.identity.Cluster || p.Validate() != nil || !p.Enabled || p.Tenant != b.Tenant || p.Revision != b.Selection.PolicyRevision || !slices.Contains(p.Build.Nodes, b.Node) || !slices.Contains(p.Build.Targets, b.Target) {
		return compilerDisk{}, ErrCompilerOwner
	}
	r, err := m.load(b.Tenant, b.ID)
	if errors.Is(err, storage.ErrMissing) {
		if len(m.known) >= maxBuildJobs {
			return compilerDisk{}, ErrCompilerOwner
		}
		s, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Present: true, Generation: 1, Spec: compilerSpec(b, p)}})
		if err != nil {
			return compilerDisk{}, err
		}
		r = compilerDisk{Schema: 1, Intent: b.Clone(), Policy: p.Clone(), State: s}
		if err := m.save(r); err != nil {
			return compilerDisk{}, err
		}
	} else if err != nil {
		return compilerDisk{}, err
	}
	want, _ := json.Marshal(p)
	original, _ := json.Marshal(r.Policy)
	if r.Intent.Digest() != b.Digest() || !bytes.Equal(want, original) {
		return compilerDisk{}, ErrCompilerOwner
	}
	return r, nil
}

func (m *CompilerOwner) Preparation(tenant, id string) (CompilerPreparation, error) {
	m.life.RLock()
	defer m.life.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.uncertain || !name(tenant) || !digest(id) {
		return CompilerPreparation{}, ErrCompilerOwner
	}
	r, err := m.load(tenant, id)
	if err != nil {
		return CompilerPreparation{}, err
	}
	return CompilerPreparation{Intent: r.Intent.Clone(), InputReady: r.InputReady, Cancelled: r.Cancel, Closed: r.Closure != nil, NativeDispatched: r.CreateDispatched}, nil
}
