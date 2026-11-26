// SPDX-License-Identifier: Apache-2.0

package control

import (
	"bytes"
	"maps"
	"sync/atomic"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/config"
)

// Only read-only runtime/permit/planning/projection/validation paths may borrow
// this view. Apps gives reducers an owned metadata copy. Returned
// results must own their mutable fields and never publish borrowed Apps
// internals. A single entry bounds retained data;
// eviction changes cost, never authority. No permit or state-dependent grant
// is retained here.
type permitAppsDecode struct {
	policy   [32]byte
	revision uint64
	raw      []byte
	apps     Apps
	current  atomic.Pointer[permitAppsCurrent]
}

// Structural validation is a pure function of these exact committed inputs.
// This record contains no caller, permit, clock, current role or native result.
// Keep one success only; maps come from State.Objects and are never mutated.
type permitAppsCurrent struct {
	index, epoch uint64
	genesis      config.Peer
	objects      map[string]state.Object
}

var permitAppsDecoded atomic.Pointer[permitAppsDecode]

// ReadApps returns checked metadata for read-only runtime scheduling. Its
// exported accessors return owned mutable outputs. The interpretation may be
// shared, so control reducers must use Apps instead. This grants no authority:
// actual work still needs the current quorum permit and native checks.
func (p Policy) ReadApps(s state.State) (Apps, error) {
	return p.readOnlyApps(s)
}

func (p Policy) readOnlyApps(s state.State) (Apps, error) {
	// Even a hit must verify the current root, every part, and the digest.
	raw, revision, err := readCheckpoint(s, AppsKey, p.Cluster, p.TrustRoot)
	if err != nil || len(raw) > maxAppCheckpoint {
		return Apps{}, ErrCatalog
	}
	if raw == nil {
		return p.emptyApps(), nil
	}
	id := p.ID()
	if cached := permitAppsDecoded.Load(); cached != nil && cached.policy == id && cached.revision == revision && bytes.Equal(cached.raw, raw) {
		// Compare every current structural input, including state outside Apps.
		if err := cached.validateCurrent(p, s); err != nil {
			return Apps{}, err
		}
		return cached.apps, nil
	}
	a, err := p.decodeApps(s, raw, revision)
	if err != nil {
		return Apps{}, err
	}
	decoded := &permitAppsDecode{policy: id, revision: revision, raw: raw, apps: a}
	// decodeApps already checked the same structural dependencies.
	decoded.current.Store(&permitAppsCurrent{s.Index(), s.ModuleEpoch(), p.Genesis, s.Objects("")})
	permitAppsDecoded.Store(decoded)
	return a, nil
}

func (d *permitAppsDecode) validateCurrent(p Policy, s state.State) error {
	objects := s.Objects("")
	if current := d.current.Load(); current != nil && current.index == s.Index() && current.epoch == s.ModuleEpoch() && current.genesis == p.Genesis && maps.Equal(current.objects, objects) {
		return nil
	}
	if err := p.validatePermitAppsCurrent(s, d.apps); err != nil {
		return err
	}
	d.current.Store(&permitAppsCurrent{s.Index(), s.ModuleEpoch(), p.Genesis, objects})
	return nil
}

func (p Policy) validatePermitAppsCurrent(s state.State, a Apps) error {
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	for _, upload := range a.uploads {
		_, tenant := c.Tenant(upload.Tenant)
		_, user := c.User(upload.User)
		if !tenant || !user {
			return ErrCatalog
		}
	}
	for _, entry := range a.entries {
		_, tenant := c.Tenant(entry.Inventory.Scope().Tenant)
		_, user := c.User(entry.Origin.Session.User)
		if !tenant || !user {
			return ErrCatalog
		}
	}
	return p.validateMoveAppOrigins(s, a)
}
