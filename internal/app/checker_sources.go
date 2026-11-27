// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/storage"
	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

// The same backend serves QUIC and local Unix management streams. No store
// lock is held while fetching the current leader's authenticated quorum permit.
type checkerSourceBackend struct{ runtime *Runtime }

func (b checkerSourceBackend) permit(ctx context.Context, session access.Session, d checker.SourceDescriptor, recover bool) (checker.TenantPolicy, error) {
	r := b.runtime
	q := control.LifecycleSourcePermitRequest{Session: session, Source: d.Clone(), At: time.Now().Unix(), Recover: recover}
	raw, err := json.Marshal(q)
	if err != nil {
		return checker.TenantPolicy{}, err
	}
	reply, err := r.appCall(ctx, "checker-source-permit", raw)
	if err != nil {
		return checker.TenantPolicy{}, err
	}
	permit, err := schema.Decode[control.LifecycleSourcePermit](reply.Data)
	if err != nil || r.installation == nil || permit.Schema != 1 || permit.Cluster != r.controlPolicy.Cluster || permit.Provider != r.Identity.Public || permit.Node != r.installation.record.Root.Self.ID || permit.Source.Tenant != d.Tenant || permit.Source.ContentDigest() != d.ContentDigest() || permit.Recover != recover || permit.Index == 0 || permit.Epoch == 0 || permit.Policy.Validate() != nil || permit.Policy.Tenant != d.Tenant || !recover && !permit.Policy.AllowsDescriptor(d) {
		return checker.TenantPolicy{}, sfcp.ErrAdmission
	}
	return permit.Policy, nil
}

func (b checkerSourceBackend) Permit(ctx context.Context, session access.Session, d checker.SourceDescriptor, recover bool) error {
	_, err := b.permit(ctx, session, d, recover)
	return err
}

func (b checkerSourceBackend) publicationOwner(ctx context.Context, d checker.SourceDescriptor, id [32]byte) (*Runtime, error) {
	var found *Runtime
	for _, owner := range b.runtime.physicalOwners() {
		owner.life.RLock()
		if owner.closed || owner.ctx.Err() != nil || owner.checkerSources == nil {
			owner.life.RUnlock()
			return nil, sfcp.ErrAdmission
		}
		release, err := owner.checkerSources.HoldUpload(ctx, d, id, true)
		owner.life.RUnlock()
		if err != nil {
			if errors.Is(err, storage.ErrMissing) && !errors.Is(err, checker.ErrSourceStore) {
				continue
			}
			return nil, err
		}
		release()
		if found != nil {
			return nil, checker.ErrSourceStore
		}
		found = owner
	}
	if found == nil {
		return nil, storage.ErrMissing
	}
	if !b.runtime.acceptsResourceKey(ctx, found.Identity.Public) {
		return nil, sfcp.ErrAdmission
	}
	return found, nil
}
func (b checkerSourceBackend) BeginPublication(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte, recover bool) (func(), error) {
	if _, err := b.permit(ctx, session, d, recover); err != nil {
		return nil, err
	}
	r := b.runtime
	original, err := b.publicationOwner(ctx, d, id)
	if err != nil && (!errors.Is(err, storage.ErrMissing) || errors.Is(err, checker.ErrSourceStore)) {
		return nil, err
	}
	if recover {
		if err != nil {
			return nil, err
		}
		r = original
	} else if original != nil && original != r {
		return nil, checker.ErrReference
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return nil, sfcp.ErrAdmission
	}
	if !recover {
		if err = r.checkerSources.BeginUpload(ctx, d, id); err != nil {
			return nil, err
		}
	}
	return r.checkerSources.HoldUpload(ctx, d, id, recover)
}
func (b checkerSourceBackend) StagePublication(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte, data []byte) (checker.SourceFact, error) {
	policy, err := b.permit(ctx, session, d, false)
	if err != nil {
		return checker.SourceFact{}, err
	}
	r := b.runtime
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return checker.SourceFact{}, sfcp.ErrAdmission
	}
	if _, err = r.checkerSources.Stage(ctx, d, data, policy); err != nil {
		return checker.SourceFact{}, err
	}
	return r.checkerSources.UploadedFact(ctx, d, id, false)
}
func (b checkerSourceBackend) RecoverPublication(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte) (checker.SourceFact, error) {
	if _, err := b.permit(ctx, session, d, true); err != nil {
		return checker.SourceFact{}, err
	}
	r, err := b.publicationOwner(ctx, d, id)
	if err != nil {
		return checker.SourceFact{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return checker.SourceFact{}, sfcp.ErrAdmission
	}
	return r.checkerSources.UploadedFact(ctx, d, id, true)
}
func (b checkerSourceBackend) RecoverPublicationModule(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte, pin checker.ModulePin) (checker.ModuleFact, error) {
	if _, err := b.permit(ctx, session, d, true); err != nil {
		return checker.ModuleFact{}, err
	}
	r, err := b.publicationOwner(ctx, d, id)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return checker.ModuleFact{}, sfcp.ErrAdmission
	}
	return r.checkerSources.RecoverModule(ctx, d.Tenant, pin)
}
func (b checkerSourceBackend) StagePublicationModule(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte, a checker.ModuleArchive) (checker.ModuleFact, error) {
	policy, err := b.permit(ctx, session, d, false)
	if err != nil {
		return checker.ModuleFact{}, err
	}
	r := b.runtime
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return checker.ModuleFact{}, sfcp.ErrAdmission
	}
	return r.checkerSources.StageModule(ctx, d, a, policy)
}
