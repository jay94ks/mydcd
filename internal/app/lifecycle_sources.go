// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
)

func (b checkerSourceBackend) ValidatePublication(ctx context.Context, session access.Session, d checker.SourceDescriptor, id [32]byte, data []byte) (*checker.SourceFact, []checker.SourceDiagnostic, error) {
	policy, err := b.permit(ctx, session, d, false)
	if err != nil {
		return nil, nil, err
	}
	r := b.runtime
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		return nil, nil, mydcp.ErrAdmission
	}
	diagnostics, err := r.checkerSources.ValidateSource(ctx, d, data, policy)
	if err != nil {
		return nil, nil, err
	}
	latest, err := b.permit(ctx, session, d, false)
	if err != nil || latest.Revision != policy.Revision {
		return nil, nil, mydcp.ErrAdmission
	}
	if len(diagnostics) > 0 {
		return nil, diagnostics, nil
	}
	if _, err = r.checkerSources.Stage(ctx, d, data, latest); err != nil {
		return nil, nil, err
	}
	fact, err := r.checkerSources.UploadedFact(ctx, d, id, false)
	if err != nil {
		return nil, nil, err
	}
	return &fact, nil, nil
}

func (r *Runtime) lifecycleSourceReadPermit(ctx context.Context, read control.LifecycleSourceRead) error {
	raw, err := json.Marshal(read)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "lifecycle-source-version-permit", raw)
	if err != nil {
		return err
	}
	index, err := schema.Decode[uint64](reply.Data)
	if err != nil || index == 0 || reply.Local || reply.RaftIndex == 0 || reply.CommandIndex < index {
		return mydcp.ErrAdmission
	}
	return nil
}

// Owner reply codes preserve safe error classes without exporting internal DB
// text, paths or a SourceFact as a positive availability assertion.
type lifecycleSourceOwnerReply struct {
	Code string
	Page *checker.SourcePage `json:",omitempty"`
}

func (r *Runtime) readLifecycleSourceOwner(ctx context.Context, caller [32]byte, read control.LifecycleSourceRead) (checker.SourcePage, error) {
	if caller == ([32]byte{}) || !r.acceptsResourceKey(ctx, read.Source.Owner) {
		return checker.SourcePage{}, mydcp.ErrAdmission
	}
	if owner, ok := r.nativeOwner(read.Source.Owner); ok && owner != r {
		return owner.readLifecycleSourceOwner(ctx, caller, read)
	}
	if read.Source.Owner != r.Identity.Public {
		return checker.SourcePage{}, mydcp.ErrAdmission
	}
	if err := r.lifecycleSourceReadPermit(ctx, read); err != nil {
		return checker.SourcePage{}, err
	}
	r.life.RLock()
	if r.closed || r.ctx.Err() != nil || r.checkerSources == nil {
		r.life.RUnlock()
		return checker.SourcePage{}, mydcp.ErrAdmission
	}
	fact, data, err := r.checkerSources.SourceArtifact(ctx, read.Source.Descriptor())
	r.life.RUnlock()
	if err != nil {
		return checker.SourcePage{}, err
	}
	defer clear(data)
	if fact.ContentDigest() != read.Source.ContentDigest() {
		return checker.SourcePage{}, checker.ErrSourceStore
	}
	page, err := checker.NewSourcePage(read.Tenant, read.Query.Name, read.Query.Revision, read.Query.Offset, read.Source.Descriptor(), data)
	if err != nil {
		return checker.SourcePage{}, err
	}
	if err = r.lifecycleSourceReadPermit(ctx, read); err != nil {
		return checker.SourcePage{}, err
	}
	return page, nil
}
func (r *Runtime) readLifecycleSource(ctx context.Context, read control.LifecycleSourceRead) (checker.SourcePage, error) {
	if r.acceptsResourceKey(ctx, read.Source.Owner) {
		return r.readLifecycleSourceOwner(ctx, r.commandIdentity().Public, read)
	}
	peer, ok := r.resourcePeerForKey(ctx, read.Source.Owner)
	if !ok || !peer.Member {
		return checker.SourcePage{}, mydcp.ErrAdmission
	}
	raw, err := json.Marshal(read)
	if err != nil {
		return checker.SourcePage{}, err
	}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.commandIdentity(), r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "lifecycle-source-version-owner", Input: raw})
	if err != nil {
		return checker.SourcePage{}, err
	}
	result, err := schema.Decode[lifecycleSourceOwnerReply](reply.Data)
	if err != nil {
		return checker.SourcePage{}, mydcp.ErrFrame
	}
	if result.Code != "ok" {
		if result.Page != nil {
			return checker.SourcePage{}, mydcp.ErrFrame
		}
		switch result.Code {
		case "missing":
			return checker.SourcePage{}, storage.ErrMissing
		case "denied":
			return checker.SourcePage{}, mydcp.ErrAdmission
		case "invalid":
			return checker.SourcePage{}, checker.ErrSourceStore
		case "unavailable":
			return checker.SourcePage{}, checker.ErrSourceUncertain
		default:
			return checker.SourcePage{}, mydcp.ErrFrame
		}
	}
	page := result.Page
	if page == nil || !page.Valid() || page.Tenant != read.Tenant || page.Name != read.Query.Name || page.Revision != read.Query.Revision || page.Offset != read.Query.Offset || page.Digest != read.Source.Digest || page.Total != read.Source.Length {
		return checker.SourcePage{}, mydcp.ErrFrame
	}
	if err = r.lifecycleSourceReadPermit(ctx, read); err != nil {
		return checker.SourcePage{}, err
	}
	return *page, nil
}
func (r *Runtime) lifecycleSourceModule(ctx context.Context, method, key string, input []byte, view cluster.View) (json.RawMessage, error) {
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	read, err := schema.Decode[control.LifecycleSourceRead](input)
	if err != nil {
		return nil, err
	}
	if method == "lifecycle-source-version-permit" {
		if view.Local {
			return nil, mydcp.ErrAdmission
		}
		index, err := r.controlPolicy.LifecycleSourceReadPermit(view.State, caller, read, time.Now().Unix())
		if err != nil {
			return nil, err
		}
		return json.Marshal(index)
	}
	page, err := r.readLifecycleSourceOwner(ctx, caller, read)
	result := lifecycleSourceOwnerReply{Code: "ok", Page: &page}
	if err != nil {
		result.Page = nil
		result.Code = "unavailable"
		switch {
		case errors.Is(err, storage.ErrMissing) && !errors.Is(err, checker.ErrSourceStore):
			result.Code = "missing"
		case errors.Is(err, mydcp.ErrAdmission), errors.Is(err, access.ErrDenied):
			result.Code = "denied"
		case errors.Is(err, checker.ErrSourceStore):
			result.Code = "invalid"
		}
	}
	return json.Marshal(result)
}
