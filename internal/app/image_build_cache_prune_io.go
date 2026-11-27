// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r *Runtime) imageBuildCachePruneWork(ctx context.Context, s imagebuild.NativeCachePruneSpec) (control.ImageBuildCachePruneWork, error) {
	if !s.Valid() || s.Source.Cluster != r.controlPolicy.Cluster || s.Source.Scope.Root.Key != r.Identity.Public || r.ctx.Err() != nil {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	q := control.ImageBuildCachePruneWorkQuery{Tenant: s.Source.Tenant, ID: s.ID, At: time.Now().Unix()}
	raw, _ := json.Marshal(q)
	reply, err := r.appCall(ctx, "image-build-cache-prune-work", raw)
	if err != nil || reply.Local {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	work, err := schema.Decode[control.ImageBuildCachePruneWork](reply.Data)
	if err != nil {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	granted, err := work.NativeGrant()
	if err != nil || granted.Spec.Digest() != s.Digest() {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	view, err := r.Engine().ReadAtLeast(ctx, work.Index)
	if err != nil || view.State.ModuleEpoch() != work.Epoch {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	q.At = time.Now().Unix()
	current, err := r.controlPolicy.ImageBuildCachePruneWork(view.State, r.Identity.Public, q)
	if err != nil {
		return control.ImageBuildCachePruneWork{}, err
	}
	grant, err := current.NativeGrant()
	if err != nil || grant.Spec.Digest() != s.Digest() || grant.Revision < granted.Revision {
		return control.ImageBuildCachePruneWork{}, sfcp.ErrAdmission
	}
	return current, nil
}
func (r *Runtime) imageBuildCachePruneAuthority(ctx context.Context, s imagebuild.NativeCachePruneSpec, _ bool) (imagebuild.NativeCachePruneGrant, error) {
	work, err := r.imageBuildCachePruneWork(ctx, s)
	if err != nil {
		return imagebuild.NativeCachePruneGrant{}, err
	}
	return work.NativeGrant()
}
func (r *Runtime) publishImageBuildCachePrune(ctx context.Context, work control.ImageBuildCachePruneWork, report control.ImageBuildCachePruneReport) error {
	grant, err := work.NativeGrant()
	if err != nil {
		return err
	}
	report.Schema, report.Kind, report.Cluster, report.Owner, report.Intent = 1, "cache-prune", work.Cluster, r.Identity.Public, grant.Spec.Intent
	report.Tenant, report.ID = grant.Spec.Source.Tenant, grant.Spec.ID
	report.Expected, report.RootRevision, report.Epoch = work.Record.Revision, work.RootRevision, work.Epoch
	report.At = uint64(time.Now().Unix())
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildCachePruneReportBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "image-build-cache-prune-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	return nil
}

func (r *Runtime) claimImageBuildCachePruneRoot(work control.ImageBuildCachePruneWork) (failure error) {
	if r.imageBuildNative == nil || r.nodeRoots == nil {
		return imagebuild.ErrStorage
	}
	grant, err := work.NativeGrant()
	if err != nil {
		return err
	}
	s := grant.Spec
	hold, err := r.imageBuildNative.CachePruneRootHold(s)
	if err != nil {
		return err
	}
	consumer, err := r.imageBuildNative.RootConsumer(s.Source, imagebuild.CacheRoot)
	if err != nil {
		return err
	}
	ref := s.Source.Scope.Root
	pin, held, err := r.nodeRoots.RecordedPin(ref, consumer)
	if err != nil || !held || pin.Lease != hold.Lease {
		return imagebuild.ErrStorage
	}
	pin, err = r.nodeRoots.OpenRecordedPin(ref, consumer)
	if pin.Directory != nil {
		defer func() { failure = errors.Join(failure, pin.Directory.Close()) }()
	}
	if err != nil || pin.Directory == nil {
		return imagebuild.ErrStorage
	}
	return r.imageBuildNative.ClaimCachePrune(grant, pin.Directory.FD())
}
