// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

func imageBuildCacheAutomaticWorkerID(cache [32]byte) [32]byte {
	return sha256.Sum256(append([]byte("mydc-cache-automatic-worker-1\x00"), cache[:]...))
}

// Only proposes a new shared pass. The already existing finite maintenance
// worker consumes it, reserves budgets and owns all native cleanup/recovery.
func (r *Runtime) submitImageBuildCacheAutomatic(ctx context.Context, candidate imagebuild.JobSpec) error {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return mydcp.ErrAdmission
	}
	row, err := r.controlPolicy.ImageBuildCacheAutomaticPlan(view.State, r.Identity.Public, candidate.Tenant, candidate.Scope.Root.Node, imagebuild.CacheIdentity(candidate), time.Now().Unix())
	if errors.Is(err, reconcile.ErrPending) || errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrConflict) {
		return nil
	}
	if err != nil {
		return err
	}
	book, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return err
	}
	source, found := book.Job(candidate.Tenant, row.Source)
	if !found {
		return imagebuild.ErrStorage
	}
	summary, err := r.imageBuildNative.ReadCacheSummary(source.Run.Spec)
	if err != nil {
		return err
	}
	if !summary.Recorded || !summary.Allocated || summary.Borrowed {
		return nil
	}
	now := uint64(time.Now().Unix())
	if summary.LastAttemptAt > now || now-summary.LastAttemptAt < control.ImageBuildCacheAutomaticInterval {
		return nil
	}
	report := *row.Automatic
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildCacheAutomaticBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return err
	}
	reply, err := r.appCall(ctx, "image-build-cache-automatic-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	return nil
}

func imageBuildCacheAutomaticCandidate(book control.ImageBuildCatalog, owner [32]byte, next map[[32]byte]time.Time, now time.Time) (imagebuild.JobSpec, [32]byte) {
	var selected imagebuild.JobSpec
	var key [32]byte
	var due time.Time
	found := false
	for _, row := range book.Jobs {
		spec := row.Run.Spec
		if spec.Scope.Root.Key != owner || !row.Run.Terminal() {
			continue
		}
		policy, ok := book.Policy(spec.Tenant)
		if !ok || policy.Deleted || policy.Spec.BuilderImage != spec.Policy.BuilderImage {
			continue
		}
		cache := imagebuild.CacheIdentity(spec)
		at := next[cache]
		if now.Before(at) {
			continue
		}
		if !found || at.Before(due) || at.Equal(due) && string(cache[:]) < string(key[:]) {
			selected, key, due, found = spec, cache, at, true
		}
	}
	return selected, key
}
