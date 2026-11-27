// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func imageBuildGitWatchID(key string) [32]byte {
	return sha256.Sum256([]byte("sfc-imagebuild-git-watch-1\x00" + key))
}

func imageBuildGitWatchCandidate(eligible map[string]control.ImageBuildContextRecord, next map[string]time.Time, now time.Time) (string, control.ImageBuildContextRecord) {
	var selected string
	var earliest time.Time
	for key := range eligible {
		due := next[key]
		if due.After(now) {
			continue
		}
		if selected == "" || due.Before(earliest) || due.Equal(earliest) && key < selected {
			selected, earliest = key, due
		}
	}
	return selected, eligible[selected]
}

func (r *Runtime) imageBuildGitWatchWork(ctx context.Context, tenant, id string) (control.ImageBuildGitWatchWork, error) {
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return control.ImageBuildGitWatchWork{}, errors.Join(sfcp.ErrAdmission, err)
	}
	return r.controlPolicy.ImageBuildGitWatchWork(view.State, r.Identity.Public, tenant, id, time.Now().Unix())
}

func imageBuildGitWatchSameScope(a, b control.ImageBuildGitWatchWork) bool {
	return a.Definition == b.Definition && a.Read.ContextRevision == b.Read.ContextRevision && a.Read.PolicyRevision == b.Read.PolicyRevision && a.Read.Epoch == b.Read.Epoch
}

func (r *Runtime) observeImageBuildGit(ctx context.Context, tenant, id string) error {
	// Permission withdrawal/configuration changes stop observation, not a new
	// source fetch or a fallback to node CLI authority.
	closedPolicy := func(err error) bool {
		return errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrConflict)
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	defer cancel()
	work, err := r.imageBuildGitWatchWork(ctx, tenant, id)
	if closedPolicy(err) {
		return nil
	}
	if err != nil {
		return err
	}
	current := func() (control.ImageBuildSourceRead, error) {
		fresh, err := r.imageBuildGitWatchWork(ctx, tenant, id)
		if err != nil {
			return control.ImageBuildSourceRead{}, err
		}
		if !imageBuildGitWatchSameScope(work, fresh) {
			return control.ImageBuildSourceRead{}, access.ErrConflict
		}
		return fresh.Read, nil
	}
	result, err := r.inspectImageBuildSourceOwner(ctx, work.Read, current)
	if closedPolicy(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !result.Valid(work.Read) || result.Code == "OK" && !imagebuild.ValidGitCommit(result.Commit) {
		return sfcp.ErrAdmission
	}
	// Refresh only the report CAS, never the fetched commit or its source
	// scope. A changed context/policy/epoch discards this read-only result.
	view, err := r.currentView(ctx)
	if err != nil || view.Local {
		return errors.Join(sfcp.ErrAdmission, err)
	}
	fresh, err := r.controlPolicy.ImageBuildGitWatchWork(view.State, r.Identity.Public, tenant, id, time.Now().Unix())
	if closedPolicy(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !imageBuildGitWatchSameScope(work, fresh) {
		return nil
	}
	book, err := r.controlPolicy.ImageBuilds(view.State)
	if err != nil {
		return err
	}
	row, _ := book.Context(tenant, id)
	if row.GitObservation != nil && row.GitObservation.Same(fresh, result) {
		cancel()
		return r.submitImageBuildAutomaticGit(parent, tenant, id)
	}
	report := control.ImageBuildGitObservationReport{Schema: 1, Kind: "git-observation", Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Definition: fresh.Definition, Tenant: tenant, Expected: fresh.Expected, RootRevision: fresh.RootRevision, Epoch: fresh.Read.Epoch, At: uint64(time.Now().Unix()), Result: result}
	report.Signature = ed25519.Sign(r.commandIdentity().Private, control.ImageBuildGitObservationReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "image-build-git-observation-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return imagebuild.ErrConflict
	}
	cancel()
	return r.submitImageBuildAutomaticGit(parent, tenant, id)
}
