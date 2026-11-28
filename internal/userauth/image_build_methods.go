// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

// ImageBuildJobPlanQuery plans one build job of a saved context version.
type ImageBuildJobPlanQuery struct {
	Tenant string
	Query  control.ImageBuildJobQuery
}

func (q ImageBuildJobPlanQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid()
}

// ImageBuildsQuery pages one part of the tenant's build metadata.
type ImageBuildsQuery struct {
	Tenant string
	Query  control.ImageBuildQuery
	After  string `json:",omitempty"`
}

func (q ImageBuildsQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid() && len(q.After) <= 512
}

// ImageBuildCacheQuery pages one server's build cache usage.
type ImageBuildCacheQuery struct {
	Tenant string
	Query  imagebuild.CacheQuery
	After  string `json:",omitempty"`
}

func (q ImageBuildCacheQuery) Valid() bool {
	_, _, _, _, err := control.ImageBuildCacheOffset(q.After)
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid() && err == nil
}

// ImageBuildLogsQuery pages one build job's log. A tail read has no cursor.
type ImageBuildLogsQuery struct {
	Tenant string
	Query  imagebuild.LogQuery
	After  string `json:",omitempty"`
}

func (q ImageBuildLogsQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid() && !(q.Query.Tail && q.After != "") && len(q.After) <= 512
}

// BuildContextContentQuery pages one directory or file of a build context.
type BuildContextContentQuery struct {
	Tenant string
	Query  imagebuild.ContentQuery
	After  string `json:",omitempty"`
}

func (q BuildContextContentQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid() && len(q.After) <= 512
}

// CheckBuildContextQuery inspects a build context's source.
type CheckBuildContextQuery struct {
	Tenant string
	Query  control.ImageBuildSourceQuery
}

func (q CheckBuildContextQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Query.Valid()
}

// SaveBuildGitQuery saves, or reads the result of saving, a Git context.
type SaveBuildGitQuery struct {
	Tenant  string
	Request imagebuild.GitSaveRequest
}

func (q SaveBuildGitQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Request.Valid()
}

// BuildDraftQuery reads or edits a build context draft.
type BuildDraftQuery struct {
	Tenant  string
	Request imagebuild.DraftRequest
}

func (q BuildDraftQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Request.Valid()
}

// BuildZIPTransferQuery sends one part of, or seals, a build ZIP upload.
type BuildZIPTransferQuery struct {
	Tenant  string
	Request imagebuild.Transfer
}

func (q BuildZIPTransferQuery) Valid() bool {
	return lifecycle.ValidID(q.Tenant) && q.Request.Valid()
}

// imageBuildCode maps a build error to a reply code: denied, invalid,
// conflict or unavailable.
func imageBuildCode(err error) string {
	switch {
	case errors.Is(err, access.ErrDenied):
		return "denied"
	case errors.Is(err, access.ErrInvalid) || errors.Is(err, imagebuild.ErrInvalid):
		return "invalid"
	case errors.Is(err, access.ErrConflict) || errors.Is(err, imagebuild.ErrConflict) || errors.Is(err, imagebuild.ErrExpired):
		return "conflict"
	}
	return "unavailable"
}

func imageBuildError(err error) Reply { return Reply{Schema: 1, Code: imageBuildCode(err)} }

// mayRegistry says whether session may manage the tenant's registry.
func (s Service) mayRegistry(view cluster.View, session access.Session, tenant string) bool {
	return s.mayAny(view, session, tenant, access.ManageRegistry)
}

// mayReadBuilds says whether session may read the tenant's builds.
func (s Service) mayReadBuilds(view cluster.View, session access.Session, tenant string) bool {
	return s.mayAny(view, session, tenant, access.Read, access.ManageRegistry)
}

var (
	// ImageBuildJobPlanMethod needs the begin-image-build operation and the
	// tenant's ManageRegistry. A fresh report from the build server can rule
	// it out with build-disabled.
	ImageBuildJobPlanMethod = define(Method[ImageBuildJobPlanQuery, control.ImageBuildJobPlan]{Name: "image-build-job-plan"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageBuildJobPlanQuery) (control.ImageBuildJobPlan, string) {
		c, err := s.Policy.Catalog(view.State)
		if err != nil || c.OperationAllowed(session, "begin-image-build") != nil || !s.mayRegistry(view, session, q.Tenant) {
			return control.ImageBuildJobPlan{}, "denied"
		}
		now := time.Now().Unix()
		plan, err := s.Policy.ImageBuildJobPlan(view.State, session, now, q.Tenant, q.Query)
		if err == nil && s.NodeObservations != nil {
			if reports, _, rerr := s.NodeObservations(ctx, view); rerr == nil {
				err = s.Policy.CheckBuildNode(view.State, plan.Spec.Context.Root.Node, reports, now)
			}
		}
		if errors.Is(err, control.ErrBuildDisabled) {
			return control.ImageBuildJobPlan{}, "build-disabled"
		}
		if err != nil {
			return control.ImageBuildJobPlan{}, imageBuildCode(err)
		}
		return plan, "ok"
	})

	// ImageBuildsMethod needs the tenant's Read or ManageRegistry. The caches
	// part is read from the servers that hold them.
	ImageBuildsMethod = define(Method[ImageBuildsQuery, control.ImageBuildPage]{Name: "image-builds"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageBuildsQuery) (control.ImageBuildPage, string) {
		if !s.mayReadBuilds(view, session, q.Tenant) {
			return control.ImageBuildPage{}, "denied"
		}
		page, err := s.Policy.ImageBuildPage(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
		if err == nil && q.Query.Part == "caches" {
			if s.ImageBuildCaches == nil {
				err = imagebuild.ErrStorage
			} else {
				page, err = s.ImageBuildCaches(ctx, session, q.Tenant, q.Query, q.After)
				if err == nil && (page.Tenant != q.Tenant || !control.ValidImageBuildCacheInventoryPage(page, q.Query, q.After, true)) {
					err = imagebuild.ErrStorage
				}
			}
		}
		if err != nil {
			return control.ImageBuildPage{}, imageBuildCode(err)
		}
		return page, "ok"
	})

	// ImageBuildCacheMethod needs the tenant's Read or ManageRegistry.
	ImageBuildCacheMethod = define(Method[ImageBuildCacheQuery, control.ImageBuildCachePage]{Name: "image-build-cache"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageBuildCacheQuery) (control.ImageBuildCachePage, string) {
		if !s.mayReadBuilds(view, session, q.Tenant) {
			return control.ImageBuildCachePage{}, "denied"
		}
		read, err := s.Policy.ImageBuildCacheRead(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
		if err != nil {
			return control.ImageBuildCachePage{}, imageBuildCode(err)
		}
		if s.ImageBuildCache == nil {
			return control.ImageBuildCachePage{}, "unavailable"
		}
		out, err := s.ImageBuildCache(ctx, read)
		if err != nil {
			return control.ImageBuildCachePage{}, imageBuildCode(err)
		}
		if !out.Valid(read) {
			return control.ImageBuildCachePage{}, "unavailable"
		}
		return out, "ok"
	})

	// ImageBuildLogsMethod needs the tenant's Read or ManageRegistry.
	ImageBuildLogsMethod = define(Method[ImageBuildLogsQuery, control.ImageBuildLogPage]{Name: "image-build-logs"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageBuildLogsQuery) (control.ImageBuildLogPage, string) {
		if !s.mayReadBuilds(view, session, q.Tenant) {
			return control.ImageBuildLogPage{}, "denied"
		}
		read, err := s.Policy.ImageBuildLogRead(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
		if err != nil {
			return control.ImageBuildLogPage{}, imageBuildCode(err)
		}
		if s.ImageBuildLogs == nil {
			return control.ImageBuildLogPage{}, "unavailable"
		}
		out, err := s.ImageBuildLogs(ctx, read)
		if err != nil {
			return control.ImageBuildLogPage{}, imageBuildCode(err)
		}
		if !out.Valid(read) {
			return control.ImageBuildLogPage{}, "unavailable"
		}
		return out, "ok"
	})

	// BuildContextContentMethod needs the tenant's Read or ManageRegistry.
	BuildContextContentMethod = define(Method[BuildContextContentQuery, control.ImageBuildContentPage]{Name: "build-context-content"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q BuildContextContentQuery) (control.ImageBuildContentPage, string) {
		if !s.mayReadBuilds(view, session, q.Tenant) {
			return control.ImageBuildContentPage{}, "denied"
		}
		read, err := s.Policy.ImageBuildContentRead(view.State, session, time.Now().Unix(), q.Tenant, q.Query, q.After)
		if err != nil {
			return control.ImageBuildContentPage{}, imageBuildCode(err)
		}
		if s.ImageBuildContent == nil {
			return control.ImageBuildContentPage{}, "unavailable"
		}
		out, err := s.ImageBuildContent(ctx, read)
		if err != nil {
			return control.ImageBuildContentPage{}, imageBuildCode(err)
		}
		if !out.Valid(read) {
			return control.ImageBuildContentPage{}, "unavailable"
		}
		return out, "ok"
	})

	// CheckBuildContextMethod needs the tenant's ManageRegistry.
	CheckBuildContextMethod = define(Method[CheckBuildContextQuery, control.ImageBuildSourceResult]{Name: "check-build-context"}, true, func(ctx context.Context, s Service, view cluster.View, session access.Session, q CheckBuildContextQuery) (control.ImageBuildSourceResult, string) {
		if !s.mayRegistry(view, session, q.Tenant) {
			return control.ImageBuildSourceResult{}, "denied"
		}
		read, err := s.Policy.ImageBuildSourceRead(view.State, session, time.Now().Unix(), q.Tenant, q.Query)
		if err != nil {
			return control.ImageBuildSourceResult{}, imageBuildCode(err)
		}
		if s.ImageBuildSource == nil {
			return control.ImageBuildSourceResult{}, "unavailable"
		}
		out, err := s.ImageBuildSource(ctx, read)
		if err != nil {
			return control.ImageBuildSourceResult{}, imageBuildCode(err)
		}
		if !out.Valid(read) {
			return control.ImageBuildSourceResult{}, "unavailable"
		}
		return out, "ok"
	})

	// SaveBuildGitMethod needs the tenant's ManageRegistry and the user's
	// signed proof over the plan.
	SaveBuildGitMethod = define(Method[SaveBuildGitQuery, imagebuild.GitSaveResponse]{Name: "save-build-git"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q SaveBuildGitQuery) (imagebuild.GitSaveResponse, string) {
		if !s.mayRegistry(view, session, q.Tenant) {
			return imagebuild.GitSaveResponse{}, "denied"
		}
		call := control.ImageBuildGitCall{Session: session, Tenant: q.Tenant, Request: q.Request, At: time.Now().Unix()}
		if _, err := s.Policy.ImageBuildGitWork(view.State, call); err != nil {
			return imagebuild.GitSaveResponse{}, imageBuildCode(err)
		}
		if s.ImageBuildGit == nil {
			return imagebuild.GitSaveResponse{}, "unavailable"
		}
		out, err := s.ImageBuildGit(ctx, call)
		if err != nil {
			return imagebuild.GitSaveResponse{}, imageBuildCode(err)
		}
		if !out.Valid(call.Request) {
			return imagebuild.GitSaveResponse{}, "unavailable"
		}
		return out, "ok"
	})

	// BuildDraftMethod needs the tenant's ManageRegistry; edits also carry
	// the user's signed proof.
	BuildDraftMethod = define(Method[BuildDraftQuery, imagebuild.DraftResponse]{Name: "build-draft"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q BuildDraftQuery) (imagebuild.DraftResponse, string) {
		if !s.mayRegistry(view, session, q.Tenant) {
			return imagebuild.DraftResponse{}, "denied"
		}
		call := control.ImageBuildDraftCall{Session: session, Tenant: q.Tenant, Request: q.Request, At: time.Now().Unix()}
		work, err := s.Policy.ImageBuildDraftWork(view.State, call)
		if err != nil {
			return imagebuild.DraftResponse{}, imageBuildCode(err)
		}
		if s.ImageBuildDraft == nil {
			return imagebuild.DraftResponse{}, "unavailable"
		}
		out, err := s.ImageBuildDraft(ctx, call)
		if err != nil {
			return imagebuild.DraftResponse{}, imageBuildCode(err)
		}
		if !out.Valid(call.Request) || out.Scope != work.Scope {
			return imagebuild.DraftResponse{}, "unavailable"
		}
		return out, "ok"
	})

	// BuildZIPTransferMethod needs the tenant's ManageRegistry; parts carry
	// the user's signed proof.
	BuildZIPTransferMethod = define(Method[BuildZIPTransferQuery, control.ImageBuildIOResult]{Name: "build-zip-transfer"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q BuildZIPTransferQuery) (control.ImageBuildIOResult, string) {
		if !s.mayRegistry(view, session, q.Tenant) {
			return control.ImageBuildIOResult{}, "denied"
		}
		if s.ImageBuildTransfer == nil {
			return control.ImageBuildIOResult{}, "unavailable"
		}
		out, err := s.ImageBuildTransfer(ctx, view, control.ImageBuildIOCall{Session: session, Tenant: q.Tenant, Request: q.Request, At: time.Now().Unix()})
		if err != nil {
			return control.ImageBuildIOResult{}, imageBuildCode(err)
		}
		return out, "ok"
	})
)
