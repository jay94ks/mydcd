// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/imagecache"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// ImageCachePlanQuery selects a server's cached images to plan a prune.
type ImageCachePlanQuery struct{ Query imagecache.Query }

func (q ImageCachePlanQuery) Valid() bool { return q.Query.Valid(true) }

// ImageCacheStatusQuery names one recorded image prune.
type ImageCacheStatusQuery struct{ Operation string }

func (q ImageCacheStatusQuery) Valid() bool {
	return imagecache.Query{Operation: q.Operation}.Valid(false)
}

// mayManageCluster says whether session administers the cluster now.
func (s Service) mayManageCluster(view cluster.View, session access.Session) bool {
	c, err := s.Policy.Catalog(view.State)
	return err == nil && c.AuthorizeSession(session, s.Policy.Cluster, s.Policy.Issuer(session.Issuer), time.Now().Unix(), "", access.ManageCluster, "") == nil
}

var (
	// ImageCachePlanMethod asks the server for its cached images and plans
	// their removal (system administrator). The plan is checked again on a
	// fresh view so no image in use counts fewer references than committed.
	ImageCachePlanMethod = define(Method[ImageCachePlanQuery, imagecache.Plan]{Name: "image-cache-plan"}, false, func(ctx context.Context, s Service, view cluster.View, session access.Session, q ImageCachePlanQuery) (imagecache.Plan, string) {
		if !s.mayManageCluster(view, session) {
			return imagecache.Plan{}, "denied"
		}
		if s.ImageCachePlanner == nil {
			return imagecache.Plan{}, "unavailable"
		}
		d, err := s.Policy.Members(view.State)
		if err != nil {
			return imagecache.Plan{}, "unavailable"
		}
		entry, ok := d.Entry(q.Query.Node)
		owner, err := identity.ParseKey(entry.CurrentPeer().Key)
		if !ok || err != nil || !d.MemberKey(owner) {
			return imagecache.Plan{}, "denied"
		}
		read := control.ImageCacheRead{Owner: owner, Index: view.State.Index(), Session: session, Query: q.Query}
		if _, err = s.Policy.ImageCacheReadPermit(view.State, owner, time.Now().Unix(), read); err != nil {
			return imagecache.Plan{}, "denied"
		}
		plan, err := s.ImageCachePlanner(ctx, read)
		if err != nil {
			return imagecache.Plan{}, errorCode(err)
		}
		if !plan.Valid() || plan.Cluster != s.Policy.Cluster || plan.Owner != owner || plan.Node != read.Query.Node {
			return imagecache.Plan{}, "unavailable"
		}
		current, err := s.Engine.Read(ctx, true)
		if err != nil || current.Local {
			return imagecache.Plan{}, "unavailable"
		}
		read.Images = plan.Images
		permit, err := s.Policy.ImageCacheReadPermit(current.State, owner, time.Now().Unix(), read)
		if err != nil {
			return imagecache.Plan{}, errorCode(err)
		}
		if !sharedReferencesHeld(plan.Images, permit.References) {
			return imagecache.Plan{}, "conflict"
		}
		return plan, "ok"
	})
	// ImageCacheStatusMethod reads one image prune (system administrator).
	ImageCacheStatusMethod = define(Method[ImageCacheStatusQuery, control.ImageCacheStatus]{Name: "image-cache-status"}, false, func(_ context.Context, s Service, view cluster.View, session access.Session, q ImageCacheStatusQuery) (control.ImageCacheStatus, string) {
		if !s.mayManageCluster(view, session) {
			return control.ImageCacheStatus{}, "denied"
		}
		status, err := s.Policy.ImageCacheStatus(view.State, session, time.Now().Unix(), imagecache.Query{Operation: q.Operation})
		if err != nil {
			return control.ImageCacheStatus{}, errorCode(err)
		}
		return status, "ok"
	})
)

// sharedReferencesHeld checks the owner's per-image counts against the
// shared references committed now. The owner adds its node-private
// workload references (running tasks of this node) on top of the shared
// count, so an image in use counts more there, never fewer.
func sharedReferencesHeld(images []imagecache.Image, shared []uint64) bool {
	if len(images) != len(shared) {
		return false
	}
	for i, n := range shared {
		if images[i].References < n {
			return false
		}
	}
	return true
}

func (c Client) PlanImageCache(ctx context.Context, peer sfcp.Peer, session access.Session, q imagecache.Query) (imagecache.Plan, error) {
	p, err := call(ctx, c, peer, session, ImageCachePlanMethod, ImageCachePlanQuery{Query: q})
	if err != nil {
		return imagecache.Plan{}, err
	}
	ids := slices.Clone(q.Images)
	slices.Sort(ids)
	if !p.Valid() || p.Cluster != c.Cluster || p.Node != q.Node || !slices.Equal(ids, p.Selection) {
		return imagecache.Plan{}, sfcp.ErrFrame
	}
	for _, image := range p.Images {
		if image.ID <= q.After {
			return imagecache.Plan{}, sfcp.ErrFrame
		}
	}
	return p, nil
}

func (c Client) ImageCacheStatus(ctx context.Context, peer sfcp.Peer, session access.Session, operation string) (control.ImageCacheStatus, error) {
	r, err := call(ctx, c, peer, session, ImageCacheStatusMethod, ImageCacheStatusQuery{Operation: operation})
	if err != nil {
		return control.ImageCacheStatus{}, err
	}
	if r.Schema != 1 || r.Operation != operation || r.User == "" || r.Revision == 0 || !r.Plan.DeleteReady() || r.Plan.Cluster != c.Cluster || len(r.Parts) > len(r.Plan.Images) {
		return control.ImageCacheStatus{}, sfcp.ErrFrame
	}
	failed := false
	for i, part := range r.Parts {
		if !part.Valid() || part.ID != r.Plan.Images[i].ID {
			return control.ImageCacheStatus{}, sfcp.ErrFrame
		}
		failed = failed || part.State == "failed" || part.State == "skipped"
	}
	switch r.State {
	case "queued":
		if len(r.Parts) != 0 {
			return control.ImageCacheStatus{}, sfcp.ErrFrame
		}
	case "running":
		if len(r.Parts) >= len(r.Plan.Images) {
			return control.ImageCacheStatus{}, sfcp.ErrFrame
		}
	case "done", "failed":
		if len(r.Parts) != len(r.Plan.Images) || (r.State == "failed") != failed {
			return control.ImageCacheStatus{}, sfcp.ErrFrame
		}
	default:
		return control.ImageCacheStatus{}, sfcp.ErrFrame
	}
	return r, nil
}
