// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/imagecache"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (s Service) imageCacheQuery(ctx context.Context, view cluster.View, request Request, session access.Session) Reply {
	out := Reply{Schema: 1, Code: "unavailable"}
	var err error
	if request.Method == "image-cache-status" {
		status, e := s.Policy.ImageCacheStatus(view.State, session, time.Now().Unix(), *request.ImageCache)
		err = e
		if err == nil {
			out.Code, out.ImageCacheStatus = "ok", &status
		}
	} else {
		if s.ImageCachePlanner == nil {
			return out
		}
		d, e := s.Policy.Members(view.State)
		if e != nil {
			return out
		}
		entry, ok := d.Entry(request.ImageCache.Node)
		owner, e := identity.ParseKey(entry.CurrentPeer().Key)
		if !ok || e != nil || !d.MemberKey(owner) {
			return Reply{Schema: 1, Code: "denied"}
		}
		read := control.ImageCacheRead{Owner: owner, Index: view.State.Index(), Session: session, Query: *request.ImageCache}
		if _, err = s.Policy.ImageCacheReadPermit(view.State, owner, time.Now().Unix(), read); err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		var plan imagecache.Plan
		plan, err = s.ImageCachePlanner(ctx, read)
		if err == nil {
			if !plan.Valid() || plan.Cluster != s.Policy.Cluster || plan.Owner != owner || plan.Node != read.Query.Node {
				return out
			}
			current, e := s.Engine.Read(ctx, true)
			if e != nil || current.Local {
				return out
			}
			read.Images = plan.Images
			permit, e := s.Policy.ImageCacheReadPermit(current.State, owner, time.Now().Unix(), read)
			err = e
			if err == nil {
				if !sharedReferencesHeld(plan.Images, permit.References) {
					return Reply{Schema: 1, Code: "conflict"}
				}
				out.Code, out.ImageCachePlan = "ok", &plan
			}
		}
	}
	if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
		out.Code = "denied"
	}
	if errors.Is(err, access.ErrConflict) {
		out.Code = "conflict"
	}
	return out
}

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

func (c Client) QueryImageCache(ctx context.Context, peer mydcp.Peer, session access.Session, plan bool, q imagecache.Query) (Reply, error) {
	if !q.Valid(plan) {
		return Reply{}, mydcp.ErrAdmission
	}
	method := "image-cache-status"
	if plan {
		method = "image-cache-plan"
	}
	reply, err := c.query(ctx, peer, session, Request{Method: method, ImageCache: &q})
	if err != nil {
		return reply, err
	}
	if plan {
		p := reply.ImageCachePlan
		ids := slices.Clone(q.Images)
		slices.Sort(ids)
		if p == nil || !p.Valid() || p.Cluster != c.Cluster || p.Node != q.Node || !slices.Equal(ids, p.Selection) {
			return Reply{}, mydcp.ErrFrame
		}
		for _, image := range p.Images {
			if image.ID <= q.After {
				return Reply{}, mydcp.ErrFrame
			}
		}
	} else {
		r := reply.ImageCacheStatus
		if r == nil || r.Schema != 1 || r.Operation != q.Operation || r.User == "" || r.Revision == 0 || !r.Plan.DeleteReady() || r.Plan.Cluster != c.Cluster || len(r.Parts) > len(r.Plan.Images) {
			return Reply{}, mydcp.ErrFrame
		}
		failed := false
		for i, part := range r.Parts {
			if !part.Valid() || part.ID != r.Plan.Images[i].ID {
				return Reply{}, mydcp.ErrFrame
			}
			failed = failed || part.State == "failed" || part.State == "skipped"
		}
		switch r.State {
		case "queued":
			if len(r.Parts) != 0 {
				return Reply{}, mydcp.ErrFrame
			}
		case "running":
			if len(r.Parts) >= len(r.Plan.Images) {
				return Reply{}, mydcp.ErrFrame
			}
		case "done", "failed":
			if len(r.Parts) != len(r.Plan.Images) || (r.State == "failed") != failed {
				return Reply{}, mydcp.ErrFrame
			}
		default:
			return Reply{}, mydcp.ErrFrame
		}
	}
	return reply, nil
}
