// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/imagecache"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/schema"
)

func (r *Runtime) imageCachePermit(ctx context.Context, read control.ImageCacheRead) (control.ImageCachePermit, error) {
	raw, err := json.Marshal(read)
	if err != nil {
		return control.ImageCachePermit{}, err
	}
	reply, err := r.appCall(ctx, "image-cache-plan-permit", raw)
	if err != nil {
		return control.ImageCachePermit{}, err
	}
	permit, err := schema.Decode[control.ImageCachePermit](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || permit.Owner != r.Identity.Public || permit.Node != r.Engine().ObservedNodeID() || permit.Index < read.Index || permit.Epoch == 0 || len(permit.References) != len(read.Images) {
		return permit, mydcp.ErrAdmission
	}
	if _, err = r.Engine().ReadAtLeast(ctx, permit.Index); err != nil {
		return permit, err
	}
	return permit, nil
}
func (r *Runtime) nativeImageCachePlan(ctx context.Context, read control.ImageCacheRead) (imagecache.Plan, error) {
	r.imageUseMu.Lock()
	defer r.imageUseMu.Unlock()
	var out imagecache.Plan
	if len(r.Identity.Certificate.Certificate) == 0 {
		return out, mydcp.ErrAdmission
	}
	if read.Owner != r.Identity.Public || read.Query.Node != r.Engine().ObservedNodeID() || len(read.Images) != 0 || !read.Query.Valid(true) {
		return out, mydcp.ErrAdmission
	}
	if _, err := r.imageCachePermit(ctx, read); err != nil {
		return out, err
	}
	r.life.RLock()
	defer r.life.RUnlock()
	if r.closed || r.docker == nil {
		return out, mydcp.ErrAdmission
	}
	rows, next, err := r.docker.CacheCandidates(ctx, read.Query.Images, read.Query.After)
	if err != nil {
		return out, err
	}
	read.Images = rows
	permit, err := r.imageCachePermit(ctx, read)
	if err != nil {
		return out, err
	}
	for i := range rows {
		private, err := r.privateImageReferences(rows[i].ID)
		if err != nil {
			return out, err
		}
		rows[i].References = permit.References[i] + private
	}
	selection := slices.Clone(read.Query.Images)
	slices.Sort(selection)
	out = imagecache.Plan{Schema: 1, Cluster: r.controlPolicy.Cluster, Owner: r.Identity.Public, Boot: sha256.Sum256(r.Identity.Certificate.Certificate[0]), Node: read.Query.Node, At: uint64(time.Now().UnixMilli()), Index: permit.Index, Selection: selection, Images: rows, Next: next}
	out.Signature = ed25519.Sign(r.Identity.Private, imagecache.PlanBytes(out))
	if !out.Valid() {
		return imagecache.Plan{}, imagecache.ErrPlan
	}
	return out, nil
}
func (r *Runtime) imageCachePlan(ctx context.Context, read control.ImageCacheRead) (imagecache.Plan, error) {
	if _, err := r.Engine().ReadAtLeast(ctx, read.Index); err != nil {
		return imagecache.Plan{}, err
	}
	if read.Owner == r.Identity.Public {
		return r.nativeImageCachePlan(ctx, read)
	}
	peer, ok := r.Mesh.Peer(mydcp.Identity(read.Owner))
	if !ok || !peer.Member || peer.ID != read.Query.Node {
		return imagecache.Plan{}, mydcp.ErrAdmission
	}
	raw, err := json.Marshal(read)
	if err != nil {
		return imagecache.Plan{}, err
	}
	reply, err := cluster.CallManagement(ctx, r.Mesh, r.Identity, r.controlPolicy.Cluster, peer, cluster.ManagementRequest{Method: "image-cache-native-plan", Input: raw})
	if err != nil {
		return imagecache.Plan{}, err
	}
	plan, err := schema.Decode[imagecache.Plan](reply.Data)
	if err != nil || !plan.Valid() || plan.Owner != read.Owner || plan.Node != read.Query.Node || plan.Cluster != r.controlPolicy.Cluster {
		return imagecache.Plan{}, imagecache.ErrPlan
	}
	return plan, nil
}
