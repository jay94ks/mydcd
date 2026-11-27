// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/imagecache"
)

// fixtureNodeImage: one image in the fake's per-server Docker cache,
// keyed by its reference. ID is the full sha256 image ID.
type fixtureNodeImage struct {
	Ref   string
	ID    string
	Bytes int64
}

// nodeImageCache: the server's cache, seeded on first use.
func (w *world) nodeImageCache(node string) map[string]fixtureNodeImage {
	if w.nodeImages[node] == nil {
		c := map[string]fixtureNodeImage{}
		for _, ref := range []string{"registry.sfc.local/shop/php-shop:1.3.9", "docker.io/library/busybox:1.35"} {
			d := digestOf([]byte(node + ref))
			c[ref] = fixtureNodeImage{Ref: ref, ID: "sha256:" + hexOf(d[:]), Bytes: 40<<20 + int64(d[0])<<20}
		}
		w.nodeImages[node] = c
	}
	return w.nodeImages[node]
}

// AddNodeImage puts an unused image into a server's cache.
func (f *Fake) AddNodeImage(node, ref string, bytes int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := digestOf([]byte(node + ref))
	f.w.nodeImageCache(node)[ref] = fixtureNodeImage{Ref: ref, ID: "sha256:" + hexOf(d[:]), Bytes: bytes}
}

// cacheImages: the server's images as image-cache-plan rows, by ID.
// Containers counts the fake's tasks and standalone containers there that
// run the reference; the fake has no other shared references.
func (w *world) cacheImages(node string) []imagecache.Image {
	used := map[string]uint64{}
	for _, a := range w.apps {
		for _, t := range a.tasks {
			if t.Node == node {
				used[t.Image]++
			}
		}
	}
	for _, s := range w.standalones {
		if s.view.Node == node {
			used[s.view.Image]++
		}
	}
	out := []imagecache.Image{}
	for _, img := range w.nodeImageCache(node) {
		row := imagecache.Image{ID: img.ID, Aliases: []string{}, Bytes: img.Bytes, Containers: used[img.Ref]}
		if a, err := imagecache.CanonicalReference(img.Ref); err == nil && a != img.ID {
			row.Aliases = append(row.Aliases, a)
		}
		out = append(out, row)
	}
	slices.SortFunc(out, func(a, b imagecache.Image) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	return out
}

func (w *world) imageCachePlan(q ImageCacheQuery, nowMs int64) (ImageCachePlan, bool) {
	// The owner signs with its fixture key (a rotated identity keeps it).
	key := FixtureKey(q.Node)
	var owner [32]byte
	copy(owner[:], key.Public().(ed25519.PublicKey))
	p := ImageCachePlan{Schema: 1, Cluster: w.cluster, Owner: owner, Boot: fakeDigest("boot", q.Node), Node: q.Node, At: uint64(nowMs), Index: max(w.root, 1),
		Images: []imagecache.Image{}}
	all := w.cacheImages(q.Node)
	if len(q.Images) > 0 {
		p.Selection = slices.Sorted(slices.Values(q.Images))
		for _, id := range p.Selection {
			i := slices.IndexFunc(all, func(x imagecache.Image) bool { return x.ID == id })
			if i < 0 {
				return ImageCachePlan{}, false
			}
			p.Images = append(p.Images, all[i])
		}
		return signPlan(p, key), true
	}
	for _, img := range all {
		if img.ID <= q.After {
			continue
		}
		if len(p.Images) == imagecache.MaxImages {
			p.Next = p.Images[len(p.Images)-1].ID
			break
		}
		p.Images = append(p.Images, img)
	}
	return signPlan(p, key), true
}

func signPlan(p ImageCachePlan, key ed25519.PrivateKey) ImageCachePlan {
	p.Signature = ed25519.Sign(key, imagecache.PlanBytes(p))
	return p
}

// ImageCachePlan: `image-cache-plan` (system admin).
func (c *fakeConn) ImageCachePlan(ctx context.Context, q ImageCacheQuery) (ImageCachePlan, error) {
	const m = "image-cache-plan"
	if !q.Valid(true) {
		return ImageCachePlan{}, fail(m, CodeInvalid, "")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return ImageCachePlan{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(user) {
		return ImageCachePlan{}, fail(m, CodeDenied, "")
	}
	if w.memberIndex(q.Node) < 0 {
		return ImageCachePlan{}, fail(m, CodeDenied, "")
	}
	p, ok := w.imageCachePlan(q, c.f.now().UnixMilli())
	if !ok {
		return ImageCachePlan{}, fail(m, CodeConflict, "")
	}
	return p, nil
}

// ImageCacheStatus: `image-cache-status` (system admin).
func (c *fakeConn) ImageCacheStatus(ctx context.Context, operation string) (ImageCacheStatus, error) {
	const m = "image-cache-status"
	if !(ImageCacheQuery{Operation: operation}).Valid(false) {
		return ImageCacheStatus{}, fail(m, CodeInvalid, "")
	}
	user, err := c.lockSession(ctx, m)
	if err != nil {
		return ImageCacheStatus{}, err
	}
	defer c.unlock()
	w := c.f.w
	if !w.admin(user) {
		return ImageCacheStatus{}, fail(m, CodeDenied, "")
	}
	st, ok := w.imageJobs[operation]
	if !ok {
		return ImageCacheStatus{}, fail(m, CodeMissing, "")
	}
	return st, nil
}

// applyImagePrune: prune-node-images, Expected 0. The selection plan must
// still describe the server's images (same IDs, all unused) and the
// operation must be new; the fake removes the images at once.
func (c *fakeConn) applyImagePrune(op UserOperation, actor string, now int64) error {
	w := c.f.w
	var q ImageCacheChange
	if decodePayload(op.Change.Payload, &q) != nil || !q.Valid() || op.Change.Expected != 0 || q.Plan.Cluster != w.cluster {
		return errors.New("payload")
	}
	if !w.admin(actor) {
		return errForbidden
	}
	if w.memberIndex(q.Plan.Node) < 0 {
		return errors.New("unknown node")
	}
	if _, dup := w.imageJobs[q.Operation]; dup {
		return errCAS
	}
	cur, ok := w.imageCachePlan(ImageCacheQuery{Node: q.Plan.Node, Images: q.Plan.Selection}, now*1000)
	if !ok || !cur.DeleteReady() {
		return errCAS
	}
	st := ImageCacheStatus{Schema: 1, Operation: q.Operation, User: actor, State: "done", Revision: 1, RootRevision: max(w.root, 1), At: uint64(now), Plan: q.Plan}
	cache := w.nodeImages[q.Plan.Node]
	for _, img := range q.Plan.Images {
		for ref, x := range cache {
			if x.ID == img.ID {
				delete(cache, ref)
			}
		}
		st.Parts = append(st.Parts, imagecache.Part{ID: img.ID, State: "removed", At: uint64(now)})
	}
	w.imageJobs[q.Operation] = st
	return nil
}
