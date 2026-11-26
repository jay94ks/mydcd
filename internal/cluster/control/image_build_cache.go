// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type ImageBuildCacheRead struct {
	Session access.Session
	Tenant  string
	Query   imagebuild.CacheQuery
	After   string
	Spec    imagebuild.JobSpec
	Epoch   uint64
}

type ImageBuildCachePage struct {
	Page                       imagebuild.CachePage
	Tenant, Job, Context, Node string
	JobSnapshot                [32]byte
	CacheScope                 *[32]byte `json:",omitempty"`
	Epoch                      uint64
	Next                       string
}

// The existing bounded catalogue cursor carries the native observation hash,
// original selected job or explicit cache scope and current epoch. Progress may advance without
// changing the cursor; a new observation requires restarting pagination.
func ImageBuildCacheOffset(after string) (snapshot, job [32]byte, epoch uint64, offset uint32, err error) {
	var key string
	snapshot, key, err = registryclient.CatalogueCursor(after)
	if err != nil || after == "" {
		return
	}
	parts := strings.Split(key, "/")
	if len(parts) != 3 {
		err = access.ErrInvalid
		return
	}
	raw, e := hex.DecodeString(parts[0])
	if e != nil || len(raw) != 32 || hex.EncodeToString(raw) != parts[0] {
		err = access.ErrInvalid
		return
	}
	copy(job[:], raw)
	epoch, e = strconv.ParseUint(parts[1], 10, 64)
	if e != nil || epoch == 0 || strconv.FormatUint(epoch, 10) != parts[1] {
		err = access.ErrInvalid
		return
	}
	n, e := strconv.ParseUint(parts[2], 10, 32)
	if e != nil || n == 0 || n > imagebuild.MaxCacheEntries || fmt.Sprintf("%010d", n) != parts[2] || snapshot == ([32]byte{}) || job == ([32]byte{}) {
		err = access.ErrInvalid
		return
	}
	offset = uint32(n)
	return
}

func (r ImageBuildCacheRead) Offset() ([32]byte, uint32, error) {
	snapshot, job, epoch, offset, err := ImageBuildCacheOffset(r.After)
	if err != nil {
		return snapshot, 0, err
	}
	if r.After != "" && (job != r.Binding() || epoch != r.Epoch) {
		return snapshot, 0, access.ErrConflict
	}
	return snapshot, offset, nil
}

func (r ImageBuildCacheRead) Binding() [32]byte {
	if r.Query.Cache != nil {
		return imagebuild.CacheIdentity(r.Spec)
	}
	return r.Spec.Digest()
}

func cachePageNext(snapshot, job [32]byte, epoch uint64, next uint32) string {
	if next == 0 {
		return ""
	}
	return buildPageNext(snapshot, fmt.Sprintf("%x/%d/%010d", job, epoch, next))
}

func (p ImageBuildCachePage) ValidQuery(tenant string, q imagebuild.CacheQuery, after string) bool {
	snapshot, job, epoch, offset, err := ImageBuildCacheOffset(after)
	if err != nil || !q.Valid() || p.Tenant != tenant || !validID(p.Job) || !validID(p.Context) || !validID(p.Node) || p.JobSnapshot == ([32]byte{}) || p.Epoch == 0 {
		return false
	}
	binding := p.JobSnapshot
	if q.Cache != nil {
		if p.CacheScope == nil || *p.CacheScope != *q.Cache || p.Page.Cache != *q.Cache || p.Node != q.Node {
			return false
		}
		binding = *q.Cache
	} else if p.CacheScope != nil || p.Job != q.Job {
		return false
	}
	return (after == "" || job == binding && epoch == p.Epoch) && p.Page.Valid(p.Page.Cache, offset, snapshot) && p.Next == cachePageNext(p.Page.Snapshot, binding, p.Epoch, p.Page.Next)
}
func (p ImageBuildCachePage) Valid(r ImageBuildCacheRead) bool {
	return p.ValidQuery(r.Tenant, r.Query, r.After) && (r.Query.Cache != nil || p.JobSnapshot == r.Spec.Digest()) && p.Context == r.Spec.Context.ID && p.Node == r.Spec.Scope.Root.Node && p.Epoch == r.Epoch && p.Page.Cache == imagebuild.CacheIdentity(r.Spec)
}
func (r ImageBuildCacheRead) Page(page imagebuild.CachePage) (ImageBuildCachePage, error) {
	out := ImageBuildCachePage{Page: page, Tenant: r.Tenant, Job: r.Spec.ID, Context: r.Spec.Context.ID, Node: r.Spec.Scope.Root.Node, JobSnapshot: r.Spec.Digest(), Epoch: r.Epoch}
	if r.Query.Cache != nil {
		cache := imagebuild.CacheIdentity(r.Spec)
		out.CacheScope = &cache
	}
	out.Next = cachePageNext(page.Snapshot, r.Binding(), out.Epoch, page.Next)
	if !out.Valid(r) {
		return ImageBuildCachePage{}, access.ErrInvalid
	}
	return out, nil
}

func (p Policy) ImageBuildCacheRead(s state.State, session access.Session, at int64, tenant string, q imagebuild.CacheQuery, after string) (ImageBuildCacheRead, error) {
	if !q.Valid() || len(after) > 512 {
		return ImageBuildCacheRead{}, access.ErrInvalid
	}
	if q.Cache != nil {
		return p.imageBuildCacheScopeRead(s, session, at, tenant, q, after)
	}
	// Same current user/node/tenant/root-owner read authority as build logs.
	base, err := p.ImageBuildLogRead(s, session, at, tenant, imagebuild.LogQuery{Job: q.Job, MaxBytes: 1}, "")
	if err != nil {
		return ImageBuildCacheRead{}, err
	}
	r := ImageBuildCacheRead{Session: session, Tenant: tenant, Query: q, After: after, Spec: base.Spec, Epoch: base.Epoch}
	if _, _, err := r.Offset(); err != nil {
		return ImageBuildCacheRead{}, err
	}
	return r, nil
}
func (p Policy) CurrentImageBuildCacheRead(s state.State, r ImageBuildCacheRead, at int64) (ImageBuildCacheRead, error) {
	current, err := p.ImageBuildCacheRead(s, r.Session, at, r.Tenant, r.Query, r.After)
	if err != nil {
		return ImageBuildCacheRead{}, err
	}
	if current.Binding() != r.Binding() || current.Epoch != r.Epoch {
		return ImageBuildCacheRead{}, access.ErrConflict
	}
	return current, nil
}

func (p Policy) imageBuildCacheScopeRead(s state.State, session access.Session, at int64, tenant string, q imagebuild.CacheQuery, after string) (ImageBuildCacheRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildCacheRead{}, err
	}
	if !validID(tenant) || !q.Valid() || q.Cache == nil {
		return ImageBuildCacheRead{}, access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildCacheRead{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, q.Node) != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, q.Node) != nil {
		return ImageBuildCacheRead{}, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildCacheRead{}, err
	}
	row, found := imageBuildCacheRepresentative(b, tenant, q.Node, *q.Cache)
	if !found {
		return ImageBuildCacheRead{}, access.ErrConflict
	}
	spec := row.Run.Spec
	owner, err := p.nodeOwner(s, q.Node)
	if err != nil || owner != spec.Scope.Root.Key {
		return ImageBuildCacheRead{}, access.ErrDenied
	}
	cache := *q.Cache
	q.Cache = &cache // Keep caller-owned query memory outside the returned plan.
	r := ImageBuildCacheRead{Session: session, Tenant: tenant, Query: q, After: after, Spec: spec.Own(), Epoch: s.ModuleEpoch()}
	if _, _, err := r.Offset(); err != nil {
		return ImageBuildCacheRead{}, err
	}
	return r, nil
}
