// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/imagebuild"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type ImageBuildLogRead struct {
	Session access.Session
	Tenant  string
	Query   imagebuild.LogQuery
	After   string
	Spec    imagebuild.JobSpec
	Epoch   uint64
	Phase   string
}
type ImageBuildLogPage struct {
	Page        imagebuild.LogPage
	Tenant, Job string
	Root        [32]byte
	Epoch       uint64
	Phase, Next string
}

func ImageBuildLogCursorRoot(cluster [32]byte, tenant string, job [32]byte, epoch uint64) [32]byte {
	raw, _ := json.Marshal(struct {
		Cluster, Job [32]byte
		Tenant       string
		Epoch        uint64
	}{cluster, job, tenant, epoch})
	return sha256.Sum256(append([]byte("mydc-imagebuild-log-cursor-1\x00"), raw...))
}
func ImageBuildLogOffset(after string) ([32]byte, uint32, error) {
	root, key, err := registryclient.CatalogueCursor(after)
	if err != nil {
		return root, 0, access.ErrInvalid
	}
	if after == "" {
		return root, 0, nil
	}
	var offset uint32
	if _, err := fmt.Sscanf(key, "%010d", &offset); err != nil || fmt.Sprintf("%010d", offset) != key || offset > imagebuild.MaxLogBytes {
		return root, 0, access.ErrInvalid
	}
	return root, offset, nil
}
func (r ImageBuildLogRead) Snapshot() [32]byte {
	return ImageBuildLogCursorRoot(r.Spec.Cluster, r.Tenant, r.Spec.Digest(), r.Epoch)
}
func (r ImageBuildLogRead) Offset() (uint32, error) {
	if r.Query.Tail && r.After != "" {
		return 0, access.ErrInvalid
	}
	root, offset, err := ImageBuildLogOffset(r.After)
	if err != nil {
		return 0, err
	}
	if r.After != "" && root != r.Snapshot() {
		return 0, access.ErrConflict
	}
	return offset, nil
}
func (p ImageBuildLogPage) Valid(r ImageBuildLogRead) bool {
	return p.Page.Job == r.Spec.Digest() && p.Epoch == r.Epoch && p.ValidQuery(r.Spec.Cluster, r.Tenant, r.Query, r.After)
}
func (p ImageBuildLogPage) ValidQuery(cluster [32]byte, tenant string, q imagebuild.LogQuery, after string) bool {
	root, offset, err := ImageBuildLogOffset(after)
	if q.Tail {
		offset = p.Page.Total - min(p.Page.Total, q.MaxBytes)
	}
	if err != nil || q.Tail && after != "" || !q.Valid() || p.Tenant != tenant || p.Job != q.Job || !p.Page.Valid(p.Page.Job, offset, q.MaxBytes) || p.Epoch == 0 || p.Root != ImageBuildLogCursorRoot(cluster, tenant, p.Page.Job, p.Epoch) || after != "" && p.Root != root || p.Next != buildPageNext(p.Root, fmt.Sprintf("%010d", p.Page.Next)) {
		return false
	}
	switch p.Phase {
	case "queued", "running", "unknown", "succeeded", "failed", "cancelled":
		return true
	}
	return false
}
func (r ImageBuildLogRead) Page(page imagebuild.LogPage) (ImageBuildLogPage, error) {
	out := ImageBuildLogPage{Page: page, Tenant: r.Tenant, Job: r.Query.Job, Root: r.Snapshot(), Epoch: r.Epoch, Phase: r.Phase}
	out.Next = buildPageNext(out.Root, fmt.Sprintf("%010d", page.Next))
	if !out.Valid(r) {
		return ImageBuildLogPage{}, access.ErrInvalid
	}
	return out, nil
}
func (p Policy) ImageBuildLogRead(s state.State, session access.Session, at int64, tenant string, q imagebuild.LogQuery, after string) (ImageBuildLogRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildLogRead{}, err
	}
	if !validID(tenant) || !q.Valid() || len(after) > 512 {
		return ImageBuildLogRead{}, access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildLogRead{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ImageBuildLogRead{}, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildLogRead{}, err
	}
	job, exists := b.Job(tenant, q.Job)
	if !exists || job.Deleted {
		return ImageBuildLogRead{}, access.ErrConflict
	}
	spec := job.Run.Spec
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, spec.Scope.Root.Node) != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, spec.Scope.Root.Node) != nil {
		return ImageBuildLogRead{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, spec.Scope.Root.Node)
	if err != nil || owner != spec.Scope.Root.Key {
		return ImageBuildLogRead{}, access.ErrDenied
	}
	read := ImageBuildLogRead{Session: session, Tenant: tenant, Query: q, After: after, Spec: spec.Own(), Epoch: s.ModuleEpoch(), Phase: job.Run.Phase}
	if _, err := read.Offset(); err != nil {
		return ImageBuildLogRead{}, err
	}
	return read, nil
}
func (p Policy) CurrentImageBuildLogRead(s state.State, read ImageBuildLogRead, at int64) (ImageBuildLogRead, error) {
	current, err := p.ImageBuildLogRead(s, read.Session, at, read.Tenant, read.Query, read.After)
	if err != nil {
		return ImageBuildLogRead{}, err
	}
	if current.Spec.Digest() != read.Spec.Digest() || current.Epoch != read.Epoch {
		return ImageBuildLogRead{}, access.ErrConflict
	}
	return current, nil
}

func (p Policy) ImageBuildLogReclaim(s state.State, caller [32]byte, spec imagebuild.JobSpec) (imagebuild.JobClosure, error) {
	p, err := p.Current(s)
	if err != nil {
		return imagebuild.JobClosure{}, err
	}
	if spec.Validate() != nil || spec.Cluster != p.Cluster || caller != spec.Scope.Root.Key {
		return imagebuild.JobClosure{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, spec.Scope.Root.Node)
	if err != nil || owner != caller {
		return imagebuild.JobClosure{}, access.ErrDenied
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return imagebuild.JobClosure{}, err
	}
	row, exists := book.Job(spec.Tenant, spec.ID)
	if !exists || !row.Deleted || !row.Run.Terminal() || row.Run.Spec.Digest() != spec.Digest() || row.Run.Closure == nil {
		return imagebuild.JobClosure{}, access.ErrConflict
	}
	closure := *row.Run.Closure
	closure.Signature = slices.Clone(closure.Signature)
	return closure, nil
}
