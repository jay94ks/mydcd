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

type ImageBuildContentRead struct {
	Session access.Session
	Tenant  string
	Query   imagebuild.ContentQuery
	After   string
	Scope   imagebuild.UploadScope
	Seal    imagebuild.SealReceipt
	Epoch   uint64
}
type ImageBuildContentPage struct {
	Page  imagebuild.ContentPage
	Root  [32]byte
	Epoch uint64
	Next  string `json:",omitempty"`
}

func (p ImageBuildContentPage) Valid(r ImageBuildContentRead) bool {
	offset, err := r.Offset()
	if err != nil || !p.Page.Valid(r.Query) || p.Page.Tree != r.Seal.Tree || p.Page.PageOffset() != offset || p.Root != r.Snapshot() || p.Epoch != r.Epoch {
		return false
	}
	if p.Page.Part == "tree" && p.Page.Total != r.Seal.Entries {
		return false
	}
	if p.Page.Part == "file" && (p.Page.File == nil || p.Page.File.Total > uint64(r.Seal.ExpandedBytes)) {
		return false
	}
	if p.Page.PageNext() == 0 {
		return p.Next == ""
	}
	return p.Next == buildPageNext(r.Snapshot(), fmt.Sprintf("%010d", p.Page.PageNext()))
}
func (r ImageBuildContentRead) Page(page imagebuild.ContentPage) (ImageBuildContentPage, error) {
	out := ImageBuildContentPage{Page: page, Root: r.Snapshot(), Epoch: r.Epoch}
	if page.PageNext() != 0 {
		out.Next = buildPageNext(r.Snapshot(), fmt.Sprintf("%010d", page.PageNext()))
	}
	if !out.Valid(r) {
		return ImageBuildContentPage{}, access.ErrInvalid
	}
	return out, nil
}
func (r ImageBuildContentRead) Snapshot() [32]byte {
	raw, _ := json.Marshal(struct {
		Cluster, Version, Tree [32]byte
		Tenant, Part           string
		Epoch                  uint64
		Path                   string `json:",omitempty"`
	}{r.Scope.Cluster, r.Query.Version, r.Seal.Tree, r.Tenant, r.Query.Part, r.Epoch, r.Query.Path})
	return sha256.Sum256(append([]byte("mydc-imagebuild-content-cursor-1\x00"), raw...))
}
func (r ImageBuildContentRead) Offset() (uint64, error) {
	root, key, err := registryclient.CatalogueCursor(r.After)
	if err != nil {
		return 0, access.ErrInvalid
	}
	if r.After == "" {
		return r.Query.Offset, nil
	}
	if r.Query.Offset != 0 {
		return 0, access.ErrInvalid
	}
	var offset uint64
	if root != r.Snapshot() {
		return 0, access.ErrConflict
	}
	if _, err := fmt.Sscanf(key, "%010d", &offset); err != nil || fmt.Sprintf("%010d", offset) != key {
		return 0, access.ErrInvalid
	}
	limit := uint64(imagebuild.MaxExpandedBytes)
	if r.Query.Part == "tree" {
		limit = imagebuild.MaxTreeEntries
	}
	if r.Query.Part == "dockerfile" {
		limit = imagebuild.MaxDockerfileBytes
	}
	if offset > limit {
		return 0, access.ErrInvalid
	}
	return offset, nil
}
func (p Policy) ImageBuildContentRead(s state.State, session access.Session, at int64, tenant string, q imagebuild.ContentQuery, after string) (ImageBuildContentRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildContentRead{}, err
	}
	if !validID(tenant) || !q.Valid() || len(after) > 512 {
		return ImageBuildContentRead{}, access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildContentRead{}, err
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return ImageBuildContentRead{}, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildContentRead{}, err
	}
	v, ok := b.Version(tenant, q.Version)
	if !ok || v.Deleted {
		return ImageBuildContentRead{}, access.ErrConflict
	}
	u, ok := b.Upload(tenant, v.Upload)
	if !ok || !u.Closed || u.Version != v.ID || u.Reclaimed != nil || !v.Fact.Valid(u.Scope) {
		return ImageBuildContentRead{}, access.ErrConflict
	}
	if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, u.Scope.Root.Node) != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, u.Scope.Root.Node) != nil {
		return ImageBuildContentRead{}, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, u.Scope.Root.Node)
	if err != nil || owner != u.Scope.Root.Key {
		return ImageBuildContentRead{}, access.ErrDenied
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return ImageBuildContentRead{}, err
	}
	root, ok := roots.Root(u.Scope.Root.Node, u.Scope.Root.ID)
	if !ok || root.Reference(p.Cluster) != u.Scope.Root || !slices.Contains(root.Definition.Tenants, tenant) {
		return ImageBuildContentRead{}, access.ErrDenied
	}
	read := ImageBuildContentRead{Session: session, Tenant: tenant, Query: q, After: after, Scope: u.Scope, Seal: v.Fact, Epoch: s.ModuleEpoch()}
	if _, err := read.Offset(); err != nil {
		return ImageBuildContentRead{}, err
	}
	return read, nil
}
func (p Policy) CurrentImageBuildContentRead(s state.State, read ImageBuildContentRead, at int64) (ImageBuildContentRead, error) {
	current, err := p.ImageBuildContentRead(s, read.Session, at, read.Tenant, read.Query, read.After)
	if err != nil || current.Scope != read.Scope || !buildJSONEqual(current.Seal, read.Seal) || current.Epoch != read.Epoch {
		return ImageBuildContentRead{}, access.ErrConflict
	}
	return current, nil
}
