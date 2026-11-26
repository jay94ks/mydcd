// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/workload/volumes"
)

type VolumeFileQuery struct {
	ID, App, Volume, Path, Method, After string
	MaxBytes, Size                       int64
	Digest                               [32]byte
	Overwrite                            bool
}
type VolumeFilePlan struct {
	Change   VolumeFileChange
	Revision uint64
	Node     string
}
type VolumeFileView struct {
	ID, Method, Phase, Code string
	Revision                uint64
	Request                 VolumeFileChange
	Result                  *volumes.FileResult `json:",omitempty"`
}

func (q VolumeFileQuery) Valid(status bool) bool {
	if status {
		return lifecycle.ValidID(q.ID) && q.App == "" && q.Volume == "" && q.Path == "" && q.Method == "" && q.After == "" && q.MaxBytes == 0 && q.Size == 0 && q.Digest == ([32]byte{}) && !q.Overwrite
	}
	return q.ID == "" && (q.App == "" || lifecycle.ValidID(q.App)) && lifecycle.ValidID(q.Volume) && VolumeFileChange{Scope: volumes.Scope{Generation: 1}, Path: q.Path, After: q.After, MaxBytes: q.MaxBytes, Size: q.Size, Digest: q.Digest, Overwrite: q.Overwrite}.Valid(q.Method)
}
func (p Policy) PlanVolumeFile(s state.State, session access.Session, at int64, tenant string, q VolumeFileQuery) (VolumeFilePlan, error) {
	if !q.Valid(false) {
		return VolumeFilePlan{}, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return VolumeFilePlan{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VolumeFilePlan{}, err
	}
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeFilePlan{}, err
	}
	key := volumes.Scope{Tenant: tenant, App: q.App, ID: q.Volume}.Key()
	e, ok := v.entries[key]
	if !ok || e.State.Deleted() {
		return VolumeFilePlan{}, access.ErrDenied
	}
	if c.AuthorizeVolumeFile(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, q.App, q.Volume, q.Path, q.Method, e.Native.Owner.Node) != nil {
		return VolumeFilePlan{}, access.ErrDenied
	}
	change := VolumeFileChange{Scope: e.State.Scope(), Path: q.Path, After: q.After, MaxBytes: q.MaxBytes, Size: q.Size, Digest: q.Digest, Overwrite: q.Overwrite}
	return VolumeFilePlan{Change: change, Revision: e.State.Revision(), Node: e.Native.Owner.Node}, nil
}
func (p Policy) VolumeFileStatus(s state.State, session access.Session, at int64, tenant string, q VolumeFileQuery) (VolumeFileView, error) {
	if !q.Valid(true) {
		return VolumeFileView{}, access.ErrInvalid
	}
	p, err := p.Current(s)
	if err != nil {
		return VolumeFileView{}, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return VolumeFileView{}, err
	}
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeFileView{}, err
	}
	j, ok := v.files[q.ID]
	if !ok || j.Request.Scope.Tenant != tenant {
		return VolumeFileView{}, access.ErrDenied
	}
	r := j.Request
	if c.AuthorizeVolumeFile(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, r.Scope.App, r.Scope.ID, r.Path, j.Method, "") != nil || session.User != j.Origin.Session.User && !c.SystemAllowed(session.User) && c.Authorize(session.User, tenant, access.ManageVolumes, "") != nil {
		return VolumeFileView{}, access.ErrDenied
	}
	return VolumeFileView{ID: j.ID, Method: j.Method, Phase: j.Phase, Code: j.Code, Revision: j.Revision, Request: r, Result: j.Result}, nil
}
