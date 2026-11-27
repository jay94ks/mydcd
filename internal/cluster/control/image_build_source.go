// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/hex"
	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
)

type ImageBuildSourceQuery struct{ ID string }

func (q ImageBuildSourceQuery) Valid() bool { return validID(q.ID) }

type ImageBuildSourceRead struct {
	Session                                access.Session
	Tenant                                 string
	Query                                  ImageBuildSourceQuery
	Spec                                   imagebuild.ContextSpec
	Policy                                 imagebuild.Policy
	ContextRevision, PolicyRevision, Epoch uint64
}
type ImageBuildSourceResult struct {
	Schema                                 uint8
	Context, Code, Commit                  string
	Tree                                   [32]byte
	Entries, BaseSources                   uint32
	ExpandedBytes                          int64
	ContextRevision, PolicyRevision, Epoch uint64
}

func (r ImageBuildSourceResult) Valid(read ImageBuildSourceRead) bool {
	if r.Schema != 1 || r.Context != read.Spec.ID || r.ContextRevision != read.ContextRevision || r.PolicyRevision != read.PolicyRevision || r.Epoch != read.Epoch {
		return false
	}
	if r.Code != "OK" {
		return r.Commit == "" && r.Tree == ([32]byte{}) && r.Entries == 0 && r.ExpandedBytes == 0 && r.BaseSources == 0 && (r.Code == "SOURCE_FETCH" || r.Code == "UNTRUSTED_BASE" || r.Code == "INVALID_CONTEXT")
	}
	commit, err := hex.DecodeString(r.Commit)
	return err == nil && len(commit) == 20 && hex.EncodeToString(commit) == r.Commit && r.Tree != ([32]byte{}) && r.Entries > 0 && r.Entries <= imagebuild.MaxTreeEntries && r.ExpandedBytes >= 0 && r.ExpandedBytes <= read.Policy.WorkspaceBytes && r.BaseSources <= imagebuild.MaxTreeEntries
}
func (p Policy) ImageBuildSourceRead(s state.State, session access.Session, at int64, tenant string, q ImageBuildSourceQuery) (ImageBuildSourceRead, error) {
	p, err := p.Current(s)
	if err != nil {
		return ImageBuildSourceRead{}, err
	}
	if !validID(tenant) || !q.Valid() {
		return ImageBuildSourceRead{}, access.ErrInvalid
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildSourceRead{}, err
	}
	context, ok := b.Context(tenant, q.ID)
	policy, hasPolicy := b.Policy(tenant)
	if !ok || !hasPolicy || context.Deleted || policy.Deleted || context.Spec.Kind != "git" || context.Spec.Git == nil || !context.Spec.Under(policy.Spec) {
		return ImageBuildSourceRead{}, access.ErrConflict
	}
	c, err := p.Catalog(s)
	if err != nil {
		return ImageBuildSourceRead{}, err
	}
	if p.buildRootCurrent(s, c, session, at, tenant, context.Spec.Root) != nil {
		return ImageBuildSourceRead{}, access.ErrDenied
	}
	return ImageBuildSourceRead{Session: session, Tenant: tenant, Query: q, Spec: context.Spec.Own(), Policy: policy.Spec, ContextRevision: context.Revision, PolicyRevision: policy.Revision, Epoch: s.ModuleEpoch()}, nil
}
func (p Policy) CurrentImageBuildSourceRead(s state.State, read ImageBuildSourceRead, at int64) (ImageBuildSourceRead, error) {
	current, err := p.ImageBuildSourceRead(s, read.Session, at, read.Tenant, read.Query)
	if err != nil || current.ContextRevision != read.ContextRevision || current.PolicyRevision != read.PolicyRevision || current.Epoch != read.Epoch || !buildJSONEqual(current.Spec, read.Spec) || !buildJSONEqual(current.Policy, read.Policy) {
		return ImageBuildSourceRead{}, access.ErrConflict
	}
	return current, nil
}
