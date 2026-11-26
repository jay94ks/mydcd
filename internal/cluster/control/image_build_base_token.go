// SPDX-License-Identifier: Apache-2.0

package control

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/registryclient"
)

type ImageBuildBaseTokenRequest struct {
	Read       ImageBuildBaseRead
	Challenge  registryclient.PullTokenChallenge
	Additional []ImageBuildBaseRead `json:",omitempty"`
}

func (q ImageBuildBaseTokenRequest) References() []string {
	refs := []string{q.Read.Target.Normalized}
	for _, read := range q.Additional {
		refs = append(refs, read.Target.Normalized)
	}
	return refs
}

// A token may outlive this RPC. Require the original running job's signed
// reader reservation before any credential use, then recheck after exchange.
func (p Policy) CurrentImageBuildBaseToken(s state.State, q ImageBuildBaseTokenRequest, at int64) (ImageBuildBaseRead, error) {
	if len(q.Additional) > 7 {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	read, err := p.CurrentImageBuildBaseMaterial(s, q.Read, at)
	if err != nil || len(q.Additional) > 0 && read.Target.Managed != nil {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	_, authority, repo, err := registryclient.Normalize(read.Target.Normalized)
	if err != nil {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	seen := map[string]bool{authority + "/" + repo: true}
	for _, item := range q.Additional {
		current, err := p.CurrentImageBuildBaseMaterial(s, item, at)
		if err != nil || !sameBuildTokenOwner(read, current) {
			return ImageBuildBaseRead{}, access.ErrDenied
		}
		_, authority, repo, err := registryclient.Normalize(current.Target.Normalized)
		key := authority + "/" + repo
		if err != nil || seen[key] {
			return ImageBuildBaseRead{}, access.ErrDenied
		}
		seen[key] = true
	}
	if !q.Challenge.ValidForImages(q.References()) {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	return read, nil
}

func sameBuildTokenOwner(a, b ImageBuildBaseRead) bool {
	if a.Cluster != b.Cluster || a.Builder != b.Builder || a.Query.Tenant != b.Query.Tenant || a.Query.Job != b.Query.Job || a.Query.Snapshot != b.Query.Snapshot || a.Target.Owner != b.Target.Owner || a.Target.Kind != b.Target.Kind || a.Target.Source != b.Target.Source || (a.Target.External == nil) != (b.Target.External == nil) || a.Target.ExternalReadSet != b.Target.ExternalReadSet {
		return false
	}
	if a.Target.External != nil && *a.Target.External != *b.Target.External {
		return false
	}
	// Managed login credentials are currently issued for one repository.
	// Only the legacy single-read path may use them; never broaden that grant.
	return a.Target.Managed == nil && b.Target.Managed == nil
}

func (p Policy) CurrentImageBuildBaseMaterial(s state.State, original ImageBuildBaseRead, at int64) (ImageBuildBaseRead, error) {
	read, err := p.CurrentImageBuildBaseRead(s, original, at)
	if err != nil || read.Target.Code != "" {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	book, err := p.ImageBuilds(s)
	if err != nil {
		return ImageBuildBaseRead{}, err
	}
	row, ok := book.Job(read.Query.Tenant, read.Query.Job)
	if !ok || row.Begin == nil || row.Run.Phase != "running" && row.Run.Phase != "unknown" {
		return ImageBuildBaseRead{}, access.ErrDenied
	}
	return read, nil
}
