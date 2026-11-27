// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/imagebuild"
	"github.com/jay94ks/seafield/internal/registryclient"
)

type ImageBuildQuery struct {
	Part, ID, Upload string
	Job              string `json:",omitempty"`
	Node             string `json:",omitempty"`
}

func (q ImageBuildQuery) Valid() bool {
	if q.Node != "" && (q.Part != "caches" && q.Part != "cache-prunes" || !validID(q.Node)) {
		return false
	}
	if q.Job != "" && q.Part != "jobs" {
		return false
	}
	switch q.Part {
	case "cache-prunes":
		return q.Upload == "" && (q.ID == "" || validID(q.ID))
	case "caches":
		return q.Upload == "" && (q.ID == "" || validID(q.ID))
	case "jobs":
		return q.Upload == "" && (q.ID == "" || validID(q.ID)) && (q.Job == "" || validID(q.Job))
	case "policy":
		return q.ID == "" && q.Upload == ""
	case "contexts":
		return q.Upload == "" && (q.ID == "" || validID(q.ID))
	case "versions":
		return validID(q.ID) && q.Upload == ""
	case "uploads":
		return q.ID == "" && (q.Upload == "" || validID(q.Upload))
	case "missing":
		return q.ID == "" && validID(q.Upload)
	}
	return false
}

type ImageBuildPolicyView struct {
	Spec     imagebuild.Policy
	Revision uint64
	Deleted  bool
}
type ImageBuildContextView struct {
	Spec                  imagebuild.ContextSpec
	Revision, NextVersion uint64
	Deleted               bool
	DataGeneration        uint64                        `json:",omitempty"`
	GitObservation        *ImageBuildGitObservationView `json:",omitempty"`
}
type ImageBuildUploadView struct {
	Scope       imagebuild.UploadScope
	Revision    uint64
	Received    uint32
	Closed      bool
	Version     [32]byte
	ExpiredAt   uint64 `json:",omitempty"`
	ReclaimedAt uint64 `json:",omitempty"`
}
type ImageBuildVersionView struct {
	ID                   [32]byte
	Context, Upload      string
	Number               uint64
	Bytes, ExpandedBytes int64
	Entries              uint32
	Tree                 [32]byte
	At                   int64
	Deleted              bool
	Commit               string `json:",omitempty"`
}
type ImageBuildPage struct {
	Schema              uint8
	Tenant, Part        string
	RootRevision, Epoch uint64
	Policies            []ImageBuildPolicyView        `json:",omitempty"`
	Contexts            []ImageBuildContextView       `json:",omitempty"`
	Uploads             []ImageBuildUploadView        `json:",omitempty"`
	Versions            []ImageBuildVersionView       `json:",omitempty"`
	Jobs                []ImageBuildJobView           `json:",omitempty"`
	Caches              []ImageBuildCacheInventoryRow `json:",omitempty"`
	CachePrunes         []ImageBuildCachePruneView    `json:",omitempty"`
	InventoryRoot       *[32]byte                     `json:",omitempty"`
	Missing             []uint32                      `json:",omitempty"`
	UploadRevision      uint64                        `json:",omitempty"`
	Next                string                        `json:",omitempty"`
}

func imageBuildCursor(cluster [32]byte, s state.State, tenant string, q ImageBuildQuery) [32]byte {
	if q.Part == "cache-prunes" {
		return sha256.Sum256([]byte(fmt.Sprintf("sfc-build-cache-prune-page-1\x00%x\x00%s\x00%s\x00%s\x00%d\x00%d", cluster, tenant, q.ID, q.Node, s.Object(ImageBuildKey).Revision, s.ModuleEpoch())))
	}
	if q.Job != "" {
		return sha256.Sum256([]byte(fmt.Sprintf("sfc-imagebuild-job-page-1\x00%x\x00%s\x00%s\x00%s\x00%d\x00%d", cluster, tenant, q.ID, q.Job, s.Object(ImageBuildKey).Revision, s.ModuleEpoch())))
	}
	return sha256.Sum256([]byte(fmt.Sprintf("sfc-imagebuild-page-1\x00%x\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d", cluster, tenant, q.Part, q.ID, q.Upload, s.Object(ImageBuildKey).Revision, s.ModuleEpoch())))
}
func buildPageNext(snapshot [32]byte, key string) string {
	raw := append([]byte{1}, snapshot[:]...)
	return base64.RawURLEncoding.EncodeToString(append(raw, []byte(key)...))
}
func (p Policy) ImageBuildPage(s state.State, session access.Session, at int64, tenant string, q ImageBuildQuery, after string) (ImageBuildPage, error) {
	var out ImageBuildPage
	p, err := p.Current(s)
	if err != nil {
		return out, err
	}
	c, err := p.Catalog(s)
	if err != nil {
		return out, err
	}
	if !validID(tenant) || !q.Valid() || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, "") != nil {
		return out, access.ErrDenied
	}
	b, err := p.ImageBuilds(s)
	if err != nil {
		return out, err
	}
	if q.Part == "caches" {
		return p.imageBuildCacheInventoryPage(s, c, b, session, at, tenant, q, after)
	}
	if q.Part == "cache-prunes" && q.Node != "" && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, q.Node) != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, q.Node) != nil {
		return out, access.ErrDenied
	}
	snapshot := imageBuildCursor(p.Cluster, s, tenant, q)
	prior, key, err := registryclient.CatalogueCursor(after)
	if err != nil {
		return out, access.ErrInvalid
	}
	if after != "" && prior != snapshot {
		return out, access.ErrConflict
	}
	out = ImageBuildPage{Schema: 1, Tenant: tenant, Part: q.Part, RootRevision: s.Object(ImageBuildKey).Revision, Epoch: s.ModuleEpoch()}
	type row struct {
		key   string
		value any
	}
	var rows []row
	switch q.Part {
	case "cache-prunes":
		for _, r := range b.CachePrunes {
			change, _ := r.Change()
			if change.Tenant != tenant || q.ID != "" && change.ID != q.ID || q.Node != "" && change.Node != q.Node {
				continue
			}
			if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, change.Node) != nil && c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageRegistry, change.Node) != nil {
				continue
			}
			source, _ := b.Job(tenant, r.Source)
			rows = append(rows, row{change.ID, imageBuildCachePruneView(r, change, source.Run.Spec.Context.ID)})
		}
	case "jobs":
		for _, r := range b.Jobs {
			if r.Run.Spec.Tenant == tenant && (q.ID == "" || r.Run.Spec.Context.ID == q.ID) && (q.Job == "" || r.Run.Spec.ID == q.Job) {
				rows = append(rows, row{r.Run.Spec.ID, imageBuildJobView(r)})
			}
		}
	case "policy":
		if r, ok := b.Policy(tenant); ok {
			rows = append(rows, row{tenant, ImageBuildPolicyView{r.Spec, r.Revision, r.Deleted}})
		}
	case "contexts":
		for _, r := range b.Contexts {
			if r.Spec.Tenant == tenant && (q.ID == "" || r.Spec.ID == q.ID) {
				rows = append(rows, row{r.Spec.ID, ImageBuildContextView{Spec: r.Spec.Own(), Revision: r.Revision, NextVersion: r.NextVersion, Deleted: r.Deleted, DataGeneration: r.DraftGeneration(), GitObservation: imageBuildGitObservationView(r.GitObservation)}})
			}
		}
	case "versions":
		for _, r := range b.Versions {
			if r.Tenant != tenant || r.Context != q.ID {
				continue
			}
			u, ok := b.Upload(tenant, r.Upload)
			if !ok {
				return out, ErrCatalog
			}
			at := r.Origin.At
			if u.Automatic != nil {
				at = int64(u.Automatic.At)
			}
			rows = append(rows, row{fmt.Sprintf("%020d", r.Number), ImageBuildVersionView{ID: r.ID, Context: r.Context, Upload: r.Upload, Number: r.Number, Bytes: u.Scope.Length, ExpandedBytes: r.Fact.ExpandedBytes, Entries: r.Fact.Entries, Tree: r.Fact.Tree, At: at, Deleted: r.Deleted, Commit: r.Commit}})
		}
	case "uploads":
		for _, r := range b.Uploads {
			if r.Scope.Tenant == tenant && r.Scope.Creator == session.User && (q.Upload == "" || r.Scope.Upload == q.Upload) {
				view := ImageBuildUploadView{Scope: r.Scope, Revision: r.Revision, Received: r.Received, Closed: r.Closed, Version: r.Version}
				if r.Expiry != nil {
					view.ExpiredAt = r.Expiry.At
				}
				if r.Reclaimed != nil {
					view.ReclaimedAt = r.Reclaimed.At
				}
				rows = append(rows, row{r.Scope.Upload, view})
			}
		}
	case "missing":
		r, ok := b.Upload(tenant, q.Upload)
		if !ok || r.Scope.Creator != session.User {
			return out, access.ErrDenied
		}
		u, err := hydrateBuildUpload(s, r)
		if err != nil {
			return out, err
		}
		var offset uint32
		if key != "" {
			if _, err := fmt.Sscanf(key, "%08d", &offset); err != nil || fmt.Sprintf("%08d", offset) != key {
				return out, access.ErrInvalid
			}
		}
		missing, next, err := u.Missing(session.User, uint64(at), offset, 256)
		if err != nil {
			return out, err
		}
		out.Missing, out.UploadRevision = missing, u.Revision
		if next < u.Scope.Parts() {
			out.Next = buildPageNext(snapshot, fmt.Sprintf("%08d", next))
		}
		return out, nil
	}
	slices.SortFunc(rows, func(a, b row) int { return strings.Compare(a.key, b.key) })
	last := ""
	count := 0
	bytes := 0
	for _, r := range rows {
		if r.key <= key {
			continue
		}
		raw, err := json.Marshal(r.value)
		if err != nil || len(raw) > 96<<10 {
			return out, ErrCatalog
		}
		if count == 8 || bytes+len(raw) > 96<<10 {
			out.Next = buildPageNext(snapshot, last)
			break
		}
		switch value := r.value.(type) {
		case ImageBuildCachePruneView:
			out.CachePrunes = append(out.CachePrunes, value)
		case ImageBuildJobView:
			out.Jobs = append(out.Jobs, value)
		case ImageBuildPolicyView:
			out.Policies = append(out.Policies, value)
		case ImageBuildContextView:
			out.Contexts = append(out.Contexts, value)
		case ImageBuildUploadView:
			out.Uploads = append(out.Uploads, value)
		case ImageBuildVersionView:
			out.Versions = append(out.Versions, value)
		}
		last = r.key
		count++
		bytes += len(raw)
	}
	return out, nil
}
