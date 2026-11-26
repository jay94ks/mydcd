// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/deployment"
	"github.com/jay94ks/mydcd/internal/mydcp"
)

func (c Client) AppSource(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.AppSourceSelection) (Reply, error) {
	if tenant == "" || !q.Valid(false) {
		return Reply{}, access.ErrInvalid
	}
	return c.query(ctx, peer, session, Request{Method: "app-source", Tenant: tenant, AppSource: &q})
}

func (c Client) AppRevisions(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.AppSourceSelection, after string) (Reply, error) {
	if tenant == "" || !q.Valid(true) {
		return Reply{}, access.ErrInvalid
	}
	return c.query(ctx, peer, session, Request{Method: "app-revisions", Tenant: tenant, AppSource: &q, After: after})
}

func (s Service) appSourceQueryReply(view cluster.View, session access.Session, request Request) Reply {
	if request.AppSource == nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	var err error
	if request.Method == "app-source" {
		var part control.AppSourcePart
		part, err = s.Policy.AppSource(view.State, session, time.Now().Unix(), request.Tenant, *request.AppSource)
		if err == nil {
			return Reply{Schema: 1, Code: "ok", AppSource: &part}
		}
	} else {
		var page control.AppRevisionsPage
		page, err = s.Policy.AppRevisions(view.State, session, time.Now().Unix(), request.Tenant, *request.AppSource, request.After)
		if err == nil {
			return Reply{Schema: 1, Code: "ok", AppRevisions: page.Versions, AppRevisionsNext: page.Next, AppRevisionsRootRevision: page.RootRevision}
		}
	}
	code := "unavailable"
	switch {
	case errors.Is(err, control.ErrAppSourceUnavailable):
		code = "original-not-retained"
	case errors.Is(err, control.ErrAppSourceReclaimed):
		code = "version-reclaimed"
	case errors.Is(err, control.ErrAppSourceSection):
		code = "section-unavailable"
	case errors.Is(err, access.ErrConflict):
		code = "conflict"
	case errors.Is(err, access.ErrDenied), errors.Is(err, access.ErrInvalid):
		code = "denied"
	}
	return Reply{Schema: 1, Code: code}
}

// ReadAppSource assembles immutable, bounded parts. A new current version or
// leader cannot splice another document into the first part's revision/digest.
func (c Client) ReadAppSource(ctx context.Context, peer mydcp.Peer, session access.Session, tenant string, q control.AppSourceSelection) ([]byte, control.AppRevisionView, error) {
	if q.Part != 0 || !q.Valid(false) {
		return nil, control.AppRevisionView{}, access.ErrInvalid
	}
	var version control.AppRevisionView
	var raw []byte
	length := 0
	var digest [32]byte
	var first control.AppLocalPending
	section := q.Section
	if section == "" {
		section = "source"
	}
	for part := 0; ; part++ {
		q.Part = part
		reply, err := c.AppSource(ctx, peer, session, tenant, q)
		if err != nil {
			return nil, control.AppRevisionView{}, err
		}
		p := reply.AppSource
		pending := section == "pending-local"
		if p == nil || p.Part != part || p.Section != section || p.Version.Revision == 0 || p.Version.Tenant != tenant || (q.Standalone == "" && p.Version.App != q.App || q.Standalone != "" && p.Standalone != q.Standalone) || q.Deployment != "" && p.Version.Deployment != q.Deployment || q.Revision != 0 && p.Version.Revision != q.Revision || !pending && !p.Version.OriginalRetained || pending != (p.Pending != nil) {
			return nil, control.AppRevisionView{}, mydcp.ErrFrame
		}
		if part == 0 {
			version = p.Version
			length, digest = version.Length, version.Digest
			if section == "overlays" {
				length, digest = version.OverlayLength, version.OverlayDigest
			}
			if section == "local-services" {
				length, digest = version.LocalLength, version.LocalDigest
			}
			if pending {
				length, digest, first = p.Pending.Length, p.Pending.Digest, *p.Pending
			}
			if length <= 0 || length > deployment.ArtifactMaxBytes || digest == ([32]byte{}) || q.Digest != ([32]byte{}) && q.Digest != digest {
				return nil, control.AppRevisionView{}, mydcp.ErrFrame
			}
			q.Digest, q.Deployment = digest, version.Deployment
			if !pending {
				q.Revision = version.Revision
			}
		} else if pending && *p.Pending != first {
			return nil, control.AppRevisionView{}, mydcp.ErrFrame
		} else if p.Version.Digest != version.Digest || p.Version.Length != version.Length || p.Version.OverlayDigest != version.OverlayDigest || p.Version.OverlayLength != version.OverlayLength || p.Version.LocalDigest != version.LocalDigest || p.Version.LocalLength != version.LocalLength || p.Version.LocalRevision != version.LocalRevision || p.Version.LocalActor != version.LocalActor {
			return nil, control.AppRevisionView{}, mydcp.ErrFrame
		}
		if len(p.Data) != min(deployment.ArtifactPartBytes, length-len(raw)) {
			return nil, control.AppRevisionView{}, mydcp.ErrFrame
		}
		raw = append(raw, p.Data...)
		if len(raw) == length {
			if sha256.Sum256(raw) != digest {
				return nil, control.AppRevisionView{}, mydcp.ErrFrame
			}
			return raw, version, nil
		}
	}
}
