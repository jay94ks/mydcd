// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func (r Request) validCDReadFields() bool {
	if r.Method == "app-cd-field" {
		if r.AppCDField == nil || r.Tenant == "" || !(control.AppCDReadRequest{App: r.AppCDField.App, Part: r.AppCDField.Part, Digest: r.AppCDField.Digest}).Valid(false) || !deployment.AllowedAppOverride(r.AppCDField.Path) {
			return false
		}
		want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, AppCDField: r.AppCDField}
		return reflect.DeepEqual(r, want)
	}
	read := r.Method == "app-cd-history" || r.Method == "app-cd-diff"
	if !read {
		return r.AppCDRead == nil
	}
	if r.AppCDRead == nil || r.Tenant == "" || !r.AppCDRead.Valid(r.Method == "app-cd-history") || r.Method == "app-cd-diff" && r.After != "" {
		return false
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, AppCDRead: r.AppCDRead, After: r.After}
	return reflect.DeepEqual(r, want)
}

func (s Service) appCDReadReply(view cluster.View, session access.Session, r Request) Reply {
	if r.AppCDRead == nil {
		return Reply{Schema: 1, Code: "denied"}
	}
	var err error
	if r.Method == "app-cd-history" {
		var page control.AppCDHistoryPage
		page, err = s.Policy.AppDeliveryHistory(view.State, session, time.Now().Unix(), r.Tenant, *r.AppCDRead, r.After)
		if err == nil {
			return Reply{Schema: 1, Code: "ok", AppCDHistory: &page}
		}
	} else {
		var part control.AppCDSnapshotPart
		part, err = s.Policy.AppDeliveryDiff(view.State, session, time.Now().Unix(), r.Tenant, *r.AppCDRead)
		if err == nil {
			return Reply{Schema: 1, Code: "ok", AppCDSnapshot: &part}
		}
	}
	code := "unavailable"
	if errors.Is(err, access.ErrDenied) {
		code = "denied"
	}
	if errors.Is(err, access.ErrInvalid) {
		code = "invalid"
	}
	if errors.Is(err, access.ErrConflict) {
		code = "conflict"
	}
	return Reply{Schema: 1, Code: code}
}

func (c Client) AppDeliveryHistory(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, app, after string) (control.AppCDHistoryPage, error) {
	q := control.AppCDReadRequest{App: app}
	if !q.Valid(true) || tenant == "" {
		return control.AppCDHistoryPage{}, access.ErrInvalid
	}
	reply, err := c.query(ctx, peer, session, Request{Method: "app-cd-history", Tenant: tenant, AppCDRead: &q, After: after})
	if err != nil {
		return control.AppCDHistoryPage{}, err
	}
	p := reply.AppCDHistory
	if p == nil || p.Schema != 1 || p.Tenant != tenant || p.App != app || len(p.Records) > 16 || len(p.Next) > 1536 {
		return control.AppCDHistoryPage{}, sfcp.ErrFrame
	}
	previous := ^uint64(0)
	for i, row := range p.Records {
		if row.Sequence == 0 || i > 0 && row.Sequence >= previous || row.Sequence < p.First || row.Sequence > p.Last {
			return control.AppCDHistoryPage{}, sfcp.ErrFrame
		}
		previous = row.Sequence
	}
	return *p, nil
}

// A changed snapshot fails explicitly; neither field nor diff reads retry from
// a new candidate or silently mix the original parts with a new source.
func collectCDSnapshot(tenant, app, kind string, read func(int, [32]byte) (*control.AppCDSnapshotPart, error)) ([]byte, error) {
	var raw []byte
	var digest [32]byte
	length := 0
	for i := 0; ; i++ {
		p, err := read(i, digest)
		if err != nil {
			return nil, err
		}
		if p == nil || p.Schema != 1 || p.Tenant != tenant || p.App != app || p.Kind != kind || p.Part != i || p.Length < 1 || p.Length > 16<<20 || p.Digest == ([32]byte{}) {
			return nil, sfcp.ErrFrame
		}
		if i == 0 {
			length, digest = p.Length, p.Digest
		} else if p.Length != length || p.Digest != digest {
			return nil, sfcp.ErrFrame
		}
		if len(p.Data) != min(deployment.ArtifactPartBytes, length-len(raw)) {
			return nil, sfcp.ErrFrame
		}
		raw = append(raw, p.Data...)
		if len(raw) == length {
			if sha256.Sum256(raw) != digest {
				return nil, sfcp.ErrFrame
			}
			return raw, nil
		}
	}
}

func (c Client) AppDeliveryDiff(ctx context.Context, peer sfcp.Peer, session access.Session, tenant, app string) (control.AppCDDiff, error) {
	q := control.AppCDReadRequest{App: app}
	if tenant == "" || !q.Valid(false) {
		return control.AppCDDiff{}, access.ErrInvalid
	}
	raw, err := collectCDSnapshot(tenant, app, "diff", func(part int, digest [32]byte) (*control.AppCDSnapshotPart, error) {
		q.Part, q.Digest = part, digest
		reply, err := c.query(ctx, peer, session, Request{Method: "app-cd-diff", Tenant: tenant, AppCDRead: &q})
		return reply.AppCDSnapshot, err
	})
	if err != nil {
		return control.AppCDDiff{}, err
	}
	var out control.AppCDDiff
	if json.Unmarshal(raw, &out) != nil || out.Schema != 1 || out.Tenant != tenant || out.App != app || out.ChangeCount != len(out.Changes) {
		return control.AppCDDiff{}, sfcp.ErrFrame
	}
	if out.Replacement != nil && !out.Replacement.Valid(tenant, app) {
		return control.AppCDDiff{}, sfcp.ErrFrame
	}
	return out, nil
}
