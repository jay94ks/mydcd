// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster"
	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/tenancy"
)

func (r Request) validPublicReadFields() bool {
	method := control.PublicReadMethod(r.Method)
	if (r.PublicRead != nil) != method {
		return false
	}
	if !method {
		return true
	}
	want := Request{Schema: r.Schema, Method: r.Method, Nonce: r.Nonce, Tenant: r.Tenant, After: r.After, PublicRead: r.PublicRead}
	return (r.Method != "network-closure" || r.After == "") && r.PublicRead.Valid(r.Method) && len(r.After) <= 512 && reflect.DeepEqual(r, want)
}
func (c Client) PublicRead(ctx context.Context, target mydcp.Peer, session access.Session, method, tenant string, q control.PublicReadQuery, after string) (Reply, error) {
	if !control.PublicReadMethod(method) || !q.Valid(method) || len(after) > 512 || method == "network-closure" && after != "" {
		return Reply{}, mydcp.ErrAdmission
	}
	reply, err := c.query(ctx, target, session, Request{Method: method, Tenant: tenant, After: after, PublicRead: &q})
	if err != nil {
		return reply, err
	}
	if err := verifyPublicReadReply(c.Cluster, method, tenant, q, reply); err != nil {
		return Reply{}, err
	}
	return reply, nil
}
func (s Service) publicReadReply(ctx context.Context, view cluster.View, session access.Session, request Request) Reply {
	page, err := s.Policy.PublicRead(view.State, session, time.Now().Unix(), request.Method, request.Tenant, *request.PublicRead, request.After)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
			code = "denied"
		} else if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return Reply{Schema: 1, Code: code}
	}
	if request.Method == "network-closure" && len(page.Rows) == 1 {
		target, err := s.Policy.NetworkClosureRead(view.State, session, time.Now().Unix(), request.Tenant, request.PublicRead.Name)
		if err != nil {
			return Reply{Schema: 1, Code: "denied"}
		}
		if s.NetworkObserver != nil {
			observeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			status, observeErr := s.NetworkObserver(observeCtx, target)
			cancel()
			latest, err := s.Engine.Read(ctx, true)
			if err != nil || latest.Local {
				return Reply{Schema: 1, Code: "unavailable"}
			}
			current, err := s.Policy.NetworkClosureRead(latest.State, session, time.Now().Unix(), request.Tenant, request.PublicRead.Name)
			want, _ := json.Marshal(target)
			got, _ := json.Marshal(current)
			if err != nil || !bytes.Equal(want, got) {
				return Reply{Schema: 1, Code: "denied"}
			}
			if observeErr == nil {
				if status.Closure != nil && !current.VerifyClosure(s.Policy.Cluster, *status.Closure) {
					return Reply{Schema: 1, Code: "unavailable"}
				}
				page.Rows[0].Closure = &status
			}
		}
	}
	return Reply{Schema: 1, Code: "ok", Tenant: request.Tenant, RootRevision: page.CatalogRevision, PublicRead: &page}
}

func publicRowMethod(method string, r control.PublicReadRow) bool {
	switch method {
	case "volume-file-grants":
		return r.FileGrant != nil
	case "network-closure":
		return r.Closure != nil
	case "volume-backup-limits":
		return r.BackupLimit != nil
	case "network-users", "volume-users":
		return r.User != nil
	case "route-endpoints":
		return r.RouteEndpoint != nil
	case "lifecycle-uses":
		return r.Lifecycle != nil
	case "vault-approvals":
		return r.Approval != nil
	case "vault-usages":
		return r.SecretUsage != nil
	case "volume-retained-sources":
		return r.Retained != nil
	case "image-trust":
		return r.Image != nil
	}
	return false
}

func verifyPublicReadReply(cluster [32]byte, method, tenant string, q control.PublicReadQuery, reply Reply) error {
	page := reply.PublicRead
	if reply.Schema != 1 || reply.Code != "ok" || page == nil || page.Schema != 1 || page.Method != method || page.Tenant != tenant || len(page.Rows) > 8 || len(page.Next) > 512 || page.Total < len(page.Rows) || len(page.Rows) == 0 && page.Next != "" {
		return mydcp.ErrAdmission
	}
	previous := ""
	for _, row := range page.Rows {
		count := 0
		for _, present := range []bool{row.FileGrant != nil, row.Closure != nil, row.User != nil, row.BackupLimit != nil, row.Lifecycle != nil, row.Approval != nil, row.SecretUsage != nil, row.Retained != nil, row.RouteEndpoint != nil, row.Image != nil} {
			if present {
				count++
			}
		}
		if count != 1 || row.Key == "" || row.Key <= previous || !publicRowMethod(method, row) {
			return mydcp.ErrAdmission
		}
		previous = row.Key
		if grant := row.FileGrant; grant != nil {
			// Read selectors do not expand the original grant's exact scope.
			if !lifecycle.ValidID(grant.User) || !lifecycle.ValidID(grant.Volume) || grant.App != "" && !lifecycle.ValidID(grant.App) || !access.ValidVolumeFilePath(grant.Prefix, true) || !strings.HasSuffix(grant.Prefix, "/") || grant.Revision == 0 || q.Name != "" && grant.Volume != q.Name || q.App != "" && grant.App != q.App || row.Key != grant.User+"/"+grant.App+"/"+grant.Volume+"/"+grant.Prefix || !slices.Equal(grant.Operations, []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}) {
				return mydcp.ErrAdmission
			}
		}
		if row.FileGrant != nil && row.FileGrant.Tenant != tenant || row.User != nil && row.User.Tenant != tenant || row.BackupLimit != nil && row.BackupLimit.Tenant != tenant || row.Approval != nil && row.Approval.Realm != tenant || row.SecretUsage != nil && row.SecretUsage.Realm != tenant || row.Retained != nil && row.Retained.Scope.Tenant != tenant || row.RouteEndpoint != nil && row.RouteEndpoint.Tenant != tenant {
			return mydcp.ErrAdmission
		}
	}

	if method == "network-closure" {
		if len(page.Rows) != 1 || page.Total != 1 || page.Next != "" || page.Rows[0].Key != q.Name {
			return mydcp.ErrAdmission
		}
		for _, row := range page.Rows {
			status := row.Closure
			if status.State != "pending" && status.State != "unreachable" && status.State != "closed" || (status.State == "closed") != (status.Closure != nil) {
				return mydcp.ErrAdmission
			}
			if row.Closure.Closure != nil {
				proof := row.Closure.Closure
				if proof.Cluster != cluster || proof.Tenant != tenant || proof.Network != q.Name || !proof.NativeGone || proof.PendingEndpoints != 0 || proof.PendingFlows != 0 || proof.PendingPins != 0 || !ed25519.Verify(ed25519.PublicKey(proof.Owner[:]), tenancy.NetworkClosureBytes(*proof), proof.Signature) {
					return mydcp.ErrAdmission
				}
			}
		}
	}
	return nil
}
