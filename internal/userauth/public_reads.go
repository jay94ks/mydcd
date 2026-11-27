// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/tenancy"
)

// publicReadPage reads one page; a network-closure row also carries the
// owner's live closure state, checked again against a fresh quorum view.
func (s Service) publicReadPage(ctx context.Context, view cluster.View, session access.Session, method string, p PublicReadParams) (control.PublicReadPage, string) {
	none := control.PublicReadPage{}
	page, err := s.Policy.PublicRead(view.State, session, time.Now().Unix(), method, p.Tenant, p.Query, p.After)
	if err != nil {
		code := "unavailable"
		if errors.Is(err, access.ErrDenied) || errors.Is(err, access.ErrInvalid) {
			code = "denied"
		} else if errors.Is(err, access.ErrConflict) {
			code = "conflict"
		}
		return none, code
	}
	if method == "network-closure" && len(page.Rows) == 1 {
		target, err := s.Policy.NetworkClosureRead(view.State, session, time.Now().Unix(), p.Tenant, p.Query.Name)
		if err != nil {
			return none, "denied"
		}
		if s.NetworkObserver != nil {
			observeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			status, observeErr := s.NetworkObserver(observeCtx, target)
			cancel()
			latest, err := s.Engine.Read(ctx, true)
			if err != nil || latest.Local {
				return none, "unavailable"
			}
			current, err := s.Policy.NetworkClosureRead(latest.State, session, time.Now().Unix(), p.Tenant, p.Query.Name)
			want, _ := json.Marshal(target)
			got, _ := json.Marshal(current)
			if err != nil || !bytes.Equal(want, got) {
				return none, "denied"
			}
			if observeErr == nil {
				if status.Closure != nil && !current.VerifyClosure(s.Policy.Cluster, *status.Closure) {
					return none, "unavailable"
				}
				page.Rows[0].Closure = &status
			}
		}
	}
	return page, "ok"
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
	case "bridge-endpoints":
		return r.BridgeEndpoint != nil
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

func verifyPublicReadPage(cluster [32]byte, method, tenant string, q control.PublicReadQuery, page control.PublicReadPage) error {
	if page.Schema != 1 || page.Method != method || page.Tenant != tenant || len(page.Rows) > 8 || len(page.Next) > 512 || page.Total < len(page.Rows) || len(page.Rows) == 0 && page.Next != "" {
		return sfcp.ErrAdmission
	}
	previous := ""
	for _, row := range page.Rows {
		count := 0
		for _, present := range []bool{row.FileGrant != nil, row.Closure != nil, row.User != nil, row.BackupLimit != nil, row.Lifecycle != nil, row.Approval != nil, row.SecretUsage != nil, row.Retained != nil, row.RouteEndpoint != nil, row.BridgeEndpoint != nil, row.Image != nil} {
			if present {
				count++
			}
		}
		if count != 1 || row.Key == "" || row.Key <= previous || !publicRowMethod(method, row) {
			return sfcp.ErrAdmission
		}
		previous = row.Key
		if grant := row.FileGrant; grant != nil {
			// Read selectors do not expand the original grant's exact scope.
			if !lifecycle.ValidID(grant.User) || !lifecycle.ValidID(grant.Volume) || grant.App != "" && !lifecycle.ValidID(grant.App) || !access.ValidVolumeFilePath(grant.Prefix, true) || !strings.HasSuffix(grant.Prefix, "/") || grant.Revision == 0 || q.Name != "" && grant.Volume != q.Name || q.App != "" && grant.App != q.App || row.Key != grant.User+"/"+grant.App+"/"+grant.Volume+"/"+grant.Prefix || !slices.Equal(grant.Operations, []string{"volume-file-put", "volume-file-get", "volume-file-list", "volume-file-delete"}) {
				return sfcp.ErrAdmission
			}
		}
		if row.FileGrant != nil && row.FileGrant.Tenant != tenant || row.User != nil && row.User.Tenant != tenant || row.BackupLimit != nil && row.BackupLimit.Tenant != tenant || row.Approval != nil && row.Approval.Realm != tenant || row.SecretUsage != nil && row.SecretUsage.Realm != tenant || row.Retained != nil && row.Retained.Scope.Tenant != tenant || row.RouteEndpoint != nil && row.RouteEndpoint.Tenant != tenant || row.BridgeEndpoint != nil && (row.BridgeEndpoint.Tenant != tenant || row.Key != row.BridgeEndpoint.Network) {
			return sfcp.ErrAdmission
		}
	}

	if method == "network-closure" {
		if len(page.Rows) != 1 || page.Total != 1 || page.Next != "" || page.Rows[0].Key != q.Name {
			return sfcp.ErrAdmission
		}
		for _, row := range page.Rows {
			status := row.Closure
			if status.State != "pending" && status.State != "unreachable" && status.State != "closed" || (status.State == "closed") != (status.Closure != nil) {
				return sfcp.ErrAdmission
			}
			if row.Closure.Closure != nil {
				proof := row.Closure.Closure
				if proof.Cluster != cluster || proof.Tenant != tenant || proof.Network != q.Name || !proof.NativeGone || proof.PendingEndpoints != 0 || proof.PendingFlows != 0 || proof.PendingPins != 0 || !ed25519.Verify(ed25519.PublicKey(proof.Owner[:]), tenancy.NetworkClosureBytes(*proof), proof.Signature) {
					return sfcp.ErrAdmission
				}
			}
		}
	}
	return nil
}
