// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/hex"
	"github.com/jay94ks/mydcd/internal/access"
	"strings"
	"unicode/utf8"
)

type CDRejection struct {
	Source          string
	Candidate       [32]byte
	Actor, Reason   string
	CatalogRevision uint64
}

func ValidCDReason(reason string) bool {
	return utf8.ValidString(reason) && utf8.RuneCountInString(reason) <= 512 && !strings.ContainsRune(reason, 0)
}
func rejectionSource(a deliveryArtifact) string {
	if a.Kind == "git" && a.Commit != "" {
		return "git/" + a.Commit
	}
	return "file/" + hex.EncodeToString(a.Digest[:])
}
func (d Delivery) Rejected() bool {
	if d.d.Candidate == nil {
		return false
	}
	key := rejectionSource(d.d.Candidate.Artifact)
	for _, row := range d.d.Rejections {
		if row.Source == key {
			return true
		}
	}
	return false
}
func (d Delivery) ApprovalReady(c access.Catalog) bool {
	a := d.d.Approval
	return !d.Rejected() && d.d.Candidate != nil && a != nil && a.Candidate == d.d.Candidate.ID && a.CatalogRevision == c.Revision() && d.mayDecide(c, a.Actor)
}
func (d Delivery) ExplicitApprovalReady(c access.Catalog) bool {
	return d.d.Approval != nil && d.d.Approval.Explicit && d.ApprovalReady(c)
}
func (d Delivery) ApproveDecision(expected uint64, c access.Catalog, ctx PlanningContext, actor string, id [32]byte, reason string) (Delivery, error) {
	if !ValidCDReason(reason) || d.d.Running != nil && d.d.Inventory.Active != nil && d.d.Inventory.Active.CompletedAt == 0 {
		return d, ErrInputs
	}
	n, err := d.Approve(expected, c, ctx, actor, id, reason)
	if err != nil {
		return d, err
	}
	n.d.Approval.Explicit = true
	return n, nil
}
func (d Delivery) Reject(expected uint64, c access.Catalog, ctx PlanningContext, actor string, id [32]byte, reason string) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || d.d.Candidate == nil || d.d.Candidate.ID != id || !ValidCDReason(reason) || !d.mayDecide(c, actor) || d.d.Inventory.Active != nil && d.d.Inventory.Active.CompletedAt == 0 || d.Rejected() || len(d.d.Rejections) >= 128 {
		return d, ErrInputs
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Approval = nil
	n.d.Rejections = append(n.d.Rejections, CDRejection{Source: rejectionSource(d.d.Candidate.Artifact), Candidate: id, Actor: actor, Reason: reason, CatalogRevision: c.Revision()})
	return n, nil
}

// Only an explicit user replan may lift a rejection of this same source. A
// fetch/rebase/automatic replan never calls this transition.
func (d Delivery) Reconsider(expected uint64, c access.Catalog, ctx PlanningContext, actor string) (Delivery, error) {
	if expected != d.Revision() || !d.scope(c, ctx) || c.Authorize(actor, d.d.Inventory.Tenant, access.ManageCD, "") != nil || d.d.Candidate == nil {
		return d, ErrInputs
	}
	if !d.Rejected() {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.floors(c, ctx)
	n.d.Approval = nil
	key := rejectionSource(n.d.Candidate.Artifact)
	kept := n.d.Rejections[:0]
	for _, row := range n.d.Rejections {
		if row.Source != key {
			kept = append(kept, row)
		}
	}
	n.d.Rejections = kept
	return n, nil
}
func (d Delivery) validDecisions() bool {
	if len(d.d.Rejections) > 128 {
		return false
	}
	seen := map[string]bool{}
	for _, row := range d.d.Rejections {
		parts := strings.Split(row.Source, "/")
		if len(parts) != 2 || parts[0] != "git" && parts[0] != "file" || !identifier(row.Actor) || row.Candidate == ([32]byte{}) || !ValidCDReason(row.Reason) || row.CatalogRevision == 0 || row.CatalogRevision > d.d.CatalogFloor || seen[row.Source] {
			return false
		}
		raw, err := hex.DecodeString(parts[1])
		if err != nil || hex.EncodeToString(raw) != parts[1] || len(raw) != 32 && (parts[0] != "git" || len(raw) != 20) {
			return false
		}
		seen[row.Source] = true
	}
	return d.d.Approval == nil || ValidCDReason(d.d.Approval.Reason)
}
