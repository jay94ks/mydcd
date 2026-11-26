// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func selectionSummaryMatches(h OperationSummary, s deliverySelection, status string) bool {
	if h.ID != s.Operation || h.Submitter != s.Submitter || h.Epoch != s.Epoch || h.Plan != (Blueprint{s.Candidate.Plan}).Digest() {
		return false
	}
	return status == "Succeeded" && h.CompletedAt != 0 && (h.Status == "Succeeded" || h.Status == "Retired" || h.Status == "Closed") || status == "Failed" && h.Failed && (h.Status == "Retired" || h.Status == "Closed")
}
func (d Delivery) savedSummary(s *deliverySelection, status string) (*OperationSummary, error) {
	if s == nil {
		return nil, nil
	}
	a := d.Inventory()
	if e, ok := a.Execution(); ok {
		h := summarize(e, e.Status())
		if selectionSummaryMatches(h, *s, status) {
			return &h, nil
		}
	}
	for _, h := range a.d.History {
		if selectionSummaryMatches(h, *s, status) {
			copy := h
			return &copy, nil
		}
	}
	compacted := d.d.CompactedSuccess
	if status == "Failed" {
		compacted = d.d.CompactedFailure
	}
	if compacted != nil && selectionSummaryMatches(*compacted, *s, status) {
		copy := *compacted
		return &copy, nil
	}
	return nil, ErrInputs
}

// RotateWindow consumes an ALREADY COMMITTED A1 epoch advance. It never issues
// an epoch rotation, changes native ownership, or clears an unsettled request.
func (d Delivery) RotateWindow(expected uint64, c access.Catalog, actor string, shared state.State) (Delivery, error) {
	if expected != d.Revision() || !d.Quiescent() || !d.transitionAccess(c, actor) {
		return d, ErrInputs
	}
	success, err := d.savedSummary(d.d.LastSuccess, "Succeeded")
	if err != nil {
		return d, err
	}
	failure, err := d.savedSummary(d.d.LastFailure, "Failed")
	if err != nil {
		return d, err
	}
	epochs := map[string]uint64{}
	for _, t := range d.d.Transitions {
		epoch, ok := shared.LedgerEpoch(t.Submitter)
		if !ok || epoch <= t.Epoch {
			return d, inputError("COMMITTED_EPOCH_REQUIRED", t.Submitter)
		}
		epochs[t.Submitter] = epoch
	}
	a := d.Inventory()
	updated, err := a.RotateWindow(a.Revision(), c, actor, shared)
	if err != nil {
		return d, err
	}
	// Abandoned/down identities may have no application execution summary.
	// They still require their positive committed epoch fence before removal.
	for submitter, epoch := range epochs {
		if updated.d.MinEpoch[submitter] >= epoch {
			continue
		}
		if updated.Revision() == a.Revision() {
			updated, err = updated.clone()
			if err != nil {
				return d, err
			}
		}
		if updated.d.MinEpoch == nil {
			updated.d.MinEpoch = map[string]uint64{}
		}
		updated.d.MinEpoch[submitter] = epoch
	}
	for _, s := range []*OperationSummary{success, failure} {
		if s != nil && updated.d.MinEpoch[s.Submitter] <= s.Epoch {
			return d, inputError("COMMITTED_EPOCH_REQUIRED", s.Submitter)
		}
	}
	if updated.Revision() == a.Revision() && len(d.d.Transitions) == 0 {
		return d, nil
	}
	n, err := d.clone()
	if err != nil {
		return d, err
	}
	n.d.Inventory = updated.d
	n.d.Running = nil
	n.d.CompactedSuccess = success
	n.d.CompactedFailure = failure
	n.d.Transitions = nil
	n.d.CatalogFloor = c.Revision()
	return n, nil
}
func (d Delivery) validateCompacted() error {
	pairs := []struct {
		summary   *OperationSummary
		selection *deliverySelection
		status    string
	}{{d.d.CompactedSuccess, d.d.LastSuccess, "Succeeded"}, {d.d.CompactedFailure, d.d.LastFailure, "Failed"}}
	for _, pair := range pairs {
		if pair.summary == nil {
			continue
		}
		if pair.selection == nil || !selectionSummaryMatches(*pair.summary, *pair.selection, pair.status) || d.d.Inventory.MinEpoch[pair.summary.Submitter] <= pair.summary.Epoch {
			return ErrInputs
		}
	}
	return nil
}
