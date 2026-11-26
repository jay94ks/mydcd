// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"github.com/jay94ks/mydcd/internal/cluster/state"
)

func (d Delivery) validCandidate(c deliveryCandidate) bool {
	b := Blueprint{c.Plan}
	if c.LocalRevision > d.d.LocalRevision || c.LocalServices != nil && c.LocalServices.Revision != c.LocalRevision {
		return false
	}
	if c.OverrideRevision > d.d.OverrideRevision || !validOverrideSet(c.Overrides, c.OverrideRevision) || checkOverrideOwners(b, c.Overrides) != nil {
		return false
	}
	if c.ID != candidateID(c) || c.PolicyRevision == 0 || c.PolicyRevision > d.d.PolicyRevision || c.InventoryRevision == 0 || c.InventoryRevision > d.d.Inventory.Revision || !(Inventory{d.d.Inventory}).scope(b) || c.Plan.Actor != d.d.Principal {
		return false
	}
	raw, err := b.Encode()
	if err != nil {
		return false
	}
	if _, err = DecodeBlueprint(raw); err != nil {
		return false
	}
	input, err := artifactComposeKind(c.Artifact, c.Plan.InputKind)
	if err != nil {
		return false
	}
	input, err = mergeLocalServices(input, c.LocalServices, b.Scope())
	if err != nil {
		return false
	}
	input, err = applyDeliveryOverrides(input, c.Overrides)
	if err != nil {
		return false
	}
	if source := b.d.Document; source != nil && (c.Artifact.Kind != "git" && !c.Artifact.Original || !bytes.Equal(source.Body, c.Artifact.Body) || !bytes.Equal(goal(source.Overrides), goal(c.Overrides))) {
		return false
	}
	if source := b.d.Document; source != nil && !bytes.Equal(goal(source.LocalServices), goal(c.LocalServices)) {
		return false
	}
	return matchesBlueprintInput(input, b, nil)
}
func (d Delivery) validate() error {
	r := d.d
	if r.LocalServices != nil {
		if r.LocalServices.Revision != r.LocalRevision {
			return ErrInputs
		}
		if _, err := localServicesInput(r.LocalServices); err != nil {
			return err
		}
	}
	if r.Candidate != nil && r.Candidate.LocalRevision == r.LocalRevision && !bytes.Equal(goal(r.Candidate.LocalServices), goal(r.LocalServices)) {
		return ErrInputs
	}
	// Validation only reads private immutable records. Public getters return
	// owned deep copies for external consumers; making those copies here
	// repeatedly must not compete with Raft heartbeat processing.
	inventory := Inventory{r.Inventory}
	if !d.validDecisions() || !validOverrideSet(r.Overrides, r.OverrideRevision) || !validApprovers(r.Approvers) {
		return ErrInputs
	}
	for _, o := range r.Overrides {
		if o.CatalogRevision > r.CatalogFloor {
			return ErrInputs
		}
	}
	if r.Schema != 1 || r.Revision == 0 || r.PolicyRevision == 0 || !identifier(r.Principal) || r.CatalogFloor == 0 || inventory.validate() != nil {
		return ErrInputs
	}
	if d.validateTransitions() != nil {
		return ErrInputs
	}
	if d.validateCompacted() != nil {
		return ErrInputs
	}
	if r.Candidate == nil && r.Running == nil {
		return ErrInputs
	}
	if r.Candidate != nil && !d.validCandidate(*r.Candidate) {
		return ErrInputs
	}
	if r.Candidate != nil && r.Candidate.OverrideRevision == r.OverrideRevision && !bytes.Equal(goal(r.Candidate.Overrides), goal(r.Overrides)) {
		return ErrInputs
	}
	var model Compose
	if r.Candidate != nil {
		model = r.Candidate.Plan.Input
	} else {
		model = r.Running.Candidate.Plan.Input
	}
	model.MyDC.Delivery = &r.Policy
	if model.validateExtensions() != nil {
		return ErrInputs
	}
	if r.Fetch != nil && (r.Fetch.Sequence != r.FetchSequence || r.Fetch.Sequence == 0 || r.Fetch.PolicyRevision != r.PolicyRevision || r.Fetch.Source != deliverySourceID(r.Policy) || !r.Policy.Enabled) {
		return ErrInputs
	}
	if r.Approval != nil && (r.Candidate == nil || r.Approval.Candidate != r.Candidate.ID || !identifier(r.Approval.Actor) || r.Approval.CatalogRevision == 0 || r.Approval.CatalogRevision > r.CatalogFloor) {
		return ErrInputs
	}
	for _, s := range []*deliverySelection{r.Running, r.LastSuccess, r.LastFailure} {
		if s != nil && (!d.validCandidate(s.Candidate) || !identifier(s.Operation) || s.Submitter == "" || len(s.Submitter) > 256 || s.Epoch == 0) {
			return ErrInputs
		}
	}
	active := r.Inventory.Active != nil
	if active != (r.Running != nil) {
		return ErrInputs
	}
	if active && (r.Inventory.Active.Operation != r.Running.Operation || r.Inventory.Active.Submitter != r.Running.Submitter || r.Inventory.Active.Epoch != r.Running.Epoch || (Blueprint{r.Inventory.Active.Plan}).Digest() != (Blueprint{r.Running.Candidate.Plan}).Digest()) {
		return ErrInputs
	}
	if r.LastSuccess != nil && !d.recordedSelection(*r.LastSuccess, "Succeeded") {
		return ErrInputs
	}
	if r.LastFailure != nil && !d.recordedSelection(*r.LastFailure, "Failed") {
		return ErrInputs
	}
	switch r.SourceError {
	case "", "fetch", "missing", "invalid", "scope", "policy", "name-conflict", "alias-conflict":
	default:
		return ErrInputs
	}
	return nil
}
func (d Delivery) recordedSelection(s deliverySelection, status string) bool {
	plan := (Blueprint{s.Candidate.Plan}).Digest()
	if active := d.d.Inventory.Active; active != nil && active.Operation == s.Operation && active.Submitter == s.Submitter && active.Epoch == s.Epoch && (Blueprint{active.Plan}).Digest() == plan {
		e := Execution{*active}
		if e.Status() == status || status == "Succeeded" && e.d.CompletedAt != 0 {
			return true
		}
		if status == "Failed" {
			for _, stage := range e.d.Stages {
				if stage.Result != nil && stage.Result.Code != state.Applied {
					return true
				}
			}
		}
	}
	for _, h := range d.d.Inventory.History {
		if h.ID == s.Operation && h.Submitter == s.Submitter && h.Epoch == s.Epoch && h.Plan == plan && (h.Status == status || h.Status == "Retired" && (status == "Succeeded" && h.CompletedAt != 0 || status == "Failed" && h.Failed)) {
			return true
		}
	}
	compacted := d.d.CompactedSuccess
	if status == "Failed" {
		compacted = d.d.CompactedFailure
	}
	if compacted != nil && d.d.Inventory.MinEpoch[compacted.Submitter] > compacted.Epoch && selectionSummaryMatches(*compacted, s, status) {
		return true
	}
	return false
}
func (d Delivery) Encode() ([]byte, error) {
	raw, err := json.Marshal(d.d)
	if err != nil || len(raw) > 64<<20 {
		return nil, ErrInputs
	}
	// Only private deterministic invariants are memoized. Marshal fresh bytes
	// first so mutating a local record can never inherit another record's hit.
	if !validatedDeliveryBytes.contains(raw) {
		if d.validate() != nil {
			return nil, ErrInputs
		}
		validatedDeliveryBytes.remember(raw)
	}
	return raw, err
}
func DecodeDelivery(raw []byte) (Delivery, error) {
	if len(raw) > 64<<20 {
		return Delivery{}, ErrInputs
	}
	var r deliveryRecord
	if json.Unmarshal(raw, &r) != nil {
		return Delivery{}, ErrInputs
	}
	d := Delivery{r}
	if !validatedDeliveryBytes.contains(raw) {
		if d.validate() != nil {
			return Delivery{}, ErrInputs
		}
		canonical, _ := json.Marshal(r)
		if !bytes.Equal(raw, canonical) {
			return Delivery{}, ErrInputs
		}
		validatedDeliveryBytes.remember(raw)
	}
	return d, nil
}
