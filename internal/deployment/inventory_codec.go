// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/schema"
)

func (a Inventory) validClaim(c Claim) bool {
	root := ResourceKey(c.Step.Kind, a.d.Tenant, a.d.App, "root")
	if root == "" || len(c.Step.Key) < len(root)-4 {
		return false
	}
	id := c.Step.Key[len(root)-4:]
	if ResourceKey(c.Step.Kind, a.d.Tenant, a.d.App, id) != c.Step.Key || c.Command.Key != c.Step.Key || c.Command.Kind != state.Mutate || c.Command.Delete || c.Command.Epoch == 0 || c.Command.Actor == "" || c.Command.RequestID == "" || !validResult(c.Result) || c.Result.Code != state.Applied || !identifier(c.Operation) || c.Plan == ([32]byte{}) || c.Step.Retain != (c.Step.Kind == "volume" || c.Step.Kind == "namespace") {
		return false
	}
	var g GoalCommand
	if json.Unmarshal([]byte(c.Command.Value), &g) != nil || g.Schema != 1 || g.Cluster != a.d.Cluster || g.Tenant != a.d.Tenant || g.App != a.d.App || g.Deployment != a.d.Deployment || g.Kind != c.Step.Kind || g.Node != c.Step.Node || g.Owner != c.Step.Owner || !bytes.Equal(g.Config, c.Step.Goal) || g.Lifecycle != nil {
		return false
	}
	for _, ref := range c.Step.StableDNS {
		if c.Step.Kind != "task" || !slices.Contains(g.Dependencies, ref) {
			return false
		}
	}
	if c.Step.Node != "" && c.Step.Owner == ([32]byte{}) || c.Step.Node == "" && c.Step.Owner != ([32]byte{}) {
		return false
	}
	if o := c.Observation; o != nil {
		if o.Cluster != a.d.Cluster || o.Plan != c.Plan || o.Operation != c.Operation || o.Key != c.Step.Key || o.Owner != c.Step.Owner || o.Command != state.Digest(c.Command) || o.Generation != c.Result.Generation || o.Revision != c.Result.Revision || o.Sequence == 0 || o.At == 0 || o.Native != c.Native || !ed25519.Verify(c.Step.Owner[:], ObservationBytes(*o), o.Signature) {
			return false
		}
	}
	if c.Removed {
		if c.Step.Retain || c.Removal == nil || !a.validRemoval(c, *c.Removal) {
			return false
		}
	} else if c.Removal != nil {
		return false
	}
	if c.RetainProof != nil && (!c.Retained || !a.validRetain(c, *c.RetainProof, c.RetainProof.Retirement, c.RetainProof.StopRevision)) {
		return false
	}
	return true
}
func (a Inventory) validRetain(c Claim, o RetainReceipt, id string, revision uint64) bool {
	return o.Cluster == a.d.Cluster && o.Retirement == id && o.StopRevision == revision && revision > 0 && o.Key == c.Step.Key && o.Owner == c.Step.Owner && o.Command == state.Digest(c.Command) && o.Generation == c.Result.Generation && o.Revision == c.Result.Revision && o.Released && o.Stopped && o.Retained && !o.Gone && o.Fenced && o.Pins == 0 && (c.Native == "" || o.Native == c.Native) && ed25519.Verify(c.Step.Owner[:], RetainReceiptBytes(o), o.Signature)
}
func (a Inventory) validRemoval(c Claim, p RemovalProof) bool {
	if !identifier(p.ID) || p.Revision == 0 || p.Delete == nil || !p.Delete.valid() || p.Delete.Result == nil || p.Delete.Result.Code != state.Applied || !p.Delete.Command.Delete || p.Delete.Command.Key != c.Step.Key || p.Delete.Command.Value != "" || p.Delete.Result.Generation != c.Result.Generation {
		return false
	}
	if c.Step.Owner == ([32]byte{}) {
		r := retirementRecord{ID: p.ID, Revision: p.Revision, Submitter: p.Delete.Command.Actor, Epoch: p.Delete.Command.Epoch}
		return c.Step.Kind == "delivery" && p.Drain == nil && p.Proof == nil && p.Delete.Command == retireCommand(r, c, "delete", "", c.Result.Revision, true)
	}
	if p.Drain == nil || p.Proof == nil || !p.Drain.valid() || !p.Proof.valid() || p.Drain.Result == nil || p.Proof.Result == nil || p.Drain.Result.Code != state.Applied || p.Proof.Result.Code != state.Applied || p.Drain.Command.Expected != c.Result.Revision || p.Proof.Command.Expected != p.Drain.Result.Revision || p.Delete.Command.Expected != p.Proof.Result.Revision || p.Drain.Result.Generation != c.Result.Generation || p.Proof.Result.Generation != c.Result.Generation || schema.VerifyGone(c.Step.Owner, a.d.Cluster, c.Step.Key, c.Result.Generation, []byte(p.Drain.Command.Value), p.Gone) != nil {
		return false
	}
	var original, drained, proved GoalCommand
	if json.Unmarshal([]byte(c.Command.Value), &original) != nil || json.Unmarshal([]byte(p.Drain.Command.Value), &drained) != nil || json.Unmarshal([]byte(p.Proof.Command.Value), &proved) != nil {
		return false
	}
	original.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: retirementNonce(a.d.Cluster, p.ID+"/"+string(goal(p.Revision)), c.Step.Key, c.Result.Generation)}
	if !bytes.Equal(goal(original), goal(drained)) {
		return false
	}
	original.Lifecycle.Proof = p.Gone
	r := retirementRecord{ID: p.ID, Revision: p.Revision, Submitter: p.Delete.Command.Actor, Epoch: p.Delete.Command.Epoch}
	return bytes.Equal(goal(original), goal(proved)) && p.Drain.Command == retireCommand(r, c, "drain", string(goal(drained)), c.Result.Revision, false) && p.Proof.Command == retireCommand(r, c, "proof", string(goal(proved)), p.Drain.Result.Revision, false) && p.Delete.Command == retireCommand(r, c, "delete", "", p.Proof.Result.Revision, true)
}

// A completed Noop still records the original effect while that SAME effect
// is retired. It may outlive a live claim only through the current positive
// closure, never by adopting an already removed/retained source in a new run.
func (a Inventory) closedNoopClaim(c Claim) bool {
	if a.d.Retirement == nil {
		return false
	}
	at := a.target(c.Step.Key)
	if at < 0 {
		return false
	}
	r := a.d.Retirement
	t := r.Targets[at]
	if !t.Closed || t.Original.Command != c.Command || t.Original.Result != c.Result || t.Original.Operation != c.Operation || t.Original.Plan != c.Plan {
		return false
	}
	if c.Step.Retain {
		return c.Retained && bytes.Equal(goal(c.RetainProof), goal(t.Retained))
	}
	return c.Removed && bytes.Equal(goal(c.Removal), goal(RemovalProof{r.ID, r.Revision, t.Drain, t.Proof, t.Delete, t.Gone}))
}

func (a Inventory) validate() error {
	d := a.d
	if d.Schema != 1 || d.Cluster == ([32]byte{}) || !identifier(d.Tenant) || !identifier(d.App) || !identifier(d.Deployment) || d.Revision == 0 || len(d.Claims) > 1024 || len(d.History) > 128 || d.Stopping != (d.Retirement != nil) {
		return ErrInputs
	}
	seen := map[string]bool{}
	for actor, epoch := range d.MinEpoch {
		if actor == "" || len(actor) > 256 || epoch == 0 {
			return ErrInputs
		}
	}
	for _, summary := range d.History {
		if summary.Failed && summary.Status == "Succeeded" {
			return ErrInputs
		}
		if !identifier(summary.ID) || seen[summary.ID] || summary.Plan == ([32]byte{}) || summary.Submitter == "" || summary.Epoch == 0 || summary.Epoch < d.MinEpoch[summary.Submitter] || summary.Status != "Succeeded" && summary.Status != "Closed" && summary.Status != "Retired" {
			return ErrInputs
		}
		seen[summary.ID] = true
	}
	for i, c := range d.Claims {
		if !a.validClaim(c) || i > 0 && d.Claims[i-1].Step.Key >= c.Step.Key {
			return ErrInputs
		}
	}
	if d.Active != nil {
		e := Execution{*d.Active}
		if e.validate() != nil || !a.scope(Blueprint{e.d.Plan}) || seen[e.d.Operation] || e.d.Epoch < d.MinEpoch[e.d.Submitter] {
			return ErrInputs
		}
		for _, stage := range e.d.Stages {
			if stage.Result != nil && stage.Result.Code == state.Applied {
				i := a.claim(stage.Key)
				if i < 0 || d.Claims[i].Result != *stage.Result {
					return ErrInputs
				}
				claim := d.Claims[i]
				if claim.Command != *stage.Command {
					step := e.d.Plan.Steps[e.index(stage.Key)]
					if !stage.Noop || (claim.Removed || claim.Retained) && !a.closedNoopClaim(claim) || claim.Command.Value != stage.Command.Value || claim.Step.Owner != step.Owner || claim.Step.Node != step.Node {
						return ErrInputs
					}
				}
			}
		}
	}
	if !a.validReplacementInventory() {
		return ErrInputs
	}
	if r := d.Retirement; r != nil {
		if r.KeepExecution {
			e, ok := a.Execution()
			if !ok || e.d.Replacement == nil || e.d.Replacement.Phase != "retiring" || r.Down || r.ID != e.replacementRetirementID() || r.Submitter != e.d.Submitter || r.Epoch != e.d.Epoch {
				return ErrInputs
			}
		}
		if !identifier(r.ID) || !identifier(r.Actor) || r.Submitter == "" || r.Epoch == 0 || r.Revision == 0 || r.Revision > d.Revision || len(r.Targets) > 1024 {
			return ErrInputs
		}
		targets := map[string]bool{}
		for _, t := range r.Targets {
			c := t.Original
			if !a.validClaim(c) || c.Removed || targets[c.Step.Key] || a.claim(c.Step.Key) < 0 || !r.Down && !containsString(r.Keys, c.Step.Key) {
				return ErrInputs
			}
			targets[c.Step.Key] = true
			for _, m := range []*Mutation{t.Drain, t.Proof, t.Delete} {
				if m != nil && (!m.valid() || m.Replay != nil && m.Replay.Revision > d.Revision || m.Command.Key != c.Step.Key || m.Command.Actor != r.Submitter || m.Command.Epoch != r.Epoch) {
					return ErrInputs
				}
			}
			if c.Step.Retain {
				if t.Drain != nil || t.Proof != nil || t.Delete != nil || t.Closed && c.Step.Owner != ([32]byte{}) && (t.Retained == nil || !a.validRetain(c, *t.Retained, r.ID, r.Revision)) {
					return ErrInputs
				}
			} else {
				var g GoalCommand
				_ = json.Unmarshal([]byte(c.Command.Value), &g)
				if c.Step.Owner == ([32]byte{}) && (c.Step.Kind != "delivery" || t.Drain != nil || t.Proof != nil || t.Delete == nil) {
					return ErrInputs
				}
				if c.Step.Owner != ([32]byte{}) && (t.Drain == nil || t.Drain.Command.Expected != c.Result.Revision) {
					return ErrInputs
				}
				if t.Drain != nil {
					g.Lifecycle = &schema.Lifecycle{Drain: true, Nonce: retirementNonce(d.Cluster, r.ID+"/"+string(goal(r.Revision)), c.Step.Key, c.Result.Generation)}
					if t.Drain.Command != retireCommand(*r, c, "drain", string(goal(g)), c.Result.Revision, false) {
						return ErrInputs
					}
				}
				if t.Proof != nil && (t.Drain == nil || t.Drain.Result == nil || t.Drain.Result.Code != state.Applied || schema.VerifyGone(c.Step.Owner, a.d.Cluster, c.Step.Key, c.Result.Generation, []byte(t.Drain.Command.Value), t.Gone) != nil) {
					return ErrInputs
				}
				if t.Proof != nil {
					g.Lifecycle.Proof = t.Gone
					if t.Proof.Command != retireCommand(*r, c, "proof", string(goal(g)), t.Drain.Result.Revision, false) {
						return ErrInputs
					}
				}
				if t.Delete != nil {
					expected := c.Result.Revision
					if c.Step.Owner != ([32]byte{}) {
						if t.Proof == nil || t.Proof.Result == nil || t.Proof.Result.Code != state.Applied {
							return ErrInputs
						}
						expected = t.Proof.Result.Revision
					}
					if t.Delete.Command != retireCommand(*r, c, "delete", "", expected, true) {
						return ErrInputs
					}
				}
				if t.Closed && !a.validRemoval(c, RemovalProof{r.ID, r.Revision, t.Drain, t.Proof, t.Delete, t.Gone}) {
					return ErrInputs
				}
			}
		}
		for _, claim := range d.Claims {
			if !claim.Removed && (r.Down || containsString(r.Keys, claim.Step.Key)) && !targets[claim.Step.Key] {
				return ErrInputs
			}
		}
	}
	return nil
}
func containsString(items []string, want string) bool {
	for _, s := range items {
		if s == want {
			return true
		}
	}
	return false
}
func (a Inventory) Encode() ([]byte, error) {
	if err := a.validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a.d)
	if len(raw) > 32<<20 {
		return nil, ErrInputs
	}
	return raw, err
}
func DecodeInventory(raw []byte) (Inventory, error) {
	if len(raw) > 32<<20 {
		return Inventory{}, ErrInputs
	}
	var d inventoryRecord
	if json.Unmarshal(raw, &d) != nil {
		return Inventory{}, ErrInputs
	}
	a := Inventory{d}
	if err := a.validate(); err != nil {
		return Inventory{}, err
	}
	canonical, _ := json.Marshal(d)
	if !bytes.Equal(raw, canonical) || strings.ContainsRune(d.App, 0) {
		return Inventory{}, ErrInputs
	}
	return a, nil
}
