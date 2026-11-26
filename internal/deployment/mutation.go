// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"encoding/json"

	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/reconcile"
)

// Mutation is a consumer of A2 for one immutable management request. It never
// automatically retries Unknown or treats an absent/expired ledger as NotApplied.
type Mutation struct {
	Command state.Command
	Journal reconcile.State
	Result  *state.Result
	Replay  *MutationReplay `json:",omitempty"`
}

// MutationReplay is a single explicit authorization to send the SAME immutable
// Raft command again. It never asserts NotApplied and never authorizes native
// effects directly. The command's retained ledger identity still deduplicates it.
type MutationReplay struct {
	Request    string
	Revision   uint64
	Dispatched bool
}

func (m Mutation) Dispatchable() bool {
	return m.Result == nil && m.Journal.Pending != nil &&
		(m.Journal.Pending.Phase == reconcile.Prepared ||
			m.Journal.Pending.Phase == reconcile.RecoveryRequired && m.Replay != nil && !m.Replay.Dispatched)
}

func newMutation(cmd state.Command, revision uint64) (Mutation, error) {
	j, err := reconcile.SetDesired(reconcile.State{}, reconcile.Desired{Revision: revision, Resource: reconcile.Resource{Generation: revision, Present: true, Spec: string(goal(cmd))}})
	if err != nil {
		return Mutation{}, err
	}
	j, _, err = reconcile.Plan(j)
	return Mutation{Command: cmd, Journal: j}, err
}
func (m Mutation) copy() Mutation {
	raw, _ := json.Marshal(m)
	var n Mutation
	_ = json.Unmarshal(raw, &n)
	return n
}
func (m Mutation) dispatch() (Mutation, error) {
	if m.Result != nil || m.Journal.Pending == nil {
		return m, ErrInputs
	}
	if m.Journal.Pending.Phase == reconcile.RecoveryRequired && m.Replay != nil && !m.Replay.Dispatched {
		n := m.copy()
		// Preserve the original pending ID/target/command and its Unknown
		// history. This is an explicitly authorized transmission, not reset.
		n.Journal.Pending.Phase = reconcile.Dispatched
		n.Replay.Dispatched = true
		return n, nil
	}
	j, err := reconcile.Dispatch(m.Journal, m.Journal.Pending.ID)
	if err != nil {
		return m, err
	}
	n := m.copy()
	n.Journal = j
	return n, nil
}
func (m Mutation) uncertain() (Mutation, error) {
	if m.Result != nil || m.Journal.Pending == nil {
		return m, ErrInputs
	}
	j, err := reconcile.Settle(m.Journal, m.Journal.Pending.ID, reconcile.EffectUnknown)
	if err != nil {
		return m, err
	}
	n := m.copy()
	n.Journal = j
	return n, nil
}
func (m Mutation) settle(shared state.State) (Mutation, error) {
	r, found := shared.LookupResult(m.Command)
	if !found || !validResult(r) {
		return m, inputError("ORIGINAL_RESULT_UNKNOWN", m.Command.Key)
	}
	if m.Result != nil {
		if *m.Result == r {
			return m, nil
		}
		return m, ErrInputs
	}
	if m.Journal.Pending == nil {
		return m, ErrInputs
	}
	outcome := reconcile.EffectNotApplied
	if r.Code == state.Applied {
		outcome = reconcile.EffectApplied
	}
	j, err := reconcile.Settle(m.Journal, m.Journal.Pending.ID, outcome)
	if err != nil {
		return m, err
	}
	n := m.copy()
	n.Journal = j
	n.Result = &r
	return n, nil
}
func (m Mutation) valid() bool {
	j := m.Journal
	if m.Replay != nil && (m.Replay.Request == "" || len(m.Replay.Request) > 512 || m.Replay.Revision < j.Desired.Revision ||
		m.Result == nil && (j.Pending == nil || !m.Replay.Dispatched && j.Pending.Phase != reconcile.RecoveryRequired ||
			m.Replay.Dispatched && j.Pending.Phase != reconcile.Dispatched && j.Pending.Phase != reconcile.RecoveryRequired)) {
		return false
	}
	if reconcile.Validate(j) != nil || j.LastID != 1 || j.Stopped || !j.Desired.Present || j.Desired.Spec != string(goal(m.Command)) || j.Desired.Generation != j.Desired.Revision {
		return false
	}
	if m.Result == nil {
		return j.Pending != nil && !j.Applied.Present && j.Pending.Target == j.Desired.Resource
	}
	return validResult(*m.Result) && j.Pending == nil && (m.Result.Code == state.Applied && j.Applied == j.Desired.Resource || m.Result.Code != state.Applied && !j.Applied.Present)
}
