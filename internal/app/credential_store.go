// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/sfcp"
)

// builtinLedger is the builtin credential store of this node: sealed
// records in Raft (control/credentials), opened with the cluster master key
// that only current voters hold.
type builtinLedger struct{ r *Runtime }

func (l builtinLedger) Cluster() [32]byte { return l.r.controlPolicy.Cluster }
func (l builtinLedger) Self() [32]byte    { return l.r.commandIdentity().Public }

// Ready reads only local applied state: the voter that seals or opens a
// record checks the current quorum view again on every read and write.
func (l builtinLedger) Ready() bool {
	r := l.r
	if r.historicalOwner || r.reports == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancel()
	_, members, err := r.members(ctx, false)
	if err != nil || !members.VoterKey(l.Self()) {
		return false
	}
	for _, owner := range r.physicalOwners() {
		if owner.reports != nil && owner.certificateNative().HasMaster() {
			return true
		}
	}
	return false
}

func (l builtinLedger) Master() ([]byte, error) { return l.r.certificateMaster() }

func (l builtinLedger) Record(ctx context.Context, id string) (credentials.BuiltinRecord, bool, error) {
	view, err := l.r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return credentials.BuiltinRecord{}, false, sfcp.ErrAdmission
	}
	members, err := l.r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(l.Self()) {
		return credentials.BuiltinRecord{}, false, credentials.ErrBuiltinUnavailable
	}
	return l.r.controlPolicy.BuiltinCredential(view.State, id)
}

// submit sends one signed store report. A ConditionFailed answer is a
// committed refusal (the store root moved or the record changed), so the
// caller may re-read and decide again; any other failure is unknown.
func (l builtinLedger) submit(ctx context.Context, action string, record *credentials.BuiltinRecord, id string) (state.Code, error) {
	view, err := l.r.physicalOwners()[0].currentView(ctx)
	if err != nil || view.Local {
		return 0, sfcp.ErrAdmission
	}
	self := l.r.commandIdentity()
	report := control.CredentialStoreReport{Schema: 1, Cluster: l.Cluster(), Reporter: self.Public, RootRevision: view.State.Object(control.CredentialsKey).Revision, Epoch: view.State.ModuleEpoch(), At: uint64(time.Now().Unix()), Action: action, Record: record, ID: id}
	report.Signature = ed25519.Sign(self.Private, control.CredentialStoreBytes(report))
	raw, err := json.Marshal(report)
	if err != nil {
		return 0, err
	}
	reply, err := l.r.appCall(ctx, "credential-store-report", raw)
	if err != nil {
		return 0, err
	}
	if reply.Committed == nil {
		return 0, sfcp.ErrAdmission
	}
	return reply.Committed.Result.Code, nil
}

func (l builtinLedger) Put(ctx context.Context, record credentials.BuiltinRecord) error {
	for range 3 {
		old, found, err := l.Record(ctx, record.ID)
		if err != nil {
			return err
		}
		if found {
			// Only this call's own earlier attempt can have written the same
			// sealed bytes; anything else is a different original write.
			if credentials.SameBuiltin(old, record) {
				return nil
			}
			return credentials.ErrDenied
		}
		code, err := l.submit(ctx, "put", &record, "")
		if err != nil {
			return err
		}
		if code == state.Applied {
			return nil
		}
		if code != state.ConditionFailed {
			return credentials.ErrDenied
		}
	}
	return credentials.ErrDenied
}

func (l builtinLedger) Consume(ctx context.Context, id string) error {
	for range 3 {
		old, found, err := l.Record(ctx, id)
		if err != nil {
			return err
		}
		if !found || old.Consumed {
			return credentials.ErrDenied
		}
		code, err := l.submit(ctx, "consume", nil, id)
		if err != nil {
			return err
		}
		if code == state.Applied {
			return nil
		}
		if code != state.ConditionFailed {
			return credentials.ErrDenied
		}
	}
	return credentials.ErrDenied
}
