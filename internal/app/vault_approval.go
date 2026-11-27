// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/credentials"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/userauth"
)

func (r *Runtime) openVaultApprovals(root string) error {
	r.vaultApprovalBudget = credentials.NewBudget()
	var err error
	r.vaultApprovals, err = reconcile.OpenJournal(filepath.Join(root, "vault", "approvals.db"))
	return err
}
func (r *Runtime) vaultApprovalPermit(ctx context.Context, session access.Session, target secrets.Target, origin *control.UserOperation, selection *control.AppApprovalSelection) (control.VaultApprovalPermit, error) {
	raw, _ := json.Marshal(control.VaultApprovalPermitRequest{Session: session, Target: target, At: time.Now().Unix(), Origin: origin, Selection: selection})
	reply, err := r.appCall(ctx, "vault-approval-permit", raw)
	if err != nil {
		return control.VaultApprovalPermit{}, err
	}
	permit, err := schema.Decode[control.VaultApprovalPermit](reply.Data)
	left, _ := json.Marshal(permit.Target)
	right, _ := json.Marshal(target)
	if err != nil || !bytes.Equal(left, right) {
		return control.VaultApprovalPermit{}, secrets.ErrPolicy
	}
	return permit, nil
}
func approvalJournalKey(cluster, node [32]byte, target secrets.Target) string {
	raw, _ := json.Marshal(struct {
		Cluster, Node [32]byte
		Target        secrets.Target
	}{cluster, node, target})
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("approval/%x", digest)
}
func (r *Runtime) approveVault(ctx context.Context, session access.Session, q userauth.SecretRequest, source string) (secrets.Approval, error) {
	r.vaultApprovalLife.RLock()
	defer r.vaultApprovalLife.RUnlock()
	if r.ctx.Err() != nil || r.vaultApprovals == nil || q.Target == nil {
		return secrets.Approval{}, secrets.ErrPolicy
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	target := *q.Target
	permit, err := r.vaultApprovalPermit(ctx, session, target, q.Origin, q.Selection)
	if err != nil {
		return secrets.Approval{}, secrets.ErrPolicy
	}
	if permit.Existing != nil {
		return *permit.Existing, nil
	}
	key := approvalJournalKey(r.controlPolicy.Cluster, r.Identity.Public, target)
	known := slices.Contains(r.vaultApprovals.Keys(), key)
	if !known {
		if len(r.vaultApprovals.Keys()) >= 4096 || len(q.Password) == 0 {
			return secrets.Approval{}, secrets.ErrPolicy
		}
		builtin := permit.Binding.Reference.Profile == secrets.BuiltinProfile
		backend := r.vaultBackends[vaultBackendKey(target.Realm, permit.Binding.Reference.Profile)]
		if !builtin && (backend == nil || !backend.config.Verifiers || backend.verifier == nil) {
			return secrets.Approval{}, secrets.ErrProvider
		}
		release, err := r.vaultApprovalBudget.Begin(ctx, session.User, source, time.Now())
		if err != nil {
			return secrets.Approval{}, secrets.ErrPolicy
		}
		defer release()
		var fetched secrets.Fetched
		if builtin {
			fetched, err = r.openBuiltinVerifier(ctx, target.Realm, permit.Binding)
		} else {
			fetched, err = backend.verifier.FetchVerifier(ctx, target.Group, permit.Binding)
		}
		if err != nil {
			return secrets.Approval{}, secrets.ErrProvider
		}
		verifier, restoreErr := identity.RestorePasswordVerifier(fetched.Values["verifier"])
		for _, value := range fetched.Values {
			clear(value)
		}
		if restoreErr != nil || !verifier.Verify(q.Password) || ctx.Err() != nil {
			return secrets.Approval{}, secrets.ErrPolicy
		}
		release()
		fresh, err := r.vaultApprovalPermit(ctx, session, target, q.Origin, q.Selection)
		if err != nil || !permit.Binding.Equal(fresh.Binding) {
			return secrets.Approval{}, secrets.ErrPolicy
		}
		if fresh.Existing != nil {
			return *fresh.Existing, nil
		}
		permit = fresh
		at := time.Now().Unix()
		approval := secrets.Approval{Schema: 1, Issuer: r.Identity.Public, Payload: secrets.ApprovalPayload{ApprovedAt: at, Fact: "secret-group-use-approved", Target: target}}
		approval.Signature = ed25519.Sign(r.Identity.Private, secrets.ApprovalBytes(approval))
		report := control.VaultApprovalReport{Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.commandIdentity().Public, Session: session, Approval: approval, At: at, Epoch: permit.Epoch, RootRevision: permit.RootRevision, Capacity: permit.Capacity, RequestID: key, Origin: q.Origin, Selection: q.Selection}
		report.Signature = ed25519.Sign(r.commandIdentity().Private, control.VaultApprovalReportBytes(report))
		command, err := report.Command()
		if err != nil {
			return secrets.Approval{}, err
		}
		spec, err := state.EncodeCommand(command)
		if err != nil {
			return secrets.Approval{}, err
		}
		// Existing key/spec is immutable. Two concurrent issuers for the same local
		// target cannot replace one another's first original command or root CAS.
		if err = r.vaultApprovals.Desired(key, reconcile.Desired{Revision: 1, Resource: reconcile.Resource{Generation: 1, Spec: string(spec), Present: true}}, 1); err != nil {
			return secrets.Approval{}, err
		}
	}
	record, err := r.vaultApprovals.Read(key)
	if err != nil {
		return secrets.Approval{}, err
	}
	command, err := state.DecodeCommand([]byte(record.State.Desired.Spec))
	if err != nil {
		return secrets.Approval{}, err
	}
	stored, err := schema.Decode[control.VaultApprovalReport]([]byte(command.Value))
	left, _ := json.Marshal(stored.Approval.Payload.Target)
	right, _ := json.Marshal(target)
	if err != nil || stored.Cluster != r.controlPolicy.Cluster || stored.Reporter != r.Identity.Public || command.Actor != "node/"+r.Identity.Actor() || !bytes.Equal(left, right) || !ed25519.Verify(r.Identity.Public[:], control.VaultApprovalReportBytes(stored), stored.Signature) {
		return secrets.Approval{}, secrets.ErrPolicy
	}
	if err = r.vaultApprovals.Step(ctx, key, &approvalDriver{runtime: r, command: command}); err != nil {
		return secrets.Approval{}, userauth.ErrApprovalUnknown
	}
	// The metadata request being processed is distinct from the approval being
	// valid now. Re-read current shared authority before returning any approval.
	latest, err := r.vaultApprovalPermit(ctx, session, target, q.Origin, q.Selection)
	if err != nil || latest.Existing == nil {
		return secrets.Approval{}, secrets.ErrPolicy
	}
	return *latest.Existing, nil
}

type approvalDriver struct {
	runtime *Runtime
	command state.Command
}

func (d *approvalDriver) Execute(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	if !d.matches(op) {
		return reconcile.EffectUnknown, secrets.ErrPolicy
	}
	raw, err := state.EncodeCommand(d.command)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	reply, err := d.runtime.appCall(ctx, "vault-approve-command", raw)
	if err != nil || reply.Committed == nil {
		return reconcile.EffectUnknown, userauth.ErrApprovalUnknown
	}
	return reconcile.EffectApplied, nil // Any definite A1 result, including rejection.
}
func (d *approvalDriver) Recover(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	if !d.matches(op) {
		return reconcile.EffectUnknown, secrets.ErrPolicy
	}
	raw, err := state.EncodeCommand(d.command)
	if err != nil {
		return reconcile.EffectUnknown, err
	}
	reply, err := d.runtime.appCall(ctx, "vault-approval-result", raw)
	if err != nil {
		return reconcile.EffectUnknown, userauth.ErrApprovalUnknown
	}
	result, err := schema.Decode[control.AppResult](reply.Data)
	if err != nil || !result.Found || result.Result == nil {
		return reconcile.EffectUnknown, userauth.ErrApprovalUnknown
	}
	return reconcile.EffectApplied, nil
}
func (d *approvalDriver) matches(op reconcile.Operation) bool {
	raw, err := state.EncodeCommand(d.command)
	return err == nil && op.Kind == reconcile.Apply && op.Target.Present && op.Target.Generation == 1 && op.Target.Spec == string(raw)
}

var _ reconcile.Driver = (*approvalDriver)(nil)
