// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/tenancy"
)

type AppRetirementProgress struct {
	Phase     string                       `json:",omitempty"`
	Gone      []byte                       `json:",omitempty"`
	Retained  *deployment.RetainReceipt    `json:",omitempty"`
	DNS       *services.ReferenceClose     `json:",omitempty"`
	Addresses []services.AddressOwnerClose `json:",omitempty"`
	Network   *tenancy.NetworkClosure      `json:",omitempty"`
}

func validRetirementReport(r AppProgress) bool {
	if r.Retire == nil || r.Observation != nil || r.Release != nil || r.Volume != nil {
		return false
	}
	p := r.Retire
	if r.Action != "retire-gone" && (p.DNS != nil || p.Network != nil) || r.Action != "retire-addresses" && len(p.Addresses) != 0 {
		return false
	}
	switch r.Action {
	case "retire-dns":
		return r.Key != "" && p.Phase == "" && len(p.Gone) == 0 && p.Retained == nil
	case "retire-addresses":
		return r.Key != "" && (p.Phase == "fence" && len(p.Addresses) == 0 || p.Phase == "release" && len(p.Addresses) > 0 && len(p.Addresses) <= 16) && len(p.Gone) == 0 && p.Retained == nil
	case "retire-send", "retire-unknown", "retire-collect":
		return r.Key != "" && (p.Phase == "drain" || p.Phase == "proof" || p.Phase == "delete") && len(p.Gone) == 0 && p.Retained == nil
	case "retire-gone":
		return r.Key != "" && p.Phase == "" && len(p.Gone) == ed25519.SignatureSize && p.Retained == nil
	case "retire-retain":
		return r.Key != "" && p.Phase == "" && len(p.Gone) == 0 && p.Retained != nil
	case "retire-finish":
		return r.Key == "" && p.Phase == "" && len(p.Gone) == 0 && p.Retained == nil
	}
	return false
}
func (p Policy) validateAppDown(i deployment.Inventory, origin UserOperation, op *UserOperation) error {
	return p.validateAppDownTarget(i, origin, op, appDownTarget(origin), "")
}
func (p Policy) validateAppDownTarget(i deployment.Inventory, origin UserOperation, op *UserOperation, target [32]byte, retirementID string) error {
	r, retiring := i.Retirement()
	if op == nil {
		if retiring && !r.KeepExecution {
			return ErrCatalog
		}
		return nil
	}
	var down AppDown
	cmd, err := op.Command()
	scope := i.Scope()
	expected := op.Change.Expected
	if op.Change.Action == "begin-volume-move" || op.Change.Action == "drain-node" {
		down, expected, err = moveAppRetirement(*op, scope)
	} else if op.Change.Action != "down-app" || canonical(op.Change.Payload, &down) != nil {
		return ErrCatalog
	}
	if err != nil || op.VerifyOriginal(p.Cluster) != nil || down.Tenant != scope.Tenant || down.App != scope.App || down.Operation == "" {
		return ErrCatalog
	}
	if AppDownCASAllowed(op.Change) && (down.Target == nil || *down.Target != target || expected > i.Revision()) {
		return ErrCatalog
	}
	if retiring {
		positionOK := r.Revision == expected+1
		if (op.Change.Action == "begin-volume-move" || op.Change.Action == "drain-node") || AppDownCASAllowed(op.Change) {
			positionOK = r.Revision > expected
		}
		id := down.Operation
		if retirementID != "" {
			id = retirementID
			positionOK = r.Revision > expected
		}
		if !r.Down || r.ID != id || r.Actor != op.Session.User || r.Submitter != cmd.Actor || r.Epoch != cmd.Epoch || !positionOK {
			return ErrCatalog
		}
	} else if _, active := i.Execution(); active {
		return ErrCatalog
	}
	return nil
}
func appView(entry appEntry, scope deployment.AppScope) AppView {
	i := entry.Inventory
	active, ok := i.Active()
	if !ok {
		if origin, err := appExecutionOrigin(entry.Origin, entry.Sync, scope); err == nil {
			active, _ = i.Operation(origin.Operation)
		}
	}
	if !ok && entry.Compacted != nil {
		active = *entry.Compacted
	}
	v := AppView{Tenant: scope.Tenant, App: scope.App, Deployment: scope.Deployment, Revision: i.Revision(), Operation: active, Claims: len(i.Claims())}
	if target := entry.beginTarget(); target != ([32]byte{}) {
		v.BeginTarget = &target
	}
	if execution, exists := i.Execution(); exists {
		if replacement, ok := execution.Replacement(); ok {
			v.Replacement = &replacement
			if retirement, pending := i.Retirement(); pending && retirement.KeepExecution {
				v.Retirement = &AppRetirementStatus{ID: retirement.ID, Status: "Retiring"}
			}
		}
	}
	v.LogClear = appLogClearView(entry, "")
	if proof := entry.PendingSync; proof != nil && proof.Recreate != nil {
		status := "Retiring"
		if proof.Recreate.Closure != ([32]byte{}) {
			status = "Retired"
		}
		v.Retirement = &AppRetirementStatus{ID: proof.Choice.Operation, Status: status}
	}
	v.CD = appCDView(entry)
	if v.CD != nil && v.CD.Transition != nil && entry.Down == nil {
		status := "Retiring"
		if v.CD.Transition.Phase == "ready" {
			status = "Retired"
		}
		v.Retirement = &AppRetirementStatus{ID: v.CD.Transition.Selection.Operation, Status: status}
	}
	if entry.Down != nil {
		var down AppDown
		if entry.Down.Change.Action == "begin-volume-move" || entry.Down.Change.Action == "drain-node" {
			down, _, _ = moveAppRetirement(*entry.Down, i.Scope())
		} else {
			_ = canonical(entry.Down.Change.Payload, &down)
		}
		status := "Retired"
		if _, retiring := i.Retirement(); retiring {
			status = "Retiring"
		}
		v.Retirement = &AppRetirementStatus{ID: down.Operation, Status: status}
	}
	if validStandaloneCleanup(entry) {
		q := *entry.Standalone.Cleanup
		status := "Retired"
		if _, ok := i.Retirement(); ok {
			status = "Retiring"
		}
		v.Retirement = &AppRetirementStatus{ID: standalonePolicyID(q), Status: status}
	}
	if v.Retirement != nil {
		if retirement, found := i.Retirement(); found {
			for _, target := range retirement.Targets {
				if target.Closed || !i.CanRetire(target.Original.Step.Key) {
					continue
				}
				for _, phase := range []string{"drain", "proof", "delete"} {
					m, found := i.Removal(target.Original.Step.Key, phase)
					if found && m.Result == nil && m.Journal.Pending != nil && m.Journal.Pending.Phase == reconcile.RecoveryRequired {
						v.Retirement.Pending = &AppRetirementPending{Retirement: retirement.ID, Key: target.Original.Step.Key, Phase: phase, Request: m.Command.RequestID, Command: state.Digest(m.Command), ReplayAuthorized: m.Dispatchable()}
						break
					}
				}
				if v.Retirement.Pending != nil {
					break
				}
			}
		}
	}
	return v
}
func (a Apps) Inventory(tenant, app string) (deployment.Inventory, bool) {
	entry, ok := a.entries[appKey(tenant, app)]
	if !ok {
		return deployment.Inventory{}, false
	}
	raw, _ := entry.Inventory.Encode()
	i, err := deployment.DecodeInventory(raw)
	return i, err == nil
}
func (a Apps) Claim(tenant, app string, ref deployment.ObjectRef) (deployment.Claim, bool) {
	return bindingClaim(a.entries[appKey(tenant, app)], ref)
}
func (p Policy) authorizeAppRemoval(s state.State, entry appEntry) error {
	retirement, retiring := entry.Inventory.Retirement()
	rolling := retiring && retirement.KeepExecution
	if validStandaloneCleanup(entry) {
		return nil
	}
	if entry.Down == nil && entry.PendingSync == nil && !rolling {
		return access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	op := entry.Down
	if op == nil {
		op = &entry.Origin
		if entry.PendingSync != nil && entry.PendingSync.User != nil {
			op = entry.PendingSync.User
		}
		if rolling && entry.Sync != nil && entry.Sync.User != nil {
			op = entry.Sync.User
		}
	}
	return c.AuthorizeAcceptedCleanup(op.Session, p.Cluster, op.At, entry.Inventory.Scope().Tenant, access.Deploy)
}
func (p Policy) reduceAppRetirement(s state.State, r AppProgress, a Apps, entry appEntry) (map[string][]byte, state.Code) {
	retirement, ok := entry.Inventory.Retirement()
	acceptedAt := uint64(entry.Origin.At)
	if entry.Down != nil {
		acceptedAt = uint64(entry.Down.At)
	}
	if entry.PendingSync != nil && entry.PendingSync.User != nil {
		acceptedAt = uint64(entry.PendingSync.User.At)
	}
	if entry.PendingSync != nil && entry.PendingSync.Member != nil {
		acceptedAt = entry.PendingSync.Member.At
	}
	if !ok || retirement.ID != r.Operation || entry.Down == nil && entry.PendingSync == nil && !validStandaloneCleanup(entry) && !retirement.KeepExecution || r.At < acceptedAt {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	if r.Action == "retire-send" && p.authorizeAppRemoval(s, entry) != nil {
		return nil, state.Forbidden
	}
	i := entry.Inventory
	switch r.Action {
	case "retire-dns":
		return p.retireAppDNS(s, r, a, entry)
	case "retire-addresses":
		return p.retireAppAddresses(s, r, a, entry)
	case "retire-send":
		if m, found := i.Removal(r.Key, r.Retire.Phase); found && m.Journal.Pending != nil && m.Journal.Pending.Phase == reconcile.RecoveryRequired {
			if _, committed := s.LookupResult(m.Command); committed {
				return nil, state.ConditionFailed
			}
		}
		if validStandaloneCleanup(entry) {
			i, err = i.SendAcceptedPolicyRemoval(i.Revision(), r.Key, r.Retire.Phase)
		} else {
			i, err = i.SendRemoval(i.Revision(), c, retirement.Actor, r.Key, r.Retire.Phase)
		}
	case "retire-unknown":
		m, ok := i.Removal(r.Key, r.Retire.Phase)
		if !ok || m.Journal.Pending == nil || m.Journal.Pending.Phase != reconcile.Dispatched {
			return nil, state.ConditionFailed
		}
		if _, found := s.LookupResult(m.Command); found {
			return nil, state.ConditionFailed
		}
		i, err = i.UnknownRemoval(i.Revision(), r.Key, r.Retire.Phase)
	case "retire-collect":
		i, err = i.SettleRemoval(i.Revision(), r.Key, r.Retire.Phase, s)
	case "retire-gone":
		for _, b := range a.bindings.Live() {
			if source, ok := a.BindingSource(b.Digest()); ok && (source.Task.Key == r.Key || source.Inputs.Key == r.Key) {
				return nil, state.ConditionFailed
			}
		}
		i, err = i.Gone(i.Revision(), r.Key, r.Retire.Gone)
		if err == nil {
			a, err = p.closeAppNetwork(s, r, a, entry)
		}
	case "retire-retain":
		for _, target := range retirement.Targets {
			if target.Original.Step.Key == r.Key && target.Original.Step.Kind == "volume" {
				v, e := p.Volumes(s)
				if e != nil {
					return nil, state.Invalid
				}
				id := r.Key[strings.LastIndex(r.Key, "/")+1:]
				row, exists := v.entries[r.Tenant+"/"+r.App+"/"+id]
				if !exists || len(row.State.Consumers()) != 0 || row.Native.Owner.Native != r.Retire.Retained.Native {
					return nil, state.ConditionFailed
				}
			}
		}
		i, err = i.Retained(i.Revision(), r.Key, r.Retire.Retained)
	case "retire-finish":
		for _, target := range retirement.Targets {
			if target.Original.Step.Kind == "task" && target.Closed {
				allocations, err := a.NetworkRetirementAllocations(r.Tenant, r.App, target.Original.Step.Key)
				if err != nil || len(allocations) != 0 {
					return nil, state.ConditionFailed
				}
			}
		}
		for _, b := range a.bindings.Live() {
			if b.Needs().Use.Tenant == r.Tenant && b.Needs().Use.App == r.App && !preserveRetirementBinding(s, a, entry, retirement, b) {
				return nil, state.ConditionFailed
			}
		}
		if entry.Delivery != nil && !retirement.KeepExecution {
			actor := retirement.Actor
			d, finishErr := entry.Delivery.FinishRetirement(entry.Delivery.Revision(), c, actor)
			err = finishErr
			if err == nil {
				entry.Delivery, i = &d, d.Inventory()
			}
		} else {
			i, err = i.FinishRetirement(i.Revision())
		}
	default:
		return nil, state.Forbidden
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	if r.Action == "retire-finish" && entry.PendingSync != nil && entry.PendingSync.Recreate != nil {
		encoded, _ := json.Marshal(retirement)
		proof := *entry.PendingSync
		recreation := *proof.Recreate
		recreation.Closure = sha256.Sum256(append([]byte("sfc-log-clear-closure-1\x00"), encoded...))
		proof.Recreate = &recreation
		entry.PendingSync = &proof
	}
	entry.Inventory = i
	a.entries[appKey(r.Tenant, r.App)] = entry
	return p.appsCheckpoint(s, a, r.At)
}

// Partial CD retirement closes only its selected resources. Unchanged Tasks
// retain their original input/Secret/Volume binding; full down cannot do so.
// This is structural provenance, never fresh activation authority.
func preserveRetirementBinding(s state.State, a Apps, entry appEntry, retirement deployment.RetirementView, b deployment.Binding) bool {
	if retirement.Down || entry.Down != nil || !retirement.KeepExecution && (entry.PendingSync == nil || entry.Delivery == nil && entry.PendingSync.Recreate == nil) {
		return false
	}
	n, scope := b.Needs(), entry.Inventory.Scope()
	if n.Use.Tenant != scope.Tenant || n.Use.App != scope.App || n.Use.Deployment != scope.Deployment {
		return false
	}
	source, known := a.BindingSource(b.Digest())
	if !known || source.Task.Key == "" {
		return false
	}
	for _, ref := range []deployment.ObjectRef{source.Task, source.Inputs} {
		if ref == (deployment.ObjectRef{}) {
			continue
		}
		claim, found := bindingClaim(entry, ref)
		current := s.Object(ref.Key)
		if !found || claim.Removed || claim.Retained || !current.Present || current.Generation != ref.Generation || current.Revision != ref.Revision || current.Value != claim.Command.Value {
			return false
		}
		for _, target := range retirement.Targets {
			if target.Original.Step.Key == ref.Key {
				return false
			}
		}
	}
	return true
}
func (p Policy) admitAppRemoval(s state.State, a Apps, cmd state.Command) bool {
	for _, entry := range a.entries {
		r, ok := entry.Inventory.Retirement()
		if !ok || !strings.HasPrefix(cmd.Actor, "user/") && !validStandaloneCleanup(entry) || p.authorizeAppRemoval(s, entry) != nil {
			continue
		}
		for _, target := range r.Targets {
			if target.Closed || !entry.Inventory.CanRetire(target.Original.Step.Key) {
				continue
			}
			for _, m := range []*deployment.Mutation{target.Drain, target.Proof, target.Delete} {
				if m != nil && m.Command == cmd && m.Result == nil && m.Journal.Pending != nil && (m.Journal.Pending.Phase == reconcile.Dispatched || m.Journal.Pending.Phase == reconcile.RecoveryRequired) {
					return true
				}
			}
		}
	}
	return false
}
func appRemovalResult(entry appEntry, cmd state.Command) (*state.Result, bool) {
	if r, ok := entry.Inventory.Retirement(); ok {
		for _, t := range r.Targets {
			for _, m := range []*deployment.Mutation{t.Drain, t.Proof, t.Delete} {
				if m != nil && m.Command == cmd {
					return m.Result, true
				}
			}
		}
	}
	for _, claim := range entry.Inventory.Claims() {
		if claim.Removal != nil {
			for _, m := range []*deployment.Mutation{claim.Removal.Drain, claim.Removal.Proof, claim.Removal.Delete} {
				if m != nil && m.Command == cmd {
					return m.Result, true
				}
			}
		}
	}
	return nil, false
}

func isRetirementAction(action string) bool { return strings.HasPrefix(action, "retire-") }
