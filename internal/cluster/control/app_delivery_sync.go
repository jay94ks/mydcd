// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

type AppDeliveryChoice struct {
	Operation               string
	Candidate, Registration [32]byte
}
type AppCDChange struct {
	Tenant, App    string
	Choice         *AppDeliveryChoice              `json:",omitempty"`
	Policy         *deployment.DeliveryDeclaration `json:",omitempty"`
	PolicyRevision uint64                          `json:",omitempty"`
	Target         *[32]byte                       `json:",omitempty"`
}

// AppDeliverySync preserves the accepted authority and semantic choice while
// the same Inventory moves from retirement to the rebased original execution.
// User and Member are original signed inputs, never fabricated begin-app ops.
type AppDeliverySync struct {
	Local                  *AppLocalGrant `json:",omitempty"`
	Choice                 AppDeliveryChoice
	Plan, Intent, Artifact [32]byte
	Epoch                  uint64
	User                   *UserOperation       `json:",omitempty"`
	Member                 *AppDeliveryProgress `json:",omitempty"`
}
type appExecutionIdentity struct {
	Operation, Submitter string
	Epoch                uint64
}

func appRegistrationDigest(origin UserOperation) [32]byte {
	raw, _ := json.Marshal(origin)
	return sha256.Sum256(append([]byte("sfc-app-registration-1\x00"), raw...))
}
func (sync AppDeliverySync) verify(origin UserOperation, scope deployment.AppScope) error {
	if sync.Local != nil && sync.Local.verify(origin, scope, nil) != nil {
		return ErrCatalog
	}
	if sync.Epoch == 0 || sync.Plan == ([32]byte{}) || sync.Intent == ([32]byte{}) || sync.Artifact == ([32]byte{}) || sync.Choice.Candidate == ([32]byte{}) || sync.Choice.Registration != appRegistrationDigest(origin) || deployment.ResourceKey("task", scope.Tenant, scope.App, sync.Choice.Operation) == "" || (sync.User == nil) == (sync.Member == nil) {
		return ErrCatalog
	}
	if sync.User != nil {
		u := sync.User
		if u.Change.Action == "drain-node" {
			var q NodeDrainChange
			if u.VerifyOriginal(scope.Cluster) != nil || u.At < origin.At || u.Epoch != sync.Epoch || canonical(u.Change.Payload, &q) != nil {
				return ErrCatalog
			}
			for _, job := range q.Jobs {
				if job.Tenant != scope.Tenant || job.App != scope.App || job.Deployment != scope.Deployment || job.Operation != sync.Choice.Operation {
					continue
				}
				source := job.CD
				if source == nil || !source.Valid() || source.Registration != sync.Choice.Registration || source.Principal != origin.Session.User || source.Requester != origin.Session.Key || source.Intent != sync.Intent || source.Input != sync.Artifact {
					return ErrCatalog
				}
				return nil
			}
			return ErrCatalog
		}
		if u.Change.Action == "begin-volume-move" {
			var move VolumeMoveBegin
			if u.VerifyOriginal(scope.Cluster) != nil || u.At < origin.At || u.Epoch != sync.Epoch || canonical(u.Change.Payload, &move) != nil || move.Scope.Cluster != scope.Cluster || move.Scope.Tenant != scope.Tenant || move.Scope.App != scope.App || move.App == nil || move.App.Target == nil || move.App.CD == nil || !move.App.CD.Valid() || move.App.Target.Operation != sync.Choice.Operation || move.App.CD.Registration != sync.Choice.Registration || move.App.CD.Principal != origin.Session.User || move.App.CD.Requester != origin.Session.Key || move.App.CD.Intent != sync.Intent || move.App.CD.Input != sync.Artifact {
				return ErrCatalog
			}
			return nil
		}
		var q AppCDChange
		if u.VerifyOriginal(scope.Cluster) != nil || u.At < origin.At || u.Epoch != sync.Epoch || u.Change.Action != "sync-app" && u.Change.Action != "recover-app" || canonical(u.Change.Payload, &q) != nil || q.Tenant != scope.Tenant || q.App != scope.App || q.Choice == nil || *q.Choice != sync.Choice || q.Policy != nil || q.PolicyRevision != 0 {
			return ErrCatalog
		}
		if q.Target != nil && !AppSyncCASAllowed(u.Change) {
			return ErrCatalog
		}
	} else {
		r := sync.Member
		if r.Target != nil && (!r.TargetCAS || *r.Target == ([32]byte{})) {
			return ErrCatalog
		}
		if r.Schema != 1 || r.Kind != "app-delivery" || r.Cluster != scope.Cluster || r.Reporter == ([32]byte{}) || r.Tenant != scope.Tenant || r.App != scope.App || r.Action != "auto-sync" || r.Epoch != sync.Epoch || r.Expected == 0 || r.RootRevision == 0 || r.At == 0 || r.At > math.MaxInt64 || r.At < uint64(origin.At) || r.Choice == nil || *r.Choice != sync.Choice || r.Input != nil || r.Begin != nil || r.Part != nil || r.Ticket != nil || r.Error != "" || !ed25519.Verify(ed25519.PublicKey(r.Reporter[:]), AppDeliveryProgressBytes(*r), r.Signature) {
			return ErrCatalog
		}
	}
	return nil
}
func appExecutionOrigin(origin UserOperation, sync *AppDeliverySync, scope deployment.AppScope) (appExecutionIdentity, error) {
	begin, err := appOriginBegin(origin, scope)
	cmd, commandErr := origin.Command()
	if err != nil || commandErr != nil {
		return appExecutionIdentity{}, ErrCatalog
	}
	id := appExecutionIdentity{begin.Operation, cmd.Actor, cmd.Epoch}
	if sync != nil {
		if sync.verify(origin, scope) != nil {
			return id, ErrCatalog
		}
		id.Operation, id.Epoch = sync.Choice.Operation, sync.Epoch
	}
	return id, nil
}
func (entry appEntry) downTarget() [32]byte {
	if entry.Sync == nil {
		return appDownTarget(entry.Origin)
	}
	raw, _ := json.Marshal(struct {
		Origin UserOperation
		Sync   AppDeliverySync
	}{entry.Origin, *entry.Sync})
	return sha256.Sum256(append([]byte("sfc-app-cd-down-target-1\x00"), raw...))
}
func syncFromChoice(choice AppDeliveryChoice, selected deployment.DeliverySelection, epoch uint64, user *UserOperation, member *AppDeliveryProgress) *AppDeliverySync {
	return &AppDeliverySync{Choice: choice, Plan: selected.Plan, Intent: selected.Intent, Artifact: selected.Artifact, Epoch: epoch, User: user, Member: member}
}

func (sync AppDeliverySync) rebasesCandidate() bool {
	return sync.User != nil && AppSyncCASAllowed(sync.User.Change) || sync.Member != nil && sync.Member.TargetCAS && sync.Member.Target != nil
}

func (p Policy) authorizeCDSelection(s state.State, c access.Catalog, entry appEntry, b deployment.Blueprint, manual *UserOperation, local *AppLocalGrant) error {
	if err := p.admitIngressBlueprint(s, b); err != nil {
		return err
	}
	if err := p.imageCacheBlueprintAvailable(s, b); err != nil {
		return err
	}
	if entry.Delivery == nil || b.Scope().Actor != entry.Delivery.Principal() || b.Scope().Tenant != entry.Inventory.Scope().Tenant || b.Scope().App != entry.Inventory.Scope().App || b.Scope().Deployment != entry.Inventory.Scope().Deployment || c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, b.Scope().Tenant, access.ManageCD, "") != nil {
		return access.ErrDenied
	}
	for _, step := range b.Steps() {
		if c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, b.Scope().Tenant, step.Action(), step.Node) != nil {
			return access.ErrDenied
		}
		if manual != nil && c.AuthorizeSession(manual.Session, p.Cluster, p.Issuer(manual.Session.Issuer), manual.At, b.Scope().Tenant, step.Action(), step.Node) != nil {
			return access.ErrDenied
		}
	}
	return p.authorizeLocalBlueprint(s, c, entry, local, b)
}

func (p Policy) acceptCDSync(s state.State, entry appEntry, choice AppDeliveryChoice, manual *UserOperation, member *AppDeliveryProgress, recover bool) (appEntry, error) {
	if entry.Delivery == nil || choice.Registration != appRegistrationDigest(entry.Origin) || entry.Down != nil || entry.PendingSync != nil {
		return entry, ErrCatalog
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(entry.Inventory.Scope().Tenant, entry.Inventory.Scope().App) {
		return entry, ErrCatalog
	}
	d := *entry.Delivery
	c, ctx, err := p.appDeliveryAccess(s, entry)
	if err != nil {
		return entry, err
	}
	if member != nil && d.Policy().Sync.Mode != "automatic" && !acceptedCDApproval(c, entry) {
		return entry, access.ErrDenied
	}
	b, exists := d.CandidateBlueprint()
	selected, selectedOK := d.CandidateSelection()
	if !exists || !selectedOK || selected.Candidate != choice.Candidate {
		return entry, ErrCatalog
	}
	if manual != nil && AppSyncCASAllowed(manual.Change) || member != nil && member.Target != nil {
		// The original signed choice stays fixed. Only its current CAS/readiness
		// bases are rebased, with identical artifact and effective intent.
		original := selected
		d, err = d.RebaseCandidate(d.Revision(), c, ctx)
		if err != nil {
			return entry, err
		}
		b, exists = d.CandidateBlueprint()
		selected, selectedOK = d.CandidateSelection()
		if !exists || !selectedOK || selected.Intent != original.Intent || selected.Artifact != original.Artifact {
			return entry, ErrCatalog
		}
	}
	if p.authorizeCDSelection(s, c, entry, b, manual, entry.Local) != nil {
		return entry, ErrCatalog
	}
	at := int64(0)
	if manual != nil {
		at = manual.At
	} else if member != nil && member.At <= math.MaxInt64 {
		at = int64(member.At)
	}
	if p.checkCDGroupApprovals(s, c, entry, b, at) != nil {
		return entry, access.ErrDenied
	}
	if e, active := entry.Inventory.Execution(); active && e.Status() == "Failed" && !recover {
		return entry, ErrCatalog
	}
	actor := d.Principal()
	epoch := s.ModuleEpoch()
	if manual != nil {
		actor, epoch = manual.Session.User, manual.Epoch
	}
	identity, err := appExecutionOrigin(entry.Origin, entry.Sync, entry.Inventory.Scope())
	if err != nil {
		return entry, err
	}
	var n deployment.Delivery
	if member != nil {
		n, err = d.SyncAutomatic(d.Revision(), c, ctx, choice.Operation, identity.Submitter, epoch)
	} else {
		n, err = d.Sync(d.Revision(), c, ctx, actor, choice.Operation, identity.Submitter, epoch, recover)
	}
	if err != nil {
		return entry, err
	}
	proof := syncFromChoice(choice, selected, epoch, manual, member)
	proof.Local = ownLocalGrant(entry.Local)
	if proof.verify(entry.Origin, entry.Inventory.Scope()) != nil {
		return entry, ErrCatalog
	}
	entry.Delivery, entry.Inventory = &n, n.Inventory()
	if _, retiring := n.Transition(); retiring {
		entry.PendingSync = proof
	} else {
		entry.Sync = proof
	}
	entry.Compacted = nil
	return entry, nil
}

func (p Policy) continueCDSync(s state.State, entry appEntry, at uint64) (appEntry, error) {
	if entry.Delivery == nil {
		return entry, ErrCatalog
	}
	d := *entry.Delivery
	t, exists := d.Transition()
	if !exists || t.Phase != "ready" {
		return entry, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return entry, err
	}
	scope := entry.Inventory.Scope()
	planningActor := d.Principal()
	if t.Mode == deployment.DeliveryDown && entry.Down != nil {
		planningActor = entry.Down.Session.User
	}
	ctx, err := p.AppPlanning(s, planningActor, scope.Tenant)
	if err != nil {
		return entry, err
	}
	ctx.Project, ctx.Deployment, ctx.Actor = scope.App, scope.Deployment, d.Principal()
	if begin, err := appOriginBegin(entry.Origin, scope); err == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	actor := d.Principal()
	if t.Mode == deployment.DeliveryDown && entry.Down != nil {
		actor = entry.Down.Session.User
	}
	if t.Mode != deployment.DeliveryDown {
		if entry.PendingSync == nil || entry.PendingSync.verify(entry.Origin, scope) != nil {
			return entry, ErrCatalog
		}
		b, ok := d.TransitionPlan()
		if !ok || p.authorizeCDSelection(s, c, entry, b, nil, entry.PendingSync.Local) != nil {
			return entry, ErrCatalog
		}
		if at == 0 || at > math.MaxInt64 || p.checkCDGroupApprovals(s, c, entry, b, int64(at)) != nil {
			return entry, access.ErrDenied
		}
		if u := entry.PendingSync.User; u != nil {
			if c.AuthorizeAccepted(u.Session, p.Cluster, u.At, scope.Tenant, access.ManageCD, "") != nil {
				return entry, access.ErrDenied
			}
			for _, step := range b.Steps() {
				if c.AuthorizeAccepted(u.Session, p.Cluster, u.At, scope.Tenant, step.Action(), step.Node) != nil {
					return entry, access.ErrDenied
				}
			}
		}
	}
	n, err := d.ContinueTransition(d.Revision(), c, ctx, actor)
	if err != nil {
		return entry, err
	}
	entry.Delivery, entry.Inventory = &n, n.Inventory()
	if t.Mode != deployment.DeliveryDown {
		selected, ok := n.Selection()
		if !ok || selected.Intent != entry.PendingSync.Intent || selected.Artifact != entry.PendingSync.Artifact {
			return entry, ErrCatalog
		}
		proof := *entry.PendingSync
		proof.Plan = selected.Plan // only bases/readiness were rebased by the core
		entry.Sync, entry.PendingSync = &proof, nil
	}
	return entry, nil
}

func clearDeliveryInput(a Apps, entry appEntry) (Apps, appEntry) {
	if entry.DeliveryInput == nil || entry.Delivery == nil {
		return a, entry
	}
	input, scope, principal := entry.DeliveryInput, entry.Inventory.Scope(), entry.Delivery.Principal()
	a.uploads = slices.DeleteFunc(slices.Clone(a.uploads), func(u deployment.Upload) bool {
		return u.Tenant == scope.Tenant && u.App == scope.App && u.User == principal && u.ID == input.Upload
	})
	entry.DeliveryInput = nil
	return a, entry
}

func (p Policy) validateAppEntryDown(entry appEntry) error {
	if entry.Standalone != nil {
		return p.validateStandaloneDown(entry)
	}
	if entry.Delivery == nil {
		return p.validateAppDownTarget(entry.Inventory, entry.Origin, entry.Down, entry.downTarget(), "")
	}
	t, transition := entry.Delivery.Transition()
	if transition {
		if t.Mode == deployment.DeliveryDown {
			if entry.Down == nil || entry.PendingSync != nil {
				return ErrCatalog
			}
			return p.validateAppDownTarget(entry.Inventory, entry.Origin, entry.Down, entry.downTarget(), t.Retirement)
		}
		if entry.Down != nil || entry.PendingSync == nil || entry.PendingSync.verify(entry.Origin, entry.Inventory.Scope()) != nil || t.Selection.Operation != entry.PendingSync.Choice.Operation || t.Selection.Plan != entry.PendingSync.Plan || t.Selection.Epoch != entry.PendingSync.Epoch || t.Selection.Artifact != entry.PendingSync.Artifact || t.Selection.Intent != entry.PendingSync.Intent {
			return ErrCatalog
		}
		// A signed target-CAS choice names the original candidate. Admission
		// rechecks its intent before refreshing only the current plan bases.
		// The accepted Plan above binds that refreshed transition to its proof;
		// strict/legacy choices still require their exact original candidate.
		if t.Selection.Candidate != entry.PendingSync.Choice.Candidate && !entry.PendingSync.rebasesCandidate() {
			return ErrCatalog
		}
		return nil
	}
	if entry.PendingSync != nil {
		return ErrCatalog
	}
	return p.validateAppDownTarget(entry.Inventory, entry.Origin, entry.Down, entry.downTarget(), "")
}

func (p Policy) reduceUserCD(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q AppCDChange
	if canonical(op.Change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	key := appKey(q.Tenant, q.App)
	entry, exists := a.entries[key]
	if exists && entry.Delivery == nil && op.Change.Action == "configure-app-cd" {
		return p.attachUserCD(s, a, op, q, entry)
	}
	if !exists || entry.Delivery == nil {
		return nil, state.ConditionFailed
	}
	if q.Target != nil {
		if !AppCDTargetCASAllowed(op.Change) {
			return nil, state.Invalid
		}
		if op.Change.Expected > entry.Delivery.Revision() || *q.Target != appSyncTarget(entry) {
			return nil, state.ConditionFailed
		}
	} else if entry.Delivery.Revision() != op.Change.Expected {
		return nil, state.ConditionFailed
	}
	volumes, err := p.Volumes(s)
	if err != nil || volumes.appMovePending(q.Tenant, q.App) {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	d := *entry.Delivery
	scope := entry.Inventory.Scope()
	ctx, err := p.AppPlanning(s, op.Session.User, scope.Tenant)
	if err != nil {
		return nil, state.ConditionFailed
	}
	ctx.Project, ctx.Deployment, ctx.Actor = scope.App, scope.Deployment, d.Principal()
	if begin, err := appOriginBegin(entry.Origin, scope); err == nil {
		ctx.DefaultNode = begin.DefaultNode
	}
	switch op.Change.Action {
	case "sync-app", "recover-app":
		if q.Choice == nil || q.Policy != nil || q.PolicyRevision != 0 {
			return nil, state.Invalid
		}
		entry, err = p.acceptCDSync(s, entry, *q.Choice, &op, nil, op.Change.Action == "recover-app")
	case "replan-app":
		if q.Choice != nil || q.Policy != nil || q.PolicyRevision != 0 {
			return nil, state.Invalid
		}
		d, err = d.Reconsider(d.Revision(), c, ctx, op.Session.User)
		if err == nil {
			d, err = d.Replan(d.Revision(), c, ctx)
		}
		if err == nil {
			entry.Delivery = &d
			entry.CDDecision = nil
		}
	case "configure-app-cd":
		if q.Choice != nil || q.Policy == nil || q.PolicyRevision == 0 {
			return nil, state.Invalid
		}
		d, err = d.Configure(d.Revision(), q.PolicyRevision, c, ctx, op.Session.User, *q.Policy)
		if err == nil {
			if d.PolicyRevision() != entry.Delivery.PolicyRevision() {
				a, entry = clearDeliveryInput(a, entry)
			}
			entry.Delivery = &d
		}
	case "pause-app-cd", "resume-app-cd":
		if q.Choice != nil || q.Policy != nil || q.PolicyRevision != 0 {
			return nil, state.Invalid
		}
		entry, err = toggleCDEntry(s, entry, c, op.Session.User, op.Change.Action == "pause-app-cd")
	case "abandon-app-sync":
		if q.Choice != nil || q.Policy != nil || q.PolicyRevision != 0 {
			return nil, state.Invalid
		}
		t, exists := d.Transition()
		if !exists || t.Mode == deployment.DeliveryDown || entry.PendingSync == nil {
			return nil, state.ConditionFailed
		}
		// An explicit current operator may acknowledge already proven closure.
		// This does not send any remaining removal or replace its original ID.
		if t.Phase == "retiring" {
			for _, binding := range a.bindings.Live() {
				if binding.Needs().Use.Tenant == scope.Tenant && binding.Needs().Use.App == scope.App {
					return nil, state.ConditionFailed
				}
			}
			d, err = d.FinishRetirement(d.Revision(), c, op.Session.User)
			if err != nil {
				return nil, state.ConditionFailed
			}
		}
		d, err = d.AbandonTransition(d.Revision(), c, op.Session.User)
		if err == nil {
			d, err = d.Pause(d.Revision(), c, op.Session.User, true, s)
		}
		if err == nil {
			a, entry = clearDeliveryInput(a, entry)
			entry.Delivery, entry.Inventory, entry.PendingSync = &d, d.Inventory(), nil
		}
	default:
		return nil, state.Invalid
	}
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	a.entries[key] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}

// attachUserCD is the first 'cd set' of an app deployed without CD. The
// app's current execution becomes the running candidate; CAS is the app's
// inventory revision, as for any other change of the app itself.
func (p Policy) attachUserCD(s state.State, a Apps, op UserOperation, q AppCDChange, entry appEntry) (map[string][]byte, state.Code) {
	if q.Choice != nil || q.Policy == nil || q.PolicyRevision != 0 || q.Target != nil || entry.Standalone != nil || entry.Down != nil || entry.PendingSync != nil || op.Change.Expected != entry.Inventory.Revision() {
		return nil, state.ConditionFailed
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	d, err := deployment.AttachDelivery(entry.Inventory, c, op.Session.User, *q.Policy)
	if errors.Is(err, access.ErrDenied) {
		return nil, state.Forbidden
	}
	if err != nil {
		return nil, state.ConditionFailed
	}
	entry.Delivery = &d
	a.entries[appKey(q.Tenant, q.App)] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}
