// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// AppMovePlanRequest selects a read-only proposal. It cannot change ownership.
// The target node and operating policy come from the single app declaration.
type AppMovePlanRequest struct {
	Volume, ID      string
	MaxBytes        uint64
	MaxEntries      uint32
	TransferSeconds uint32
}

// VolumeMoveRecipe is a current owner's public journal observation. In
// particular it is neither a clean-exit receipt nor permission to stop/start.
type VolumeMoveRecipe struct {
	Schema                       uint8
	NativeBinding, Compatibility [32]byte
	Consumer                     volumes.Consumer
}

// AppMovePlan carries the exact explicit operation separately from the desired
// app artifact. It uses the same bounded authenticated plan stream.
type AppMovePlan struct {
	Schema           uint8
	Expected, Epoch  uint64
	Begin            VolumeMoveBegin
	Artifact         json.RawMessage
	StoragePreflight *MoveStoragePreflight `json:",omitempty"`
}

func DecodeAppMovePlan(raw []byte) (AppMovePlan, error) {
	var p AppMovePlan
	if len(raw) > deployment.ArtifactMaxBytes || canonical(raw, &p) != nil || p.Schema != 1 || p.Expected == 0 || p.Epoch == 0 || p.Begin.App == nil || p.Begin.App.Target == nil || p.Begin.App.Target.Upload != p.Begin.ID || p.Begin.App.Target.Operation != p.Begin.ID || p.Begin.Target.Validate() != nil || p.Begin.Scope != p.Begin.Target.Scope || !lifecycle.ValidID(p.Begin.ID) || len(p.Begin.ID) > 61 || p.Begin.Target.Materialization != "m-"+p.Begin.ID || p.Begin.MaxBytes < 1024 || p.Begin.MaxBytes > 1<<40 || p.Begin.MaxEntries == 0 || p.Begin.MaxEntries > 100000 || p.Begin.CapacityBytes < p.Begin.MaxBytes || p.Begin.CapacityBytes > 1<<40 || p.Begin.OwnerRevision == 0 || p.Begin.Compatibility == ([32]byte{}) || p.Begin.ExpiresAt <= 0 {
		return AppMovePlan{}, ErrCatalog
	}
	b, err := deployment.DecodeBlueprint(p.Artifact)
	if err != nil || b.Digest() != p.Begin.App.Target.Plan || b.Scope().Cluster != p.Begin.Scope.Cluster || b.Scope().Tenant != p.Begin.Scope.Tenant || b.Scope().App != p.Begin.Scope.App || p.Begin.App.Operation == p.Begin.ID || p.Begin.App.Operation == "" || p.Begin.App.Plan == ([32]byte{}) || p.Begin.App.Revision == 0 {
		return AppMovePlan{}, ErrCatalog
	}
	if source := p.Begin.App.CD; source != nil && (!source.Valid() || source.Principal != b.Scope().Actor || source.Intent != b.IntentDigest() || source.Input != b.AppInputDigest()) {
		return AppMovePlan{}, ErrCatalog
	}
	if p.StoragePreflight != nil && (!p.StoragePreflight.valid() || p.StoragePreflight.Node != p.Begin.Target.Node || p.StoragePreflight.RequiredBytes != p.Begin.CapacityBytes) {
		return AppMovePlan{}, ErrCatalog
	}
	return p, nil
}

func (p Policy) AppMovePlanSource(s state.State, session access.Session, at int64, tenant string, r AppPlanRequest) (volumes.NativeReady, error) {
	policy, err := p.Current(s)
	if err != nil {
		return volumes.NativeReady{}, err
	}
	p = policy
	if r.PrepareSources || r.SourceProvider != nil || r.SourceEnvelope {
		return volumes.NativeReady{}, ErrCatalog
	}
	if r.Move == nil || !lifecycle.ValidID(r.Project) || !lifecycle.ValidID(r.Move.Volume) || !lifecycle.ValidID(r.Move.ID) || len(r.Move.ID) > 61 || r.Move.MaxBytes < 1024 || r.Move.MaxBytes > 1<<40 || r.Move.MaxEntries == 0 || r.Move.MaxEntries > 100000 || r.Move.TransferSeconds == 0 || r.Move.TransferSeconds > 86400 || r.Diff || r.Part != 0 || r.Digest != ([32]byte{}) {
		return volumes.NativeReady{}, ErrCatalog
	}
	ready, err := p.VolumeNative(s, session, at, tenant, VolumeSelector{App: r.Project, ID: r.Move.Volume})
	if err != nil {
		return ready, err
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageVolumes, ready.Owner.Node) != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Deploy, ready.Owner.Node) != nil {
		return volumes.NativeReady{}, access.ErrDenied
	}
	return ready, nil
}

func (p Policy) AppMovePlanArtifact(s state.State, session access.Session, at int64, tenant string, r AppPlanRequest, witness VolumeMoveRecipe) ([]byte, error) {
	policy, err := p.Current(s)
	if err != nil {
		return nil, err
	}
	p = policy
	ready, err := p.AppMovePlanSource(s, session, at, tenant, r)
	if err != nil {
		return nil, err
	}
	if witness.Schema != 1 || witness.NativeBinding != VolumeNativeDigest(ready) || witness.Compatibility == ([32]byte{}) || !witness.Consumer.Writable || witness.Consumer.Owner != ready.Owner {
		return nil, access.ErrConflict
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, err
	}
	current, _ := v.Volume(ready.Spec.Scope)
	found := false
	for _, consumer := range current.Consumers() {
		if consumer == witness.Consumer {
			found = true
		}
	}
	owner, ownerRevision := current.Owner()
	if !found || witness.Consumer.OwnerRevision != ownerRevision || owner != ready.Owner {
		return nil, access.ErrConflict
	}
	input, err := deployment.ParseApp(r.Document)
	if err != nil {
		return nil, err
	}
	decl, ok := input.Volumes[r.Move.Volume]
	if !ok {
		return nil, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, err
	}
	a, err := p.Apps(s)
	if err != nil {
		return nil, err
	}
	entry, exists := a.entries[appKey(tenant, r.Project)]
	if !exists {
		return nil, ErrCatalog
	}
	ctx, err := p.AppPlanning(s, session.User, tenant)
	if err != nil {
		return nil, err
	}
	ctx.Project, ctx.Deployment, ctx.DefaultNode, ctx.ExternalNetworks = r.Project, r.Deployment, r.Node, r.External
	if entry.Delivery != nil {
		if entry.PendingSync != nil || entry.Down != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageCD, "") != nil || c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, tenant, access.ManageCD, "") != nil {
			return nil, access.ErrDenied
		}
		ctx.Actor = entry.Delivery.Principal()
		if ctx.Deployment == "" {
			ctx.Deployment = entry.Inventory.Scope().Deployment
		}
		if begin, err := appOriginBegin(entry.Origin, entry.Inventory.Scope()); err == nil {
			ctx.DefaultNode = begin.DefaultNode
		}
	}
	node := decl.Sfc.Node
	if node == "" {
		node = r.Node
	}
	key, err := p.nodeOwner(s, node)
	if err != nil || node == ready.Owner.Node || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.ManageVolumes, node) != nil {
		return nil, access.ErrDenied
	}
	target := ready.Spec
	target.Node = node
	target.NodeKey = key
	target.Materialization = "m-" + r.Move.ID
	targetOwner, err := restoreTargetOwner(target)
	if err != nil {
		return nil, err
	}
	placement := deployment.VolumeMovePlacement{Scope: ready.Spec.Scope, Source: ready.Owner, SourceOwnerRevision: ownerRevision, Target: targetOwner}
	var plan deployment.Blueprint
	if entry.Delivery != nil {
		plan, err = entry.Delivery.PlanMovedDocument(r.Document, c, ctx, placement)
	} else {
		plan, err = deployment.CompileAppDocumentVolumeMove(r.Document, c, ctx, placement)
	}
	if err != nil {
		return nil, err
	}
	for _, step := range plan.Steps() {
		if c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, step.Action(), step.Node) != nil {
			return nil, access.ErrDenied
		}
		if entry.Delivery != nil && c.AuthorizeAccepted(entry.Origin.Session, p.Cluster, entry.Origin.At, tenant, step.Action(), step.Node) != nil {
			return nil, access.ErrDenied
		}
	}
	inventory, ok := a.Inventory(tenant, r.Project)
	if !ok {
		return nil, ErrCatalog
	}
	active, ok := inventory.Active()
	if !ok || active.Status != "Succeeded" || active.ID == r.Move.ID {
		return nil, ErrCatalog
	}
	if _, busy := inventory.Retirement(); busy {
		return nil, access.ErrConflict
	}
	if _, used := inventory.Operation(r.Move.ID); used {
		return nil, access.ErrConflict
	}
	capacity := uint64(decl.Sfc.Capacity)
	if capacity == 0 {
		capacity = v.entries[volumeKey(ready.Spec.Scope)].CapacityBytes
	}
	if capacity < r.Move.MaxBytes || capacity < v.entries[volumeKey(ready.Spec.Scope)].CapacityBytes {
		return nil, ErrCatalog
	}
	// begin-volume-move admits the target reservation with only a result
	// code; check it here so the plan names the missing server limit.
	if code := v.originalAdmissionCode(s, tenant, node, key, capacity); code != "" {
		return nil, &deployment.InputError{Code: code, Path: "volumes." + r.Move.Volume}
	}
	// The copy also holds the source backup and target staging budgets.
	if code := v.copyBudgetFailure(&moveCharge{tenant: tenant, source: ready.Owner.Node, target: node, sourceKey: ready.Owner.Key, targetKey: key, bytes: r.Move.MaxBytes}); code != "" {
		return nil, &deployment.InputError{Code: code, Path: "volumes." + r.Move.Volume}
	}
	artifact, err := plan.Encode()
	if err != nil {
		return nil, err
	}
	q := VolumeMoveBegin{Scope: ready.Spec.Scope, ID: r.Move.ID, OwnerRevision: ownerRevision, Target: target, Compatibility: witness.Compatibility, MaxBytes: r.Move.MaxBytes, MaxEntries: r.Move.MaxEntries, CapacityBytes: capacity, ExpiresAt: at + int64(r.Move.TransferSeconds), App: &VolumeMoveApp{Operation: active.ID, Plan: active.Plan, Revision: inventory.Revision(), Target: &VolumeMoveTargetApp{Upload: r.Move.ID, Operation: r.Move.ID, Plan: sha256.Sum256(artifact)}}}
	if entry.Delivery != nil {
		q.App.CD = &AppCDMoveSource{Registration: appRegistrationDigest(entry.Origin), Principal: entry.Delivery.Principal(), Requester: entry.Origin.Session.Key, PolicyRevision: entry.Delivery.PolicyRevision(), OverrideRevision: entry.Delivery.OverrideRevision(), Intent: plan.IntentDigest(), Input: plan.AppInputDigest()}
	}
	raw, err := json.Marshal(AppMovePlan{Schema: 1, Expected: current.Revision(), Epoch: s.ModuleEpoch(), Begin: q, Artifact: artifact})
	if err != nil {
		return nil, err
	}
	if _, err = DecodeAppMovePlan(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
