// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/engine"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Restore reserves a NEW inactive target on the artifact owner. Cross-node
// transfer uses the separate authenticated streaming contract in D2.05/E4.
type VolumeRestoreBegin struct {
	Backup        VolumeBackupSelection
	ID            string
	Target        volumes.NativeSpec
	MaxBytes      uint64 // staging reservation, not an enforced filesystem quota
	CapacityBytes uint64 `json:",omitempty"`
}
type VolumeRestoreSelection struct {
	Backup VolumeBackupSelection
	ID     string
}
type VolumeRestorePermitRequest struct {
	Selection VolumeRestoreSelection
	Cleanup   bool
}
type VolumeRestoreBinding struct {
	Schema        uint8
	ID, Principal string
	Backup        VolumeBackupSelection
	BackupBinding [32]byte
	Receipt       volumes.ArchiveReceipt
	Compatibility [32]byte
	Target        volumes.NativeSpec
	Consumer      volumes.Consumer
	MaxBytes      uint64
	CapacityBytes uint64 `json:",omitempty"`
	Origin        UserOperation
}

func (b VolumeRestoreBinding) Digest() [32]byte { raw, _ := json.Marshal(b); return sha256.Sum256(raw) }

type VolumeRestore struct {
	Binding  VolumeRestoreBinding
	Revision uint64
	Phase    string               // Reserved, Cancelling, Restored (files only), Cancelled
	Staging  json.RawMessage      `json:",omitempty"`
	Report   *VolumeRestoreReport `json:",omitempty"`
}
type VolumeRestoreReport struct {
	Operation                                               string // restore, to separate node facts in the same namespace
	Schema                                                  uint8
	Selection                                               VolumeRestoreSelection
	Binding                                                 [32]byte
	Epoch, RootRevision, Revision                           uint64
	At                                                      int64
	Kind                                                    string               // restored or cancelled
	Target                                                  *volumes.NativeReady `json:",omitempty"`
	Closed                                                  volumes.Gone
	FilesSynced, CopyVerified, ArtifactReturned, TargetGone bool
	Signature                                               []byte
}

func VolumeRestoreReportBytes(r VolumeRestoreReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-volume-restore-report-1\x00"), raw...)
}
func restoreReportValue(raw []byte) bool {
	var tag struct{ Operation string }
	return json.Unmarshal(raw, &tag) == nil && tag.Operation == "restore"
}
func restoreKey(q VolumeRestoreSelection) string {
	return backupKey(q.Backup.Scope, q.Backup.ID) + "/" + q.ID
}
func restorePending(phase string) bool { return phase == "Reserved" || phase == "Cancelling" }
func restoreSelection(b VolumeRestoreBinding) VolumeRestoreSelection {
	return VolumeRestoreSelection{Backup: b.Backup, ID: b.ID}
}
func restoreTargetOwner(spec volumes.NativeSpec) (volumes.Owner, error) {
	if spec.Validate() != nil || spec.Kind != "" {
		return volumes.Owner{}, ErrCatalog
	}
	raw, _ := json.Marshal(spec)
	c := engine.Client{Owner: engine.Owner(spec.Scope.Cluster, spec.NodeKey)}
	id, err := c.Identity("volume", volumes.NativeKey(spec), reconcile.Resource{Present: true, Generation: 1, Spec: string(raw)})
	return volumes.Owner{Node: spec.Node, Key: spec.NodeKey, Native: id.Name}, err
}
func ownRestore(r VolumeRestore) VolumeRestore {
	raw, _ := json.Marshal(r)
	var out VolumeRestore
	_ = json.Unmarshal(raw, &out)
	return out
}
func (v Volumes) Restores() []VolumeRestore {
	keys := make([]string, 0, len(v.restores))
	for k := range v.restores {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]VolumeRestore, 0, len(keys))
	for _, k := range keys {
		out = append(out, ownRestore(v.restores[k]))
	}
	return out
}
func (v Volumes) Restore(q VolumeRestoreSelection) (VolumeRestore, bool) {
	r, ok := v.restores[restoreKey(q)]
	return ownRestore(r), ok
}
func (v Volumes) backupRestoring(q VolumeBackupSelection) bool {
	for _, r := range v.restores {
		if r.Binding.Backup == q && restorePending(r.Phase) {
			return true
		}
	}
	return false
}
func (v Volumes) restoreTargetAvailable(scope volumes.Scope) bool {
	if !v.creationTargetAvailable(scope) {
		return false
	}
	for _, r := range v.restores {
		if volumeKey(r.Binding.Target.Scope) == volumeKey(scope) {
			if restorePending(r.Phase) || scope.Generation <= r.Binding.Target.Scope.Generation {
				return false
			}
		}
	}
	return true
}

func (v Volumes) volumeReservations() int {
	count := 0
	for _, j := range v.moves {
		_, m, ok := v.Move(j.Selection())
		if !ok || movePending(m) {
			count++
		}
	}
	for _, e := range v.entries {
		if !e.State.Deleted() {
			count++
		}
	}
	for _, j := range v.creations {
		if creationPending(j.Phase) {
			count++
		}
	}
	for _, j := range v.restores {
		if restorePending(j.Phase) {
			count++
		}
	}
	return count
}
func restoreNeed(receipt volumes.ArchiveReceipt) uint64 {
	return receipt.DataBytes + uint64(receipt.Entries)*8192
}
func (v Volumes) restoreCharged(r VolumeRestore) bool {
	if r.Phase == "Cancelled" {
		return false
	}
	if e, ok := v.entries[volumeKey(r.Binding.Target.Scope)]; ok && r.Phase == "Restored" && e.State.Deleted() {
		return false
	}
	return true
}

func (v Volumes) restoreBudgetsOK() bool { return v.copyBudgetsOK() }

func validRestoreBinding(b VolumeRestoreBinding) bool {
	if b.Target.Kind != "" || b.Target.Scope.TenantManaged() || b.Backup.Scope.TenantManaged() {
		return false
	}
	owner, err := restoreTargetOwner(b.Target)
	if err != nil || b.Schema != 1 || !lifecycle.ValidID(b.ID) || len(b.ID) > 61 || !lifecycle.ValidID(b.Principal) || b.Target.Materialization != "r-"+b.ID || b.Target.Scope.Cluster != b.Backup.Scope.Cluster || b.Target.Scope.Tenant != b.Backup.Scope.Tenant || b.Target.Scope == b.Backup.Scope || b.BackupBinding == ([32]byte{}) || b.Compatibility == ([32]byte{}) || b.Receipt.Schema != 1 || b.MaxBytes < restoreNeed(b.Receipt) || b.MaxBytes > 1<<40 || b.CapacityBytes > 1<<40 || b.CapacityBytes != 0 && b.CapacityBytes < b.MaxBytes || b.Consumer != (volumes.Consumer{ID: "r-" + b.ID, Generation: 1, Writable: true, Owner: owner, OwnerRevision: 1, Lease: reconcile.Lease{Generation: b.Target.Scope.Generation, Token: 1}}) {
		return false
	}
	if b.Origin.VerifyOriginal(b.Target.Scope.Cluster) != nil || b.Origin.Change.Action != "begin-volume-restore" || b.Origin.Session.User != b.Principal {
		return false
	}
	var q VolumeRestoreBegin
	return canonical(b.Origin.Change.Payload, &q) == nil && q.Backup == b.Backup && q.ID == b.ID && q.Target == b.Target && q.MaxBytes == b.MaxBytes && q.CapacityBytes == b.CapacityBytes
}
func validRestoreReport(r VolumeRestoreReport, j VolumeRestore) bool {
	b := j.Binding
	if r.Operation != "restore" || r.Schema != 1 || r.Selection != restoreSelection(b) || r.Binding != b.Digest() || r.Epoch == 0 || r.Revision == 0 || r.At < 0 || !r.ArtifactReturned || r.Closed.Scope != b.Target.Scope || r.Closed.Consumer != b.Consumer || !r.Closed.Stopped || !r.Closed.MountsGone || !ed25519.Verify(b.Target.NodeKey[:], volumes.GoneBytes(r.Closed), r.Closed.Signature) || !ed25519.Verify(b.Target.NodeKey[:], VolumeRestoreReportBytes(r), r.Signature) {
		return false
	}
	if r.Kind == "cancelled" {
		return r.Target == nil && r.TargetGone && !r.FilesSynced && !r.CopyVerified
	}
	return r.Kind == "restored" && !r.TargetGone && r.FilesSynced && r.CopyVerified && r.Target != nil && r.Target.Verify() == nil && r.Target.Spec == b.Target && r.Target.Generation == 1 && r.Target.Owner == b.Consumer.Owner
}
func (p Policy) validateRestores(s state.State, c access.Catalog, v Volumes) error {
	if len(v.restores) > 256 || v.volumeReservations() > maxVolumes || !v.restoreBudgetsOK() {
		return ErrCatalog
	}
	for key, j := range v.restores {
		b := j.Binding
		if key != restoreKey(restoreSelection(b)) || !validRestoreBinding(b) {
			return ErrCatalog
		}
		backup, ok := v.Backup(b.Backup.Scope, b.Backup.ID)
		if !ok || backup.Binding.Digest() != b.BackupBinding || backup.Receipt == nil || *backup.Receipt != b.Receipt || backup.Binding.Compatibility != b.Compatibility || backup.Binding.Source.Owner.Node != b.Target.Node || backup.Binding.Source.Owner.Key != b.Target.NodeKey || b.Target.UID != backup.Binding.Source.Spec.UID || b.Target.GID != backup.Binding.Source.Spec.GID || b.Target.Mode != backup.Binding.Source.Spec.Mode {
			return ErrCatalog
		}
		switch j.Phase {
		case "Reserved", "Cancelling":
			if j.Revision != map[string]uint64{"Reserved": 1, "Cancelling": 2}[j.Phase] || j.Report != nil || backup.Phase != "Ready" {
				return ErrCatalog
			}
			if !p.acceptedIssuer(s, b.Origin.Session.Issuer) {
				return ErrCatalog
			}
			stage, err := volumes.Decode(j.Staging)
			if err != nil || stage.Revision() != 2 || stage.Scope() != b.Target.Scope || len(stage.Consumers()) != 1 || stage.Consumers()[0] != b.Consumer || stage.CheckActivation(b.Consumer) != nil {
				return ErrCatalog
			}
			if _, exists := v.entries[volumeKey(b.Target.Scope)]; exists {
				return ErrCatalog
			}
		case "Restored", "Cancelled":
			if j.Report == nil || !validRestoreReport(*j.Report, j) || j.Revision != j.Report.Revision+1 || len(j.Staging) != 0 {
				return ErrCatalog
			}
			if j.Phase == "Restored" {
				if j.Revision != 2 || j.Report.Revision != 1 {
					return ErrCatalog
				}
				entry, ok := v.entries[volumeKey(b.Target.Scope)]
				if j.Report.Kind != "restored" || !ok || (entry.Native.Spec != b.Target || !sameVolumeNative(entry.Native, *j.Report.Target)) && !movedFrom(entry.State, j.Report.Target.Owner) || slices.Contains(entry.State.Consumers(), b.Consumer) {
					return ErrCatalog
				}
			} else if j.Revision != 3 || j.Report.Kind != "cancelled" || j.Report.Revision != 2 {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
		for otherKey, other := range v.restores {
			if key < otherKey && restorePending(j.Phase) && restorePending(other.Phase) && (b.Backup == other.Binding.Backup || volumeKey(b.Target.Scope) == volumeKey(other.Binding.Target.Scope)) {
				return ErrCatalog
			}
		}
	}
	return nil
}
func (p Policy) reduceRestoreChange(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	change := op.Change
	if change.Action == "cancel-volume-restore" {
		var q VolumeRestoreSelection
		if canonical(change.Payload, &q) != nil {
			return nil, state.Invalid
		}
		j, ok := v.restores[restoreKey(q)]
		if !ok || j.Phase != "Reserved" || j.Revision != change.Expected {
			return nil, state.ConditionFailed
		}
		j.Phase, j.Revision = "Cancelling", 2
		v.restores[restoreKey(q)] = j
		return p.volumeCheckpoint(s, v)
	}
	var q VolumeRestoreBegin
	if change.Action != "begin-volume-restore" || canonical(change.Payload, &q) != nil || !lifecycle.ValidID(q.ID) || len(q.ID) > 61 || q.Target.Validate() != nil || q.Target.Scope.Cluster != p.Cluster || q.Target.Scope.Tenant != q.Backup.Scope.Tenant || q.Target.Scope == q.Backup.Scope || q.Target.Materialization != "r-"+q.ID || q.MaxBytes > 1<<40 || len(v.restores) >= 256 {
		return nil, state.Invalid
	}
	if q.Target.Kind != "" || q.Target.Scope.TenantManaged() || q.Backup.Scope.TenantManaged() {
		return nil, state.ConditionFailed
	}
	selection := VolumeRestoreSelection{Backup: q.Backup, ID: q.ID}
	if _, ok := v.restores[restoreKey(selection)]; ok {
		return nil, state.ConditionFailed
	}
	backup, ok := v.Backup(q.Backup.Scope, q.Backup.ID)
	if !ok || backup.Phase != "Ready" || backup.Revision != change.Expected || backup.Receipt == nil || v.backupRestoring(q.Backup) || !v.restoreTargetAvailable(q.Target.Scope) {
		return nil, state.ConditionFailed
	}
	if _, ok := v.entries[volumeKey(q.Target.Scope)]; ok {
		return nil, state.ConditionFailed
	}
	if v.volumeReservations() >= maxVolumes || v.volumeMetadataSlots() >= maxVolumes {
		return nil, state.ConditionFailed
	}
	if s.Object(deployment.ResourceKey("volume", q.Target.Scope.Tenant, q.Target.Scope.App, q.Target.Scope.ID)).Present {
		return nil, state.ConditionFailed
	}
	if q.Target.Node != backup.Binding.Source.Owner.Node || q.Target.NodeKey != backup.Binding.Source.Owner.Key || q.Target.UID != backup.Binding.Source.Spec.UID || q.Target.GID != backup.Binding.Source.Spec.GID || q.Target.Mode != backup.Binding.Source.Spec.Mode || q.MaxBytes < restoreNeed(*backup.Receipt) {
		return nil, state.ConditionFailed
	}
	key, err := p.workNodeOwner(s, q.Target.Node)
	if err != nil || key != q.Target.NodeKey || c.Authorize(change.Principal, q.Target.Scope.Tenant, access.ManageVolumes, q.Target.Node) != nil {
		return nil, state.Forbidden
	}
	if !v.admitOriginal(q.Target.Scope.Tenant, q.Target.Node, q.Target.NodeKey, q.CapacityBytes) || q.CapacityBytes != 0 && q.CapacityBytes < q.MaxBytes {
		return nil, state.ConditionFailed
	}
	owner, err := restoreTargetOwner(q.Target)
	if err != nil {
		return nil, state.Invalid
	}
	stage, err := volumes.New(c, change.Principal, q.Target.Scope, owner, 256)
	if err != nil {
		return nil, state.Forbidden
	}
	stage, consumer, err := stage.Acquire(c, change.Principal, stage.Revision(), "r-"+q.ID, 1, true)
	if err != nil {
		return nil, state.ConditionFailed
	}
	raw, err := stage.Encode()
	if err != nil {
		return nil, state.Invalid
	}
	b := VolumeRestoreBinding{Schema: 1, ID: q.ID, Principal: change.Principal, Backup: q.Backup, BackupBinding: backup.Binding.Digest(), Receipt: *backup.Receipt, Compatibility: backup.Binding.Compatibility, Target: q.Target, Consumer: consumer, MaxBytes: q.MaxBytes, CapacityBytes: q.CapacityBytes, Origin: op}
	v.restores[restoreKey(selection)] = VolumeRestore{Binding: b, Revision: 1, Phase: "Reserved", Staging: raw}
	if !v.restoreBudgetsOK() {
		return nil, state.ConditionFailed
	}
	return p.volumeCheckpoint(s, v)
}
func (p Policy) restoreReport(s state.State, cmd state.Command) (VolumeRestoreReport, error) {
	var r VolumeRestoreReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	j, ok := v.Restore(r.Selection)
	digest := sha256.Sum256([]byte(cmd.Value))
	wantID := "vr-" + hex.EncodeToString(digest[:])
	if cmd.Kind == state.ModuleReport {
		wantID = state.ReportRequestID(cmd)
	}
	if !ok || !validRestoreReport(r, j) || cmd.Actor != "node/"+hex.EncodeToString(j.Binding.Target.NodeKey[:]) || cmd.RequestID != wantID {
		return r, access.ErrDenied
	}
	key, err := p.nodeOwner(s, j.Binding.Target.Node)
	if err != nil || !p.ownsResource(s, key, j.Binding.Target.NodeKey) {
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) ResolveVolumeRestoreReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeRestoreReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	v, e := p.Volumes(s)
	if e != nil {
		return state.Command{}, e
	}
	j, ok := v.Restore(r.Selection)
	if !ok || !p.ownsResource(s, caller, j.Binding.Target.NodeKey) {
		return state.Command{}, access.ErrDenied
	}
	caller = j.Binding.Target.NodeKey
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(caller[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.restoreReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceRestoreReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.restoreReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	j := v.restores[restoreKey(r.Selection)]
	if !restorePending(j.Phase) || j.Revision != r.Revision || r.Kind == "cancelled" && j.Phase != "Cancelling" {
		return nil, state.ConditionFailed
	}
	stage, err := volumes.Decode(j.Staging)
	if err != nil {
		return nil, state.Invalid
	}
	stage, err = stage.Release(r.Closed)
	if err != nil {
		return nil, state.ConditionFailed
	}
	if r.Kind == "restored" {
		if j.Phase == "Cancelling" {
			return nil, state.ConditionFailed
		} // cancellation keeps the unpublished target
		if _, exists := v.entries[volumeKey(j.Binding.Target.Scope)]; exists || len(v.entries) >= maxVolumes {
			return nil, state.ConditionFailed
		}
		v.entries[volumeKey(j.Binding.Target.Scope)] = registeredVolume{Native: *r.Target, State: stage, CapacityBytes: j.Binding.CapacityBytes}
		j.Phase = "Restored"
	} else {
		j.Phase = "Cancelled"
	}
	j.Revision++
	j.Staging = nil
	j.Report = &r
	v.restores[restoreKey(r.Selection)] = j
	return p.volumeCheckpoint(s, v)
}
func (p Policy) VolumeRestorePermit(s state.State, caller [32]byte, q VolumeRestoreSelection, cleanup bool) (VolumeRestore, error) {
	current, err := p.Current(s)
	if err != nil {
		return VolumeRestore{}, err
	}
	p = current
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeRestore{}, err
	}
	j, ok := v.Restore(q)
	if !ok || !p.ownsResource(s, caller, j.Binding.Target.NodeKey) {
		return j, access.ErrDenied
	}
	key, err := p.nodeOwner(s, j.Binding.Target.Node)
	if err != nil || key != caller {
		return j, access.ErrDenied
	}
	if cleanup {
		if j.Phase != "Cancelling" {
			return j, access.ErrDenied
		}
		return j, nil
	}
	if j.Phase != "Reserved" {
		return j, access.ErrDenied
	}
	if current, err := p.workNodeOwner(s, j.Binding.Target.Node); err != nil || current != caller {
		return j, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeAccepted(j.Binding.Origin.Session, p.Cluster, j.Binding.Origin.At, j.Binding.Target.Scope.Tenant, access.ManageVolumes, j.Binding.Target.Node) != nil {
		return j, access.ErrDenied
	}
	return j, nil
}

// isRestoreAction deliberately excludes the backup actions sharing this root.
func isRestoreAction(action string) bool { return strings.HasSuffix(action, "-volume-restore") }

type VolumeRestoreView struct {
	Key                                   string
	Backup                                VolumeBackupSelection
	ID, Node, Phase                       string
	Target                                volumes.Scope
	Revision, MaxBytes                    uint64
	CapacityBytes                         uint64 `json:",omitempty"`
	Binding, BackupBinding, Compatibility [32]byte
}

func (v Volumes) RestorePage(c access.Catalog, actor, tenant, after string) ([]VolumeRestoreView, string, error) {
	if tenant == "" {
		if !c.SystemAllowed(actor) {
			return nil, "", access.ErrDenied
		}
	} else if c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	var page []VolumeRestoreView
	for _, job := range v.Restores() {
		b := job.Binding
		key := restoreKey(restoreSelection(b))
		if tenant != "" && b.Target.Scope.Tenant != tenant || key <= after {
			continue
		}
		if len(page) == 8 {
			return page, page[len(page)-1].Key, nil
		}
		page = append(page, VolumeRestoreView{Key: key, Backup: b.Backup, ID: b.ID, Node: b.Target.Node, Phase: job.Phase, Target: b.Target.Scope, Revision: job.Revision, MaxBytes: b.MaxBytes, CapacityBytes: b.CapacityBytes, Binding: b.Digest(), BackupBinding: b.BackupBinding, Compatibility: b.Compatibility})
	}
	return page, "", nil
}
