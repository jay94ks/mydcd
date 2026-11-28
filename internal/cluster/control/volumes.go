// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const VolumesKey = "control/volumes"
const maxVolumes = 256

type VolumeAcquire struct {
	Scope      volumes.Scope
	Consumer   string
	Generation uint64
	Writable   bool
}
type volumeGrant struct {
	Consumer  volumes.Consumer
	Principal string
}
type registeredVolume struct {
	Native          volumes.NativeReady
	State           volumes.State
	Grants          []volumeGrant
	DeleteIntent    *UserOperation           `json:",omitempty"`
	RetainedDeletes map[string]UserOperation `json:",omitempty"`
	CapacityBytes   uint64                   `json:",omitempty"`
}
type volumeRow struct {
	Native          volumes.NativeReady
	State           json.RawMessage
	Grants          []volumeGrant
	DeleteIntent    *UserOperation           `json:",omitempty"`
	RetainedDeletes map[string]UserOperation `json:",omitempty"`
	CapacityBytes   uint64                   `json:",omitempty"`
}
type volumeCheckpoint struct {
	Files        []VolumeFileJob `json:",omitempty"`
	Schema       uint8
	Cluster      [32]byte
	Revision     uint64
	Entries      []volumeRow
	BackupLimits []VolumeBackupLimit `json:",omitempty"`
	Backups      []VolumeBackup      `json:",omitempty"`
	Restores     []VolumeRestore     `json:",omitempty"`
	Creations    []VolumeCreation    `json:",omitempty"`
	Moves        []VolumeMove        `json:",omitempty"`
	Archives     []VolumeArchive     `json:",omitempty"`
	ArchiveKeys  *VolumeArchiveKeys  `json:",omitempty"`
}
type Volumes struct {
	files        map[string]VolumeFileJob
	Revision     uint64
	entries      map[string]registeredVolume
	backupLimits map[string]VolumeBackupLimit
	backups      map[string]VolumeBackup
	restores     map[string]VolumeRestore
	creations    map[string]VolumeCreation
	moves        map[string]VolumeMove
	archives     map[string]VolumeArchive
	archiveKeys  VolumeArchiveKeys
}

func volumeKey(s volumes.Scope) string { return s.Key() }
func (v Volumes) Volume(scope volumes.Scope) (volumes.State, bool) {
	e, ok := v.entries[volumeKey(scope)]
	return e.State, ok && e.State.Scope() == scope
}
func (p Policy) Volumes(s state.State) (Volumes, error) {
	raw, revision, err := readCheckpoint(s, VolumesKey, p.Cluster, p.TrustRoot)
	if err != nil {
		return Volumes{}, err
	}
	v := Volumes{files: map[string]VolumeFileJob{}, entries: map[string]registeredVolume{}, backupLimits: map[string]VolumeBackupLimit{}, backups: map[string]VolumeBackup{}, restores: map[string]VolumeRestore{}, creations: map[string]VolumeCreation{}, moves: map[string]VolumeMove{}, archives: map[string]VolumeArchive{}}
	if raw == nil {
		return v, v.validateOriginalStorage(s)
	}
	var disk volumeCheckpoint
	if canonical(raw, &disk) != nil || disk.Schema != 1 || disk.Cluster != p.Cluster || disk.Revision != revision || revision == 0 || len(disk.Entries) > maxVolumes || len(disk.Moves) > maxVolumes {
		return v, ErrCatalog
	}
	c, err := p.Catalog(s)
	if err != nil {
		return v, err
	}
	last := ""
	for _, row := range disk.Entries {
		core, err := volumes.Decode(row.State)
		if err != nil || row.Native.Verify() != nil || core.Scope() != row.Native.Spec.Scope || core.Scope().Cluster != p.Cluster {
			return v, ErrCatalog
		}
		owner, _ := core.Owner()
		if owner != row.Native.Owner {
			return v, ErrCatalog
		}
		key := volumeKey(core.Scope())
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		_, ok := c.Tenant(core.Scope().Tenant)
		if !ok {
			return v, ErrCatalog
		}
		consumers := core.Consumers()
		if len(row.Grants) != len(consumers) {
			return v, ErrCatalog
		}
		for i, g := range row.Grants {
			if g.Consumer != consumers[i] {
				return v, ErrCatalog
			}
			if _, ok := c.User(g.Principal); !ok {
				return v, ErrCatalog
			}
		}
		v.entries[key] = registeredVolume{Native: row.Native, State: core, Grants: slices.Clone(row.Grants), DeleteIntent: row.DeleteIntent, RetainedDeletes: row.RetainedDeletes, CapacityBytes: row.CapacityBytes}
	}

	last = ""
	for _, row := range disk.Moves {
		key := moveKey(row.Selection())
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.moves[key] = row
	}
	last = ""
	for _, row := range disk.BackupLimits {
		key := backupLimitKey(row.Tenant, row.Node)
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.backupLimits[key] = row
	}
	last = ""
	for _, row := range disk.Backups {
		key := backupKey(row.Binding.Scope, row.Binding.ID)
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.backups[key] = row
	}
	if p.validateBackups(s, c, v) != nil {
		return v, ErrCatalog
	}
	last = ""
	for _, row := range disk.Restores {
		key := restoreKey(restoreSelection(row.Binding))
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.restores[key] = row
	}
	last = ""
	for _, row := range disk.Creations {
		key := creationKey(row.Spec.Scope)
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.creations[key] = row
	}
	if p.validateCreations(s, c, v) != nil {
		return v, ErrCatalog
	}
	if p.validateRestores(s, c, v) != nil {
		return v, ErrCatalog
	}

	if p.validateMoves(v) != nil || !v.copyBudgetsOK() {
		return v, ErrCatalog
	}
	if p.validateVolumeDeletions(v) != nil || v.validateOriginalStorage(s) != nil {
		return v, ErrCatalog
	}
	last = ""
	for _, row := range disk.Archives {
		key := backupKey(row.Binding.Scope, row.Binding.ID)
		if key <= last {
			return v, ErrCatalog
		}
		last = key
		v.archives[key] = row
	}
	if disk.ArchiveKeys != nil {
		if disk.ArchiveKeys.Revision == 0 {
			return v, ErrCatalog
		}
		v.archiveKeys = *disk.ArchiveKeys
	}
	if p.validateArchives(v) != nil {
		return v, ErrCatalog
	}
	last = ""
	for _, j := range disk.Files {
		if j.ID <= last || !validVolumeFileJob(j, p.Cluster) {
			return v, ErrCatalog
		}
		last = j.ID
		v.files[j.ID] = j
		entry, ok := v.entries[volumeKey(j.Request.Scope)]
		if !ok {
			return v, ErrCatalog
		}
		if j.Phase == "Reserved" && !slices.Contains(entry.State.Consumers(), j.Consumer) {
			return v, ErrCatalog
		}
	}
	v.Revision = revision
	return v, nil
}
func (p Policy) volumeCheckpoint(s state.State, v Volumes) (map[string][]byte, state.Code) {
	if p.validateVolumeDeletions(v) != nil {
		return nil, state.ConditionFailed
	}
	if v.validateOriginalStorage(s) != nil || p.validateMoves(v) != nil || !v.copyBudgetsOK() || p.validateArchives(v) != nil {
		return nil, state.ConditionFailed
	}
	if v.Revision == ^uint64(0) || v.volumeReservations() > maxVolumes || v.volumeMetadataSlots() > maxVolumes {
		return nil, state.Invalid
	}
	disk := volumeCheckpoint{Schema: 1, Cluster: p.Cluster, Revision: v.Revision + 1}
	keys := make([]string, 0, len(v.entries))
	for k := range v.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, key := range keys {
		e := v.entries[key]
		raw, err := e.State.Encode()
		if err != nil {
			return nil, state.Invalid
		}
		disk.Entries = append(disk.Entries, volumeRow{Native: e.Native, State: raw, Grants: e.Grants, DeleteIntent: e.DeleteIntent, RetainedDeletes: e.RetainedDeletes, CapacityBytes: e.CapacityBytes})
	}
	disk.BackupLimits = v.BackupLimits()
	disk.Backups = v.Backups()
	disk.Restores = v.Restores()
	disk.Creations = v.Creations()
	disk.Moves = v.Moves()
	disk.Files = v.VolumeFiles()
	disk.Archives = v.Archives()
	if v.archiveKeys.Revision != 0 {
		keys := v.archiveKeys
		disk.ArchiveKeys = &keys
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		return nil, state.Invalid
	}
	return writeCheckpoint(s, VolumesKey, p.Cluster, p.TrustRoot, disk.Revision, raw)
}
func (p Policy) authorizeVolume(c access.Catalog, op UserOperation) error {
	var scope volumes.Scope
	node := ""
	cleanup := false
	if isVolumeFileAction(op.Change.Action) {
		return p.authorizeVolumeFile(c, op)
	}
	switch op.Change.Action {
	case "register-fixed-volume":
		var q VolumeFixedRegister
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, node = q.Scope, q.Node
	case "commit-volume-move":
		var q VolumeMoveCommit
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, node = q.Selection.Scope, q.Target.Spec.Node
	case "begin-volume-move":
		var q VolumeMoveBegin
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, node = q.Scope, q.Target.Node
	case "cancel-volume-move":
		var q VolumeMoveSelection
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, cleanup = q.Scope, true
	case "begin-volume-create":
		var q VolumeCreate
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, node = q.Scope, q.Node
	case "cancel-volume-create":
		if canonical(op.Change.Payload, &scope) != nil {
			return access.ErrInvalid
		}
		cleanup = true
	case "delete-volume", "unregister-fixed-volume":
		if canonical(op.Change.Payload, &scope) != nil {
			return access.ErrInvalid
		}
		cleanup = true
	case "delete-retained-volume":
		var q VolumeMoveSelection
		if canonical(op.Change.Payload, &q) != nil {
			return access.ErrInvalid
		}
		scope, cleanup = q.Scope, true
	case "begin-volume-restore":
		var r VolumeRestoreBegin
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope, node = r.Target.Scope, r.Target.Node
	case "cancel-volume-restore":
		var r VolumeRestoreSelection
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope, cleanup = r.Backup.Scope, true
	case "set-volume-capacity", "set-volume-backup-limit":
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	case "set-volume-archive-admin-key":
		return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, "", access.ManageCluster, "")
	case "archive-volume":
		var r VolumeArchiveBegin
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope = r.Scope
	case "unarchive-volume", "cancel-volume-archive", "discard-volume-archive":
		var r VolumeArchiveSelection
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope, cleanup = r.Scope, op.Change.Action != "unarchive-volume"
	case "begin-volume-backup":
		var r VolumeBackupBegin
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope = r.Scope
	case "cancel-volume-backup", "delete-volume-backup":
		var r VolumeBackupSelection
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope = r.Scope
		cleanup = true
	case "create-volume":
		var r volumes.NativeReady
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope, node = r.Spec.Scope, r.Spec.Node
	case "acquire-volume":
		var r VolumeAcquire
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope = r.Scope
	case "release-volume":
		var r volumes.Gone
		if canonical(op.Change.Payload, &r) != nil {
			return access.ErrInvalid
		}
		scope, cleanup = r.Scope, true
	default:
		return access.ErrInvalid
	}
	if scope.Cluster != p.Cluster {
		return access.ErrDenied
	}
	if cleanup {
		return c.AuthorizeSessionCleanup(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, scope.Tenant, access.ManageVolumes)
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, scope.Tenant, access.ManageVolumes, node)
}
func (p Policy) reduceVolumes(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	if (cmd.Kind != state.Module && cmd.Kind != state.ModuleReport) || cmd.Key != VolumesKey {
		return nil, state.Forbidden
	}
	if strings.HasPrefix(cmd.Actor, "node/") {
		if cmd.Kind != state.ModuleReport {
			return nil, state.Forbidden
		}
		if volumeFileReportValue([]byte(cmd.Value)) {
			return p.reduceVolumeFileReport(s, cmd)
		}
		if volumeMoveReportValue([]byte(cmd.Value)) {
			return p.reduceVolumeMoveReport(s, cmd)
		}
		if volumeCreateReportValue([]byte(cmd.Value)) {
			return p.reduceVolumeCreateReport(s, cmd)
		}
		if volumeDeleteReportValue([]byte(cmd.Value)) {
			return p.reduceVolumeDeleteReport(s, cmd)
		}
		if volumeRemoteFenceReportValue([]byte(cmd.Value)) {
			return p.reduceVolumeRemoteFenceReport(s, cmd)
		}
		if restoreReportValue([]byte(cmd.Value)) {
			return p.reduceRestoreReport(s, cmd)
		}
		if volumeArchiveReportValue([]byte(cmd.Value)) {
			return p.reduceArchiveReport(s, cmd)
		}
		if volumeArchiveKeyReportValue([]byte(cmd.Value)) {
			return p.reduceArchiveKeyReport(s, cmd)
		}
		return p.reduceBackupReport(s, cmd)
	}
	if cmd.Kind != state.Module || !strings.HasPrefix(cmd.Actor, "user/") {
		return nil, state.Forbidden
	}
	p, err := p.Current(s)
	if err != nil {
		return nil, state.Invalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return nil, state.Invalid
	}
	op, err := p.Operation(c, cmd, false)
	if err != nil || p.authorizeVolume(c, op) != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	if op.Change.Action == "begin-volume-create" || op.Change.Action == "register-fixed-volume" || op.Change.Action == "cancel-volume-create" {
		return p.reduceVolumeCreate(s, c, v, op)
	}
	change := op.Change
	if isVolumeFileAction(change.Action) {
		return p.reduceVolumeFile(s, c, v, op)
	}
	if isMoveAction(change.Action) {
		return p.reduceVolumeMove(s, c, v, op)
	}
	if change.Action == "set-volume-capacity" {
		return p.reduceVolumeCapacity(s, v, op)
	}
	if change.Action == "delete-volume" || change.Action == "unregister-fixed-volume" {
		return p.reduceVolumeDelete(s, c, v, op)
	}
	if change.Action == "delete-retained-volume" {
		return p.reduceRetainedVolumeDelete(s, c, v, op)
	}
	if isRestoreAction(change.Action) {
		return p.reduceRestoreChange(s, c, v, op)
	}
	if isArchiveAction(change.Action) {
		return p.reduceArchiveChange(s, c, v, op)
	}
	if strings.Contains(change.Action, "volume-backup") {
		return p.reduceBackupChange(s, c, v, op)
	}
	if change.Action == "create-volume" {
		var ready volumes.NativeReady
		if canonical(change.Payload, &ready) != nil || ready.Verify() != nil {
			return nil, state.Invalid
		}
		key := volumeKey(ready.Spec.Scope)
		if !v.restoreTargetAvailable(ready.Spec.Scope) {
			return nil, state.ConditionFailed
		}
		if _, exists := v.entries[key]; exists || change.Expected != 0 || v.volumeReservations() >= maxVolumes || v.volumeMetadataSlots() >= maxVolumes {
			return nil, state.ConditionFailed
		}
		node, err := p.workNodeOwner(s, ready.Spec.Node)
		if err != nil || node != ready.Spec.NodeKey {
			return nil, state.Forbidden
		}
		core, err := volumes.New(c, change.Principal, ready.Spec.Scope, ready.Owner, 256)
		if err != nil {
			return nil, state.Forbidden
		}
		if !v.admitOriginal(ready.Spec.Scope.Tenant, ready.Spec.Node, ready.Spec.NodeKey, 0) {
			return nil, state.ConditionFailed
		}
		v.entries[key] = registeredVolume{Native: ready, State: core}
		return p.volumeCheckpoint(s, v)
	}
	var scope volumes.Scope
	var acquire VolumeAcquire
	var gone volumes.Gone
	switch change.Action {
	case "acquire-volume":
		if canonical(change.Payload, &acquire) != nil {
			return nil, state.Invalid
		}
		scope = acquire.Scope
	case "release-volume":
		if canonical(change.Payload, &gone) != nil {
			return nil, state.Invalid
		}
		scope = gone.Scope
	default:
		return nil, state.Invalid
	}
	key := volumeKey(scope)
	entry, ok := v.entries[key]
	if !ok || entry.State.Scope() != scope || entry.State.Revision() != change.Expected {
		return nil, state.ConditionFailed
	}
	if v.Archived(scope) {
		return nil, state.ConditionFailed
	}
	if change.Action == "acquire-volume" {
		if err := p.canUseFixedVolume(s, c, change.Principal, entry); err != nil {
			return nil, state.Forbidden
		}
		owner, _ := entry.State.Owner()
		key, err := p.workNodeOwner(s, owner.Node)
		if err != nil || !p.ownsResource(s, key, owner.Key) || c.Authorize(change.Principal, scope.Tenant, access.ManageVolumes, owner.Node) != nil {
			return nil, state.Forbidden
		}
		var consumer volumes.Consumer
		entry.State, consumer, err = entry.State.Acquire(c, change.Principal, change.Expected, acquire.Consumer, acquire.Generation, acquire.Writable)
		if err != nil {
			return nil, state.ConditionFailed
		}
		found := false
		for _, g := range entry.Grants {
			if g.Consumer == consumer {
				if g.Principal != change.Principal {
					return nil, state.Forbidden
				}
				found = true
			}
		}
		if !found {
			entry.Grants = append(entry.Grants, volumeGrant{consumer, change.Principal})
		}
	} else {
		// A remote consumer's Gone is signed by its runner: trust the runner
		// key only as the membership's current resource key of that node.
		if gone.Consumer.Remote() {
			key, ok := gone.Consumer.GoneKey()
			if !ok || !p.resourceNodeOwner(s, gone.Consumer.Runner, key, false) {
				return nil, state.Forbidden
			}
		}
		entry.State, err = entry.State.Release(gone)
		if err != nil {
			return nil, state.ConditionFailed
		}
		entry.Grants = slices.DeleteFunc(entry.Grants, func(g volumeGrant) bool { return g.Consumer == gone.Consumer })
	}
	v.entries[key] = entry
	return p.volumeCheckpoint(s, v)
}

// VolumePermit consumes only a fresh authenticated member read supplied by the
// Engine adapter. The pure function cannot itself establish a quorum barrier.
func (p Policy) VolumePermit(s state.State, caller [32]byte, r volumes.StartRequest) (volumes.Permit, error) {
	v, err := p.Volumes(s)
	if err != nil {
		return volumes.Permit{}, err
	}
	e, ok := v.entries[volumeKey(r.Scope)]
	if !ok || e.State.Scope() != r.Scope {
		return volumes.Permit{}, access.ErrDenied
	}
	owner, _ := e.State.Owner()
	current, err := p.nodeOwner(s, owner.Node)
	if err != nil || !p.ownsResource(s, current, owner.Key) {
		return volumes.Permit{}, access.ErrDenied
	}
	if r.Consumer.Remote() {
		// A remote consumer's start is asked by its runner, under the exact
		// share record (control/volume-shares).
		if !p.remoteRunner(s, caller, r.Scope, r.Consumer) {
			return volumes.Permit{}, access.ErrDenied
		}
	} else if !p.ownsResource(s, caller, owner.Key) {
		return volumes.Permit{}, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil {
		return volumes.Permit{}, err
	}
	for _, g := range e.Grants {
		if g.Consumer == r.Consumer {
			if err := p.canUseFixedVolume(s, c, g.Principal, e); err != nil {
				return volumes.Permit{}, err
			}
			return e.State.PermitStart(c, g.Principal, r)
		}
	}
	return volumes.Permit{}, access.ErrDenied
}

type VolumeRetainedSourceView struct {
	Move, Node, State string
}

type VolumeView struct {
	Retained                []VolumeRetainedSourceView `json:",omitempty"`
	Kind                    string                     `json:",omitempty"`
	Storage                 string                     `json:",omitempty"`
	RootGeneration          uint64                     `json:",omitempty"`
	RetainedSources         int                        `json:",omitempty"`
	RetainedPending         int                        `json:",omitempty"`
	RetainedRemoved         int                        `json:",omitempty"`
	Key                     string
	Scope                   volumes.Scope
	Owner                   volumes.Owner
	Revision, OwnerRevision uint64
	Consumers               int
	CapacityBytes           uint64   `json:",omitempty"`
	NativeBinding           [32]byte `json:",omitempty"`
	Retain                  bool
	Phase                   string        `json:",omitempty"`
	CreateRevision          uint64        `json:",omitempty"`
	MoveID, TargetNode      string        `json:",omitempty"`
	MovePhase               volumes.Phase `json:",omitempty"`
	MoveExpiresAt           int64         `json:",omitempty"` // the move plan's end; a move not yet copying cannot continue after it
	// ArchiveID and ArchivePhase name the archive that holds the Volume
	// (Phase "Archived" from Packing until Restored, Cancelled, Failed or
	// Discarded).
	ArchiveID    string `json:",omitempty"`
	ArchivePhase string `json:",omitempty"`
	// UsedBytes: allocated bytes of the owner's last bounded scan
	// (observability.VolumeUsage, not Raft state); nil = unknown (no fresh
	// scan, too large to scan, or the owner is not reporting).
	// UsageObservedAt is that scan's Unix millisecond time.
	UsedBytes       *uint64 `json:",omitempty"`
	UsageObservedAt uint64  `json:",omitempty"`
}

func (v Volumes) Page(c access.Catalog, actor, tenant, after string) ([]VolumeView, string, error) {
	if tenant == "" {
		if !c.SystemAllowed(actor) {
			return nil, "", access.ErrDenied
		}
	} else if c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	views := map[string]VolumeView{}
	for key, e := range v.entries {
		owner, revision := e.State.Owner()
		phase := "Ready"
		if e.State.Deleting() {
			phase = "Deleting"
		} else if e.State.Deleted() {
			phase = "Deleted"
		}
		view := VolumeView{Key: key, Scope: e.State.Scope(), Owner: owner, Revision: e.State.Revision(), OwnerRevision: revision, Consumers: len(e.State.Consumers()), CapacityBytes: e.CapacityBytes, NativeBinding: VolumeNativeDigest(e.Native), Retain: e.State.RetainsData(), Phase: phase}
		if e.Native.Fixed != nil {
			view.Kind, view.Storage, view.RootGeneration = "node-fixed", e.Native.Fixed.Root.Root.ID, e.Native.Fixed.Root.Root.Generation
		}
		view.RetainedSources = len(e.State.Retained())
		for _, m := range e.State.Moves() {
			if m.Phase == volumes.Completed {
				status := "retained"
				if m.SourceDeletion != nil {
					status = "deleting"
					if m.SourceDeletion.Gone != nil {
						status = "removed"
					}
				}
				view.Retained = append(view.Retained, VolumeRetainedSourceView{Move: m.Binding.ID, Node: m.Binding.Source.Node, State: status})
			}
			if m.SourceDeletion != nil {
				if m.SourceDeletion.Gone == nil {
					view.RetainedPending++
				} else {
					view.RetainedRemoved++
				}
			}
			if movePending(m) {
				view.Phase = "Moving"
				view.MoveID = m.Binding.ID
				view.MovePhase = m.Phase
				view.TargetNode = m.Binding.Target.Node
				if j, _, ok := v.Move(VolumeMoveSelection{Scope: e.State.Scope(), ID: m.Binding.ID}); ok {
					view.MoveExpiresAt = j.ExpiresAt
				}
			}
		}
		if j, ok := v.activeArchive(key); ok {
			view.Phase, view.ArchiveID, view.ArchivePhase = "Archived", j.Binding.ID, j.Phase
		}
		views[key] = view
	}
	for _, j := range v.creations {
		key := volumeKey(j.Spec.Scope)
		if old, exists := views[key]; exists && old.Scope.Generation >= j.Spec.Scope.Generation || j.Phase == "Ready" {
			continue
		}
		bytes, _ := creationBytes(j)
		views[key] = VolumeView{Key: key, Scope: j.Spec.Scope, CapacityBytes: bytes, Owner: volumes.Owner{Node: j.Spec.Node, Key: j.Spec.NodeKey}, Revision: j.Revision, CreateRevision: j.Revision, Phase: j.Phase, Retain: creationPending(j.Phase)}
		if j.Fixed != nil {
			view := views[key]
			view.Kind, view.Storage, view.RootGeneration = "node-fixed", j.Fixed.Root.Root.ID, j.Fixed.Root.Root.Generation
			views[key] = view
		}
	}
	keys := make([]string, 0, len(views))
	for key := range views {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	var page []VolumeView
	for _, key := range keys {
		view := views[key]
		if tenant != "" && view.Scope.Tenant != tenant || key <= after {
			continue
		}
		if len(page) == 8 {
			return page, page[len(page)-1].Key, nil
		}
		page = append(page, view)
	}
	return page, "", nil
}

// volumesBook is the VolumesKey book (books.go).
var volumesBook = Book{Key: VolumesKey, Reduce: byKind(map[state.CommandKind]reducer{state.Module: Policy.reduceVolumes, state.ModuleReport: Policy.reduceVolumes})}
