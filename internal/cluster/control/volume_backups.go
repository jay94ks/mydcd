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
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

const maxVolumeBackups = 256

// Backup budgets are logical reservations, not an enforced filesystem quota.
// An absent global or tenant-node limit denies new backup admission.
type VolumeBackupLimit struct {
	Tenant, Node string
	Owner        [32]byte
	Revision     uint64
	Bytes        uint64
	Count        uint32
	StagingBytes uint64               `json:",omitempty"`
	StagingCount uint32               `json:",omitempty"`
	Original     *OriginalVolumeLimit `json:",omitempty"`
}
type VolumeBackupBegin struct {
	Scope         volumes.Scope
	ID            string
	MaxBytes      uint64
	MaxEntries    uint32
	Compatibility [32]byte
}
type VolumeBackupPermitRequest struct {
	Selection VolumeBackupSelection
	Cleanup   bool
}
type VolumeBackupSelection struct {
	Scope volumes.Scope
	ID    string
}
type VolumeBackupBinding struct {
	Schema        uint8
	Scope         volumes.Scope
	ID, Principal string
	Source        volumes.NativeReady
	Consumer      volumes.Consumer
	MaxBytes      uint64
	MaxEntries    uint32
	Compatibility [32]byte
	Origin        UserOperation
}

func (b VolumeBackupBinding) Digest() [32]byte { raw, _ := json.Marshal(b); return sha256.Sum256(raw) }
func (b VolumeBackupBinding) Options() volumes.ArchiveOptions {
	return volumes.ArchiveOptions{MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, MaxDepth: 64, UID: b.Source.Spec.UID, GID: b.Source.Spec.GID, RootMode: b.Source.Spec.Mode}
}

type VolumeBackup struct {
	Revision   uint64
	Phase      string
	Binding    VolumeBackupBinding
	Receipt    *volumes.ArchiveReceipt `json:",omitempty"`
	Report     *VolumeBackupReport     `json:",omitempty"`
	Completion *VolumeBackupReport     `json:",omitempty"`
}

// Reports are original owner facts. Only a real producer may assert a clean
// compatible source, directory sync and FD/native closure. Tests that sign
// fixtures prove FSM binding, never the underlying native/SQL facts.
type VolumeBackupReport struct {
	Schema                                                   uint8
	Scope                                                    volumes.Scope
	ID                                                       string
	Epoch, RootRevision, Revision                            uint64
	At                                                       int64
	Binding                                                  [32]byte
	Kind                                                     string // ready, failed, gone
	Receipt                                                  volumes.ArchiveReceipt
	Closed                                                   *volumes.Gone `json:",omitempty"`
	DirectorySynced, CleanShutdown, Compatible, ArtifactGone bool
	Failure                                                  string `json:",omitempty"`
	Signature                                                []byte
}

func VolumeBackupReportBytes(r VolumeBackupReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-volume-backup-report-1\x00"), raw...)
}
func backupKey(s volumes.Scope, id string) string { return volumeKey(s) + "/" + id }
func backupLimitKey(tenant, node string) string   { return tenant + "/" + node }
func backupPending(phase string) bool             { return phase == "Reserved" || phase == "Cancelling" }
func backupCharged(j VolumeBackup) (uint64, uint32) {
	switch j.Phase {
	case "Reserved", "Cancelling":
		return j.Binding.MaxBytes, 1
	case "Ready", "Deleting":
		return j.Receipt.Bytes, 1
	}
	return 0, 0
}
func ownBackup(j VolumeBackup) VolumeBackup {
	j.Binding.Source.Signature = slices.Clone(j.Binding.Source.Signature)
	raw, _ := json.Marshal(j.Binding.Origin)
	var origin UserOperation
	_ = json.Unmarshal(raw, &origin)
	j.Binding.Origin = origin
	if j.Receipt != nil {
		x := *j.Receipt
		j.Receipt = &x
	}
	if j.Completion != nil {
		x := *j.Completion
		x.Signature = slices.Clone(x.Signature)
		if x.Closed != nil {
			g := *x.Closed
			g.Signature = slices.Clone(g.Signature)
			x.Closed = &g
		}
		j.Completion = &x
	}
	if j.Report != nil {
		x := *j.Report
		x.Signature = slices.Clone(x.Signature)
		if x.Closed != nil {
			g := *x.Closed
			g.Signature = slices.Clone(g.Signature)
			x.Closed = &g
		}
		j.Report = &x
	}
	return j
}
func (v Volumes) Backup(scope volumes.Scope, id string) (VolumeBackup, bool) {
	j, ok := v.backups[backupKey(scope, id)]
	return ownBackup(j), ok && j.Binding.Scope == scope
}
func (v Volumes) BackupLimits() []VolumeBackupLimit {
	var out []VolumeBackupLimit
	for _, b := range v.backupLimits {
		if b.Original != nil {
			own := *b.Original
			b.Original = &own
		}
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b VolumeBackupLimit) int {
		return strings.Compare(backupLimitKey(a.Tenant, a.Node), backupLimitKey(b.Tenant, b.Node))
	})
	return out
}
func (v Volumes) Backups() []VolumeBackup {
	keys := make([]string, 0, len(v.backups))
	for k := range v.backups {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]VolumeBackup, 0, len(keys))
	for _, k := range keys {
		out = append(out, ownBackup(v.backups[k]))
	}
	return out
}
func (v Volumes) backupBudgetsOK() bool { return v.copyBudgetsOK() }

func validBackupBinding(b VolumeBackupBinding) bool {
	if b.Schema != 1 || b.Source.Verify() != nil || b.Source.Spec.Scope != b.Scope || !lifecycle.ValidID(b.ID) || len(b.ID) > 61 || !lifecycle.ValidID(b.Principal) || b.MaxBytes < 1024 || b.MaxBytes > 1<<40 || b.MaxEntries == 0 || b.MaxEntries > 100_000 || b.Compatibility == ([32]byte{}) || b.Consumer.ID != "b-"+b.ID || b.Consumer.Generation != 1 || b.Consumer.Writable || b.Consumer.Owner != b.Source.Owner || b.Consumer.OwnerRevision == 0 || b.Consumer.Lease.Generation != b.Scope.Generation || b.Consumer.Lease.Token == 0 {
		return false
	}
	if b.Origin.VerifyOriginal(b.Scope.Cluster) != nil || b.Origin.Change.Action != "begin-volume-backup" || b.Origin.Session.User != b.Principal {
		return false
	}
	var requested VolumeBackupBegin
	if canonical(b.Origin.Change.Payload, &requested) != nil || requested.Scope != b.Scope || requested.ID != b.ID || requested.MaxBytes != b.MaxBytes || requested.MaxEntries != b.MaxEntries || requested.Compatibility != b.Compatibility {
		return false
	}
	return true
}
func validBackupReport(r VolumeBackupReport, j VolumeBackup) bool {
	if r.Schema != 1 || r.Scope != j.Binding.Scope || r.ID != j.Binding.ID || r.Epoch == 0 || r.Revision == 0 || r.Binding != j.Binding.Digest() || r.At < 0 || !ed25519.Verify(ed25519.PublicKey(j.Binding.Source.Owner.Key[:]), VolumeBackupReportBytes(r), r.Signature) {
		return false
	}
	switch r.Kind {
	case "ready":
		if !r.DirectorySynced || !r.CleanShutdown || !r.Compatible || r.ArtifactGone || r.Failure != "" || r.Receipt.Validate(j.Binding.Options()) != nil {
			return false
		}
	case "failed":
		if !r.DirectorySynced || !r.ArtifactGone || r.Receipt != (volumes.ArchiveReceipt{}) || !lifecycle.ValidID(r.Failure) {
			return false
		}
	case "gone":
		return r.DirectorySynced && r.ArtifactGone && r.Closed == nil && r.Receipt == (volumes.ArchiveReceipt{}) && r.Failure == ""
	default:
		return false
	}
	return r.Closed != nil && r.Closed.Scope == j.Binding.Scope && r.Closed.Consumer == j.Binding.Consumer && r.Closed.Stopped && r.Closed.MountsGone && ed25519.Verify(ed25519.PublicKey(j.Binding.Source.Owner.Key[:]), volumes.GoneBytes(*r.Closed), r.Closed.Signature)
}
func (p Policy) validateBackups(s state.State, c access.Catalog, v Volumes) error {
	if len(v.backupLimits) > 4096 || len(v.backups) > maxVolumeBackups {
		return ErrCatalog
	}
	for key, b := range v.backupLimits {
		if key != backupLimitKey(b.Tenant, b.Node) || !lifecycle.ValidID(b.Node) || b.Owner == ([32]byte{}) || b.Revision == 0 || b.Bytes > 1<<50 || b.Count > maxVolumeBackups || b.StagingBytes > 1<<50 || b.StagingCount > 256 {
			return ErrCatalog
		}
		if b.Tenant != "" {
			_, ok := c.Tenant(b.Tenant)
			if !ok {
				return ErrCatalog
			}
		}
	}
	for key, j := range v.backups {
		b := j.Binding
		e, ok := v.entries[volumeKey(b.Scope)]
		if key != backupKey(b.Scope, b.ID) || j.Revision == 0 || !validBackupBinding(b) || !ok || e.State.Scope() != b.Scope {
			return ErrCatalog
		}
		if _, ok := c.User(b.Principal); !ok {
			return ErrCatalog
		}

		revisions := map[string]uint64{"Reserved": 1, "Cancelling": 2, "Ready": 2, "Failed": 2, "Deleting": 3, "Deleted": 4, "Cancelled": 3}
		if revisions[j.Phase] != j.Revision {
			return ErrCatalog
		}
		if j.Report != nil && j.Report.Revision >= j.Revision {
			return ErrCatalog
		}
		if j.Completion != nil && (j.Completion.Revision < 1 || j.Completion.Revision > 2) {
			return ErrCatalog
		}
		switch j.Phase {
		case "Reserved", "Cancelling":
			if !p.acceptedIssuer(s, b.Origin.Session.Issuer) {
				return ErrCatalog
			}
			if j.Receipt != nil || j.Report != nil || j.Completion != nil || !sameVolumeNative(e.Native, b.Source) || !slices.Contains(e.State.Consumers(), b.Consumer) || e.State.CheckActivation(b.Consumer) != nil {
				return ErrCatalog
			}
		case "Ready", "Deleting", "Deleted":
			if j.Receipt == nil || j.Report == nil || j.Completion == nil || j.Completion.Kind != "ready" || !validBackupReport(*j.Completion, j) || j.Completion.Receipt != *j.Receipt || !validBackupReport(*j.Report, j) || j.Receipt.Validate(b.Options()) != nil {
				return ErrCatalog
			}
			if j.Phase == "Deleted" {
				if j.Report.Kind != "gone" || j.Report.Revision != 3 {
					return ErrCatalog
				}
			} else if j.Report.Kind != "ready" || j.Report.Receipt != *j.Receipt {
				return ErrCatalog
			}
			if slices.Contains(e.State.Consumers(), b.Consumer) {
				return ErrCatalog
			}
		case "Failed", "Cancelled":
			if j.Completion == nil || j.Completion.Revision != j.Revision-1 {
				return ErrCatalog
			}
			if j.Receipt != nil || j.Report == nil || j.Completion == nil || j.Completion.Kind != "failed" || !validBackupReport(*j.Completion, j) || j.Report.Kind != "failed" || !validBackupReport(*j.Report, j) || slices.Contains(e.State.Consumers(), b.Consumer) {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
	}
	if !v.backupBudgetsOK() {
		return ErrCatalog
	}
	return nil
}

func (p Policy) reduceBackupChange(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	change := op.Change
	if change.Action == "set-volume-backup-limit" {
		var limit VolumeBackupLimit
		if canonical(change.Payload, &limit) != nil || !lifecycle.ValidID(limit.Node) || limit.Tenant != "" && !lifecycle.ValidID(limit.Tenant) || limit.Bytes > 1<<50 || limit.Count > maxVolumeBackups || limit.StagingBytes > 1<<50 || limit.StagingCount > 256 || limit.Revision != 0 || limit.Owner != ([32]byte{}) {
			return nil, state.Invalid
		}
		if limit.Tenant != "" {
			if _, ok := c.Tenant(limit.Tenant); !ok {
				return nil, state.ConditionFailed
			}
		}
		owner, err := p.nodeOwner(s, limit.Node)
		if err != nil {
			return nil, state.Forbidden
		}
		key := backupLimitKey(limit.Tenant, limit.Node)
		old := v.backupLimits[key]
		if old.Revision != change.Expected || old.Revision == ^uint64(0) {
			return nil, state.ConditionFailed
		}
		if old.Original != nil && limit.Original == nil {
			return nil, state.ConditionFailed
		}
		limit.Revision, limit.Owner = old.Revision+1, owner
		v.backupLimits[key] = limit
		if !v.backupBudgetsOK() || !v.restoreBudgetsOK() {
			return nil, state.ConditionFailed
		}
		return p.volumeCheckpoint(s, v)
	}
	if change.Action == "begin-volume-backup" {
		var request VolumeBackupBegin
		if canonical(change.Payload, &request) != nil || !lifecycle.ValidID(request.ID) || len(request.ID) > 61 || request.MaxBytes < 1024 || request.MaxBytes > 1<<40 || request.MaxEntries == 0 || request.MaxEntries > 100_000 || request.Compatibility == ([32]byte{}) {
			return nil, state.Invalid
		}
		e, ok := v.entries[volumeKey(request.Scope)]
		if !ok || e.State.Scope() != request.Scope || e.State.Revision() != change.Expected || len(v.backups) >= maxVolumeBackups {
			return nil, state.ConditionFailed
		}
		key := backupKey(request.Scope, request.ID)
		if _, ok := v.backups[key]; ok {
			return nil, state.ConditionFailed
		}
		owner, err := p.workNodeOwner(s, e.Native.Spec.Node)
		if err != nil || !p.ownsResource(s, owner, e.Native.Owner.Key) {
			return nil, state.Forbidden
		}
		// Reserve the original shared reader with the same existing Volume core.
		consumerID := "b-" + request.ID
		for _, held := range e.State.Consumers() {
			if held.ID == consumerID {
				return nil, state.ConditionFailed
			}
		}
		next, consumer, err := e.State.AcquireCold(c, change.Principal, change.Expected, consumerID, 1)
		if err != nil {
			return nil, state.ConditionFailed
		}
		binding := VolumeBackupBinding{Schema: 1, Scope: request.Scope, ID: request.ID, Principal: change.Principal, Source: e.Native, Consumer: consumer, MaxBytes: request.MaxBytes, MaxEntries: request.MaxEntries, Compatibility: request.Compatibility, Origin: op}
		if !validBackupBinding(binding) {
			return nil, state.ConditionFailed
		}
		v.backups[key] = VolumeBackup{Revision: 1, Phase: "Reserved", Binding: binding}
		if !v.backupBudgetsOK() {
			return nil, state.ConditionFailed
		}
		e.State = next
		e.Grants = append(e.Grants, volumeGrant{Consumer: consumer, Principal: change.Principal})
		v.entries[volumeKey(request.Scope)] = e
		return p.volumeCheckpoint(s, v)
	}
	var request VolumeBackupSelection
	if canonical(change.Payload, &request) != nil {
		return nil, state.Invalid
	}
	key := backupKey(request.Scope, request.ID)
	job, ok := v.backups[key]
	if !ok || job.Binding.Scope != request.Scope || job.Revision != change.Expected || job.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	switch change.Action {
	case "cancel-volume-backup":
		if job.Phase != "Reserved" {
			return nil, state.ConditionFailed
		}
		job.Phase = "Cancelling"
	case "delete-volume-backup":
		if v.backupRestoring(request) {
			return nil, state.ConditionFailed
		}
		if job.Phase != "Ready" {
			return nil, state.ConditionFailed
		}
		job.Phase = "Deleting"
	default:
		return nil, state.Invalid
	}
	job.Revision++
	v.backups[key] = job
	return p.volumeCheckpoint(s, v)
}

func (p Policy) backupReport(s state.State, cmd state.Command) (VolumeBackupReport, error) {
	var r VolumeBackupReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	job, ok := v.Backup(r.Scope, r.ID)
	digest := sha256.Sum256([]byte(cmd.Value))
	wantID := "vb-" + hex.EncodeToString(digest[:])
	if cmd.Kind == state.ModuleReport {
		wantID = state.ReportRequestID(cmd)
	}
	if !ok || !validBackupReport(r, job) || cmd.Actor != "node/"+hex.EncodeToString(job.Binding.Source.Owner.Key[:]) || cmd.RequestID != wantID {
		return r, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, job.Binding.Source.Owner.Node)
	if err != nil || !p.ownsResource(s, owner, job.Binding.Source.Owner.Key) {
		return r, access.ErrDenied
	}
	return r, nil
}
func (p Policy) ResolveVolumeBackupReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeBackupReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	v, e := p.Volumes(s)
	if e != nil {
		return state.Command{}, e
	}
	job, ok := v.Backup(r.Scope, r.ID)
	if !ok || !p.ownsResource(s, caller, job.Binding.Source.Owner.Key) {
		return state.Command{}, access.ErrDenied
	}
	caller = job.Binding.Source.Owner.Key
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(caller[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.backupReport(s, cmd)
	return cmd, err
}
func (p Policy) reduceBackupReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.backupReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := backupKey(r.Scope, r.ID)
	j := v.backups[key]
	if j.Revision != r.Revision || j.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	if r.Kind == "gone" {
		if j.Phase != "Deleting" {
			return nil, state.ConditionFailed
		}
		j.Phase = "Deleted"
	} else {
		if !backupPending(j.Phase) {
			return nil, state.ConditionFailed
		}
		e := v.entries[volumeKey(r.Scope)]
		e.State, err = e.State.Release(*r.Closed)
		if err != nil {
			return nil, state.ConditionFailed
		}
		e.Grants = slices.DeleteFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == j.Binding.Consumer })
		v.entries[volumeKey(r.Scope)] = e
		completion := r
		j.Completion = &completion
		if r.Kind == "ready" {
			receipt := r.Receipt
			j.Receipt = &receipt
			if j.Phase == "Cancelling" {
				j.Phase = "Deleting"
			} else {
				j.Phase = "Ready"
			}
		} else {
			if j.Phase == "Cancelling" {
				j.Phase = "Cancelled"
			} else {
				j.Phase = "Failed"
			}
		}
	}
	j.Revision++
	j.Report = &r
	v.backups[key] = j
	return p.volumeCheckpoint(s, v)
}

// BackupPermit returns the exact immutable accepted binding after a fresh
// adapter quorum read. Cancelling/Deleting permit only cleanup, independently
// of revoked deployment rights, never new copy or artifact publication.
func (p Policy) VolumeBackupPermit(s state.State, caller [32]byte, selection VolumeBackupSelection, cleanup bool) (VolumeBackup, error) {
	current, err := p.Current(s)
	if err != nil {
		return VolumeBackup{}, err
	}
	p = current
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeBackup{}, err
	}
	job, ok := v.Backup(selection.Scope, selection.ID)
	if !ok || !p.ownsResource(s, caller, job.Binding.Source.Owner.Key) {
		return job, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, job.Binding.Source.Owner.Node)
	if err != nil || owner != caller {
		return job, access.ErrDenied
	}
	if cleanup {
		if job.Phase != "Cancelling" && job.Phase != "Deleting" {
			return job, access.ErrDenied
		}
		return job, nil
	}
	if job.Phase != "Reserved" {
		return job, access.ErrDenied
	}
	if current, err := p.workNodeOwner(s, job.Binding.Source.Owner.Node); err != nil || current != caller {
		return job, access.ErrDenied
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeAccepted(job.Binding.Origin.Session, p.Cluster, job.Binding.Origin.At, job.Binding.Scope.Tenant, access.ManageVolumes, job.Binding.Source.Owner.Node) != nil {
		return job, access.ErrDenied
	}
	entry := v.entries[volumeKey(job.Binding.Scope)]
	if !sameVolumeNative(entry.Native, job.Binding.Source) || entry.State.CheckActivation(job.Binding.Consumer) != nil {
		return job, access.ErrDenied
	}
	return job, nil
}

func (v Volumes) Quiescent() bool {
	for _, j := range v.moves {
		_, m, ok := v.Move(j.Selection())
		if !ok || movePending(m) || m.SourceDeletion != nil && m.SourceDeletion.Gone == nil {
			return false
		}
	}
	for _, j := range v.creations {
		if creationPending(j.Phase) {
			return false
		}
	}
	for _, j := range v.restores {
		if restorePending(j.Phase) {
			return false
		}
	}
	for key, e := range v.entries {
		consumers := e.State.Consumers()
		// A settled archive holds its Volume for as long as it is kept.
		if j, ok := v.activeArchive(key); ok && j.Phase == "Archived" {
			consumers = slices.DeleteFunc(consumers, func(c volumes.Consumer) bool { return c == j.Binding.Consumer })
		}
		if len(consumers) != 0 || e.State.Deleting() {
			return false
		}
	}
	for _, j := range v.backups {
		if backupPending(j.Phase) || j.Phase == "Deleting" {
			return false
		}
	}
	return true
}

// VolumeBackupView exposes metadata only, never the accepted session, signed
// user envelope, artifact path or file contents.
type VolumeBackupView struct {
	Key                    string
	Scope                  volumes.Scope
	ID, Node, Phase        string
	Revision, MaxBytes     uint64
	MaxEntries             uint32
	Binding, Compatibility [32]byte
	Receipt                *volumes.ArchiveReceipt `json:",omitempty"`
	Failure                string                  `json:",omitempty"`
	Owner                  [32]byte
	UID, GID, Mode         uint32
}

func (v Volumes) BackupPage(c access.Catalog, actor, tenant, after string) ([]VolumeBackupView, string, error) {
	if tenant == "" {
		if !c.SystemAllowed(actor) {
			return nil, "", access.ErrDenied
		}
	} else if c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	var page []VolumeBackupView
	for _, job := range v.Backups() {
		b := job.Binding
		key := backupKey(b.Scope, b.ID)
		if tenant != "" && b.Scope.Tenant != tenant || key <= after {
			continue
		}
		if len(page) == 8 {
			return page, page[len(page)-1].Key, nil
		}
		row := VolumeBackupView{Key: key, Scope: b.Scope, ID: b.ID, Node: b.Source.Owner.Node, Phase: job.Phase, Revision: job.Revision, MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, Binding: b.Digest(), Compatibility: b.Compatibility, Receipt: job.Receipt, Owner: b.Source.Owner.Key, UID: b.Source.Spec.UID, GID: b.Source.Spec.GID, Mode: b.Source.Spec.Mode}
		if job.Report != nil {
			row.Failure = job.Report.Failure
		}
		page = append(page, row)
	}
	return page, "", nil
}
