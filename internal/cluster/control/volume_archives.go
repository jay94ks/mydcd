// SPDX-License-Identifier: Apache-2.0

package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// Volume archives (devel/proposals/volume-archive-packages.md): a taken-down
// app's Volume is packed into one sealed file on a storage root of its owner
// node, its native is emptied but kept, and a writable consumer "a-<id>"
// holds it so nothing mounts it until it is restored or discarded. Keeping
// the native keeps its owner and generation, so the app's next deploy reuses
// it as before.
//
//	Packing ─packed→ Clearing ─cleared→ Archived ─unarchive→ Restoring ─restored→ Restored
//	   │ cancel                            │ discard            └─unrestored→ Archived
//	   ↓                                   ↓
//	Cancelling ─cancelled→ Cancelled   Discarding ─discarded→ Discarded
//	Packing|Cancelling ─failed→ Failed (the Volume is untouched)
const maxVolumeArchives = 256

// VolumeArchiveBegin is the archive-volume payload. Root names a storage
// root on the Volume's node; empty means the node's archive default, else
// its default root.
type VolumeArchiveBegin struct {
	Scope       volumes.Scope
	ID          string
	Root        string `json:",omitempty"`
	Compression volumearchive.Compression
	MaxBytes    uint64
	MaxEntries  uint32
}

// VolumeArchiveSelection names one archive for cancel, unarchive and discard.
type VolumeArchiveSelection struct {
	Scope volumes.Scope
	ID    string
}

// VolumeArchiveAdminKey sets the administrator's X25519 public key, the
// second recipient of every new package.
type VolumeArchiveAdminKey struct {
	Key [32]byte
}

// VolumeArchiveKeys are the public recipient keys of new packages. Cluster
// is derived by every voter from the cluster master key and reported once.
type VolumeArchiveKeys struct {
	Cluster, Admin [32]byte
	Revision       uint64
}

type VolumeArchiveBinding struct {
	Schema        uint8
	Scope         volumes.Scope
	ID, Principal string
	Source        volumes.NativeReady
	Consumer      volumes.Consumer
	Root          nodestorage.Reference
	Compression   volumearchive.Compression
	MaxBytes      uint64
	MaxEntries    uint32
	Recipients    [2][32]byte // cluster key, administrator key
	Origin        UserOperation
}

func (b VolumeArchiveBinding) Digest() [32]byte { raw, _ := json.Marshal(b); return sha256.Sum256(raw) }
func (b VolumeArchiveBinding) Options() volumes.ArchiveOptions {
	return volumes.ArchiveOptions{MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, MaxDepth: 64, UID: b.Source.Spec.UID, GID: b.Source.Spec.GID, RootMode: b.Source.Spec.Mode}
}

// Bound is the largest data.mdbk a package may take: the tar limit plus
// zstd framing and sealing overhead. It is what Packing reserves on the root.
func (b VolumeArchiveBinding) Bound() uint64 { return archiveBound(b.MaxBytes) }
func archiveBound(max uint64) uint64         { return max + max/1024 + 1<<20 }

type VolumeArchive struct {
	Revision uint64
	Phase    string
	Binding  VolumeArchiveBinding
	Manifest *volumearchive.Manifest `json:",omitempty"`
	Restore  *UserOperation          `json:",omitempty"`
	Report   *VolumeArchiveReport    `json:",omitempty"`
}

// VolumeArchiveReport is an owner fact. Kinds: packed (Manifest), cleared,
// unrestored (Failure), and failed (Failure), cancelled, restored, discarded,
// which close the consumer (Closed).
type VolumeArchiveReport struct {
	Operation                     string
	Schema                        uint8
	Scope                         volumes.Scope
	ID                            string
	Epoch, RootRevision, Revision uint64
	At                            int64
	Binding                       [32]byte
	Kind                          string
	Manifest                      *volumearchive.Manifest `json:",omitempty"`
	Closed                        *volumes.Gone           `json:",omitempty"`
	Failure                       string                  `json:",omitempty"`
	Signature                     []byte
}

func VolumeArchiveReportBytes(r VolumeArchiveReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-volume-archive-report-1\x00"), raw...)
}

// VolumeArchiveKeyReport is a voter's report of the cluster archive key.
type VolumeArchiveKeyReport struct {
	Operation           string
	Schema              uint8
	Cluster, Reporter   [32]byte
	Epoch, RootRevision uint64
	Key                 [32]byte
	Signature           []byte
}

func VolumeArchiveKeyReportBytes(r VolumeArchiveKeyReport) []byte {
	r.Signature = nil
	raw, _ := json.Marshal(r)
	return append([]byte("sfc-volume-archive-key-1\x00"), raw...)
}

func (r VolumeArchiveKeyReport) Command() (state.Command, error) {
	raw, err := json.Marshal(r)
	if err != nil {
		return state.Command{}, err
	}
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(r.Reporter[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = state.EncodeCommand(cmd)
	return cmd, err
}

func operationValue(raw []byte, want string) bool {
	var value struct{ Operation string }
	return json.Unmarshal(raw, &value) == nil && value.Operation == want
}
func volumeArchiveReportValue(raw []byte) bool    { return operationValue(raw, "archive") }
func volumeArchiveKeyReportValue(raw []byte) bool { return operationValue(raw, "archive-key") }

func isArchiveAction(action string) bool {
	switch action {
	case "archive-volume", "cancel-volume-archive", "unarchive-volume", "discard-volume-archive", "set-volume-archive-admin-key":
		return true
	}
	return false
}

func archiveTerminal(phase string) bool {
	return phase == "Cancelled" || phase == "Failed" || phase == "Restored" || phase == "Discarded"
}

// archiveCharged is what an archive holds on its storage root.
func archiveCharged(j VolumeArchive) uint64 {
	switch j.Phase {
	case "Packing", "Cancelling":
		return j.Binding.Bound()
	case "Clearing", "Archived", "Restoring", "Discarding":
		return j.Manifest.DataBytes
	}
	return 0
}

func ownArchive(j VolumeArchive) VolumeArchive {
	raw, _ := json.Marshal(j)
	var out VolumeArchive
	_ = json.Unmarshal(raw, &out)
	return out
}

func (v Volumes) Archive(scope volumes.Scope, id string) (VolumeArchive, bool) {
	j, ok := v.archives[backupKey(scope, id)]
	return ownArchive(j), ok && j.Binding.Scope == scope
}
func (v Volumes) Archives() []VolumeArchive {
	keys := make([]string, 0, len(v.archives))
	for k := range v.archives {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	out := make([]VolumeArchive, 0, len(keys))
	for _, k := range keys {
		out = append(out, ownArchive(v.archives[k]))
	}
	return out
}
func (v Volumes) ArchiveKeys() VolumeArchiveKeys { return v.archiveKeys }

// activeArchive returns the archive that still holds the Volume at key.
func (v Volumes) activeArchive(key string) (VolumeArchive, bool) {
	for _, j := range v.archives {
		if volumeKey(j.Binding.Scope) == key && !archiveTerminal(j.Phase) {
			return j, true
		}
	}
	return VolumeArchive{}, false
}

// Archived reports whether the Volume is held by an archive: packed away or
// on its way in or out. Nothing else may use, move, back up or delete it.
func (v Volumes) Archived(scope volumes.Scope) bool {
	_, ok := v.activeArchive(volumeKey(scope))
	return ok
}

func archivedOnRoot(v Volumes, ref nodestorage.Reference) (int, uint64) {
	count, bytes := 0, uint64(0)
	for _, j := range v.archives {
		if j.Binding.Root == ref && !archiveTerminal(j.Phase) {
			count++
			bytes += archiveCharged(j)
		}
	}
	return count, bytes
}

func validArchiveBinding(b VolumeArchiveBinding) bool {
	if b.Schema != 1 || b.Source.Verify() != nil || b.Source.Spec.Scope != b.Scope || b.Source.Fixed != nil || !lifecycle.ValidID(b.ID) || !volumearchive.ValidID(b.ID) || len(b.ID) > 61 || !lifecycle.ValidID(b.Principal) || b.MaxBytes < 1024 || b.MaxBytes > 1<<40 || b.MaxEntries == 0 || b.MaxEntries > 100_000 || !b.Compression.Valid() {
		return false
	}
	if b.Consumer.ID != "a-"+b.ID || b.Consumer.Generation != 1 || !b.Consumer.Writable || b.Consumer.Remote() || b.Consumer.Owner != b.Source.Owner || b.Consumer.OwnerRevision == 0 || b.Consumer.Lease.Generation != b.Scope.Generation || b.Consumer.Lease.Token == 0 {
		return false
	}
	if b.Root.Cluster != b.Scope.Cluster || b.Root.Node != b.Source.Owner.Node || b.Root.Key != b.Source.Owner.Key || b.Recipients[0] == ([32]byte{}) || b.Recipients[1] == ([32]byte{}) {
		return false
	}
	if b.Origin.VerifyOriginal(b.Scope.Cluster) != nil || b.Origin.Change.Action != "archive-volume" || b.Origin.Session.User != b.Principal {
		return false
	}
	var requested VolumeArchiveBegin
	if canonical(b.Origin.Change.Payload, &requested) != nil || requested.Scope != b.Scope || requested.ID != b.ID || requested.Compression != b.Compression || requested.MaxBytes != b.MaxBytes || requested.MaxEntries != b.MaxEntries || requested.Root != "" && requested.Root != b.Root.ID {
		return false
	}
	return true
}

func validArchiveManifest(m volumearchive.Manifest, b VolumeArchiveBinding) bool {
	return m.Check(b.Options()) == nil && m.ID == b.ID && m.Scope == b.Scope && m.Compression == b.Compression && m.Node == b.Source.Owner.Key && m.DataBytes <= b.Bound()
}

func validArchiveReport(r VolumeArchiveReport, j VolumeArchive) bool {
	b := j.Binding
	if r.Operation != "archive" || r.Schema != 1 || r.Scope != b.Scope || r.ID != b.ID || r.Epoch == 0 || r.Revision == 0 || r.Binding != b.Digest() || r.At < 0 || !ed25519.Verify(ed25519.PublicKey(b.Source.Owner.Key[:]), VolumeArchiveReportBytes(r), r.Signature) {
		return false
	}
	closes := false
	switch r.Kind {
	case "packed":
		if r.Manifest == nil || !validArchiveManifest(*r.Manifest, b) || r.Failure != "" {
			return false
		}
	case "cleared":
		if r.Manifest != nil || r.Failure != "" {
			return false
		}
	case "unrestored":
		if r.Manifest != nil || !lifecycle.ValidID(r.Failure) {
			return false
		}
	case "failed":
		if r.Manifest != nil || !lifecycle.ValidID(r.Failure) {
			return false
		}
		closes = true
	case "cancelled", "restored", "discarded":
		if r.Manifest != nil || r.Failure != "" {
			return false
		}
		closes = true
	default:
		return false
	}
	if !closes {
		return r.Closed == nil
	}
	return r.Closed != nil && r.Closed.Scope == b.Scope && r.Closed.Consumer == b.Consumer && r.Closed.Stopped && r.Closed.MountsGone && ed25519.Verify(ed25519.PublicKey(b.Source.Owner.Key[:]), volumes.GoneBytes(*r.Closed), r.Closed.Signature)
}

func (p Policy) validateArchives(v Volumes) error {
	if len(v.archives) > maxVolumeArchives {
		return ErrCatalog
	}
	k := v.archiveKeys
	if k.Revision == 0 && (k.Cluster != ([32]byte{}) || k.Admin != ([32]byte{})) {
		return ErrCatalog
	}
	active := map[string]bool{}
	for key, j := range v.archives {
		b := j.Binding
		e, ok := v.entries[volumeKey(b.Scope)]
		if key != backupKey(b.Scope, b.ID) || j.Revision == 0 || !validArchiveBinding(b) || !ok || e.State.Scope() != b.Scope {
			return ErrCatalog
		}
		if j.Report != nil && (j.Report.Revision >= j.Revision || !validArchiveReport(*j.Report, j)) {
			return ErrCatalog
		}
		if j.Manifest != nil && !validArchiveManifest(*j.Manifest, b) {
			return ErrCatalog
		}
		held := slices.Contains(e.State.Consumers(), b.Consumer)
		if archiveTerminal(j.Phase) {
			if held || j.Report == nil {
				return ErrCatalog
			}
			continue
		}
		if active[volumeKey(b.Scope)] || !held || !sameVolumeNative(e.Native, b.Source) || e.State.Deleting() {
			return ErrCatalog
		}
		active[volumeKey(b.Scope)] = true
		switch j.Phase {
		case "Packing", "Cancelling":
			if j.Manifest != nil || j.Restore != nil {
				return ErrCatalog
			}
		case "Clearing", "Archived", "Discarding":
			if j.Manifest == nil || j.Restore != nil {
				return ErrCatalog
			}
		case "Restoring":
			if j.Manifest == nil || j.Restore == nil || j.Restore.VerifyOriginal(p.Cluster) != nil || j.Restore.Change.Action != "unarchive-volume" {
				return ErrCatalog
			}
		default:
			return ErrCatalog
		}
	}
	return nil
}

// archiveRoot resolves where a new package goes on node.
func archiveRoot(roots nodestorage.Catalog, node, name string) (nodestorage.Root, bool) {
	if name == "" {
		if d, ok := roots.ArchiveDefault(node); ok {
			return d, true
		}
		name = nodestorage.DefaultRootID
	}
	return roots.Root(node, name)
}

func (p Policy) reduceArchiveChange(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	change := op.Change
	switch change.Action {
	case "set-volume-archive-admin-key":
		var q VolumeArchiveAdminKey
		if canonical(change.Payload, &q) != nil || q.Key == ([32]byte{}) {
			return nil, state.Invalid
		}
		k := v.archiveKeys
		if k.Revision != change.Expected || k.Revision == ^uint64(0) || k.Admin == q.Key {
			return nil, state.ConditionFailed
		}
		k.Admin, k.Revision = q.Key, k.Revision+1
		v.archiveKeys = k
		return p.volumeCheckpoint(s, v)
	case "archive-volume":
		return p.beginArchive(s, c, v, op)
	}
	var q VolumeArchiveSelection
	if canonical(change.Payload, &q) != nil {
		return nil, state.Invalid
	}
	key := backupKey(q.Scope, q.ID)
	j, ok := v.archives[key]
	if !ok || j.Binding.Scope != q.Scope || j.Revision != change.Expected || j.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	switch change.Action {
	case "cancel-volume-archive":
		if j.Phase != "Packing" {
			return nil, state.ConditionFailed
		}
		j.Phase = "Cancelling"
	case "unarchive-volume":
		if j.Phase != "Archived" {
			return nil, state.ConditionFailed
		}
		j.Phase, j.Restore = "Restoring", &op
	case "discard-volume-archive":
		if j.Phase != "Archived" {
			return nil, state.ConditionFailed
		}
		j.Phase = "Discarding"
	default:
		return nil, state.Invalid
	}
	j.Revision++
	v.archives[key] = j
	return p.volumeCheckpoint(s, v)
}

func (p Policy) beginArchive(s state.State, c access.Catalog, v Volumes, op UserOperation) (map[string][]byte, state.Code) {
	change := op.Change
	var q VolumeArchiveBegin
	if canonical(change.Payload, &q) != nil || !lifecycle.ValidID(q.ID) || !volumearchive.ValidID(q.ID) || len(q.ID) > 61 || q.Root != "" && !lifecycle.ValidID(q.Root) || q.MaxBytes < 1024 || q.MaxBytes > 1<<40 || q.MaxEntries == 0 || q.MaxEntries > 100_000 || !q.Compression.Valid() {
		return nil, state.Invalid
	}
	keys := v.archiveKeys
	if keys.Cluster == ([32]byte{}) || keys.Admin == ([32]byte{}) {
		return nil, state.ConditionFailed
	}
	vk := volumeKey(q.Scope)
	e, ok := v.entries[vk]
	if !ok || e.State.Scope() != q.Scope || e.State.Revision() != change.Expected || e.State.Fixed() || e.State.Deleting() || e.Native.Fixed != nil {
		return nil, state.ConditionFailed
	}
	if _, held := v.activeArchive(vk); held || v.movingVolume(vk) || v.backupHolds(vk) {
		return nil, state.ConditionFailed
	}
	if !p.closedAppVolume(s, e) {
		return nil, state.ConditionFailed
	}
	// Drop this Volume's finished records so a Volume archived again and
	// again does not fill the bound.
	for key, j := range v.archives {
		if volumeKey(j.Binding.Scope) == vk && archiveTerminal(j.Phase) {
			delete(v.archives, key)
		}
	}
	key := backupKey(q.Scope, q.ID)
	if _, ok := v.archives[key]; ok || len(v.archives) >= maxVolumeArchives {
		return nil, state.ConditionFailed
	}
	owner, err := p.workNodeOwner(s, e.Native.Spec.Node)
	if err != nil || !p.ownsResource(s, owner, e.Native.Owner.Key) {
		return nil, state.Forbidden
	}
	roots, err := p.NodeStorage(s)
	if err != nil {
		return nil, state.Invalid
	}
	found, ok := archiveRoot(roots, e.Native.Owner.Node, q.Root)
	if !ok {
		return nil, state.ConditionFailed
	}
	root, err := roots.CanUse(c, change.Principal, q.Scope.Tenant, found.Definition.Node, found.Definition.ID, found.Generation)
	if err != nil || root.Definition.Key != e.Native.Owner.Key {
		return nil, state.ConditionFailed
	}
	ref := root.Reference(p.Cluster)
	if !rootAdmits(root, v, ref, archiveBound(q.MaxBytes)) {
		return nil, state.ConditionFailed
	}
	next, consumer, err := e.State.Acquire(c, change.Principal, change.Expected, "a-"+q.ID, 1, true)
	if err != nil {
		return nil, state.ConditionFailed
	}
	binding := VolumeArchiveBinding{Schema: 1, Scope: q.Scope, ID: q.ID, Principal: change.Principal, Source: e.Native, Consumer: consumer, Root: ref, Compression: q.Compression, MaxBytes: q.MaxBytes, MaxEntries: q.MaxEntries, Recipients: [2][32]byte{keys.Cluster, keys.Admin}, Origin: op}
	if !validArchiveBinding(binding) {
		return nil, state.ConditionFailed
	}
	v.archives[key] = VolumeArchive{Revision: 1, Phase: "Packing", Binding: binding}
	e.State = next
	e.Grants = append(e.Grants, volumeGrant{Consumer: consumer, Principal: change.Principal})
	v.entries[vk] = e
	return p.volumeCheckpoint(s, v)
}

func (v Volumes) movingVolume(key string) bool {
	for _, j := range v.moves {
		if volumeKey(j.Binding.Scope) != key {
			continue
		}
		if _, m, ok := v.Move(j.Selection()); ok && movePending(m) {
			return true
		}
	}
	return false
}
func (v Volumes) backupHolds(key string) bool {
	for _, j := range v.backups {
		if volumeKey(j.Binding.Scope) == key && backupPending(j.Phase) {
			return true
		}
	}
	return false
}

func (p Policy) archiveReport(s state.State, cmd state.Command) (VolumeArchiveReport, error) {
	var r VolumeArchiveReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Epoch != cmd.Epoch || r.RootRevision != cmd.Expected || cmd.RequestID != state.ReportRequestID(cmd) {
		return r, access.ErrDenied
	}
	v, err := p.Volumes(s)
	if err != nil {
		return r, err
	}
	j, ok := v.Archive(r.Scope, r.ID)
	if !ok || !validArchiveReport(r, j) || cmd.Actor != "node/"+hex.EncodeToString(j.Binding.Source.Owner.Key[:]) {
		return r, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Binding.Source.Owner.Node)
	if err != nil || !p.ownsResource(s, owner, j.Binding.Source.Owner.Key) {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) ResolveVolumeArchiveReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	r, err := schema.Decode[VolumeArchiveReport](raw)
	if err != nil {
		return state.Command{}, err
	}
	v, err := p.Volumes(s)
	if err != nil {
		return state.Command{}, err
	}
	j, ok := v.Archive(r.Scope, r.ID)
	if !ok || !p.ownsResource(s, caller, j.Binding.Source.Owner.Key) {
		return state.Command{}, access.ErrDenied
	}
	key := j.Binding.Source.Owner.Key
	cmd := state.Command{Kind: state.ModuleReport, Actor: "node/" + hex.EncodeToString(key[:]), Epoch: r.Epoch, Key: VolumesKey, Expected: r.RootRevision, Value: string(raw)}
	cmd.RequestID = state.ReportRequestID(cmd)
	_, err = p.archiveReport(s, cmd)
	return cmd, err
}

func (p Policy) reduceArchiveReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.archiveReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	key := backupKey(r.Scope, r.ID)
	j := v.archives[key]
	if j.Revision != r.Revision || j.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	from := map[string][]string{"packed": {"Packing"}, "cleared": {"Clearing"}, "unrestored": {"Restoring"}, "failed": {"Packing", "Cancelling"}, "cancelled": {"Cancelling"}, "restored": {"Restoring"}, "discarded": {"Discarding"}}
	if !slices.Contains(from[r.Kind], j.Phase) {
		return nil, state.ConditionFailed
	}
	if r.Closed != nil {
		e := v.entries[volumeKey(r.Scope)]
		e.State, err = e.State.Release(*r.Closed)
		if err != nil {
			return nil, state.ConditionFailed
		}
		e.Grants = slices.DeleteFunc(e.Grants, func(g volumeGrant) bool { return g.Consumer == j.Binding.Consumer })
		v.entries[volumeKey(r.Scope)] = e
	}
	switch r.Kind {
	case "packed":
		m := *r.Manifest
		j.Phase, j.Manifest = "Clearing", &m
	case "cleared":
		j.Phase = "Archived"
	case "unrestored":
		j.Phase, j.Restore = "Archived", nil
	case "failed":
		j.Phase = "Failed"
	case "cancelled":
		j.Phase = "Cancelled"
	case "restored":
		j.Phase = "Restored"
	case "discarded":
		j.Phase = "Discarded"
	}
	j.Revision++
	j.Report = &r
	v.archives[key] = j
	return p.volumeCheckpoint(s, v)
}

func (p Policy) archiveKeyReport(s state.State, cmd state.Command) (VolumeArchiveKeyReport, error) {
	var r VolumeArchiveKeyReport
	if cmd.Kind != state.ModuleReport || cmd.Key != VolumesKey || canonical([]byte(cmd.Value), &r) != nil || r.Operation != "archive-key" || r.Schema != 1 || r.Cluster != p.Cluster || r.Key == ([32]byte{}) || r.Epoch != s.ModuleEpoch() || r.RootRevision != s.Object(VolumesKey).Revision || !ed25519.Verify(r.Reporter[:], VolumeArchiveKeyReportBytes(r), r.Signature) {
		return r, access.ErrDenied
	}
	want, err := r.Command()
	current, pe := p.Current(s)
	if err != nil || pe != nil || want != cmd {
		return r, access.ErrDenied
	}
	// Only a voter holds the master key the cluster archive key comes from.
	members, err := current.Members(s)
	if err != nil || !members.VoterKey(r.Reporter) {
		return r, access.ErrDenied
	}
	return r, nil
}

func (p Policy) ResolveVolumeArchiveKeyReport(s state.State, caller [32]byte, raw []byte) (state.Command, error) {
	var r VolumeArchiveKeyReport
	if canonical(raw, &r) != nil || r.Reporter != caller {
		return state.Command{}, access.ErrDenied
	}
	cmd, err := r.Command()
	if err == nil {
		_, err = p.archiveKeyReport(s, cmd)
	}
	return cmd, err
}

func (p Policy) reduceArchiveKeyReport(s state.State, cmd state.Command) (map[string][]byte, state.Code) {
	r, err := p.archiveKeyReport(s, cmd)
	if err != nil {
		return nil, state.Forbidden
	}
	v, err := p.Volumes(s)
	if err != nil {
		return nil, state.Invalid
	}
	// The key is fixed by the master key: the first report sets it, a
	// different one is refused.
	if v.archiveKeys.Cluster != ([32]byte{}) || v.archiveKeys.Revision == ^uint64(0) {
		return nil, state.ConditionFailed
	}
	v.archiveKeys.Cluster = r.Key
	v.archiveKeys.Revision++
	return p.volumeCheckpoint(s, v)
}

// VolumeArchivePermit returns the accepted archive for its owner's work.
// Packing also needs the original grant to stand; cleanup phases do not.
func (p Policy) VolumeArchivePermit(s state.State, caller [32]byte, q VolumeArchiveSelection) (VolumeArchive, error) {
	current, err := p.Current(s)
	if err != nil {
		return VolumeArchive{}, err
	}
	p = current
	v, err := p.Volumes(s)
	if err != nil {
		return VolumeArchive{}, err
	}
	j, ok := v.Archive(q.Scope, q.ID)
	if !ok || archiveTerminal(j.Phase) || j.Phase == "Archived" {
		return j, access.ErrDenied
	}
	owner, err := p.nodeOwner(s, j.Binding.Source.Owner.Node)
	if err != nil || owner != caller || !p.ownsResource(s, caller, j.Binding.Source.Owner.Key) {
		return j, access.ErrDenied
	}
	if j.Phase != "Packing" {
		return j, nil
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeAccepted(j.Binding.Origin.Session, p.Cluster, j.Binding.Origin.At, j.Binding.Scope.Tenant, access.ManageVolumes, j.Binding.Source.Owner.Node) != nil {
		return j, access.ErrDenied
	}
	return j, nil
}

// VolumeArchiveView is metadata only: no session, envelope or path.
type VolumeArchiveView struct {
	Key                 string
	Scope               volumes.Scope
	ID, Node, Phase     string
	Root                string
	Revision, MaxBytes  uint64
	MaxEntries          uint32
	Compression         volumearchive.Compression
	DataBytes, TarBytes uint64 `json:",omitempty"`
	Failure             string `json:",omitempty"`
}

func (v Volumes) ArchivePage(c access.Catalog, actor, tenant, after string) ([]VolumeArchiveView, string, error) {
	if tenant == "" {
		if !c.SystemAllowed(actor) {
			return nil, "", access.ErrDenied
		}
	} else if c.Authorize(actor, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	var page []VolumeArchiveView
	for _, j := range v.Archives() {
		b := j.Binding
		key := backupKey(b.Scope, b.ID)
		if tenant != "" && b.Scope.Tenant != tenant || key <= after {
			continue
		}
		if len(page) == 8 {
			return page, page[len(page)-1].Key, nil
		}
		row := VolumeArchiveView{Key: key, Scope: b.Scope, ID: b.ID, Node: b.Source.Owner.Node, Phase: j.Phase, Root: b.Root.ID, Revision: j.Revision, MaxBytes: b.MaxBytes, MaxEntries: b.MaxEntries, Compression: b.Compression}
		if j.Manifest != nil {
			row.DataBytes, row.TarBytes = j.Manifest.DataBytes, j.Manifest.Tar.Bytes
		}
		if j.Report != nil {
			row.Failure = j.Report.Failure
		}
		page = append(page, row)
	}
	return page, "", nil
}
