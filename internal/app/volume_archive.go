// SPDX-License-Identifier: Apache-2.0

package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/jay94ks/seafield/internal/cluster"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/clusterbackup"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/nodestorage"
	"github.com/jay94ks/seafield/internal/reconcile"
	"github.com/jay94ks/seafield/internal/schema"
	"github.com/jay94ks/seafield/internal/sfcp"
	"github.com/jay94ks/seafield/internal/volumearchive"
	"github.com/jay94ks/seafield/internal/volumearchive/pack"
	"github.com/jay94ks/seafield/internal/workload/volumes"
)

// The owner side of Volume archives (devel/proposals/volume-archive-packages.md
// 10): pack into <root>/.sfc-archive/<volume key>/<id>/{data.mdbk,manifest},
// read it back, empty the native, and later restore or discard. Every step
// is idempotent and resumes from what is on disk after a restart.

const (
	archiveDataName     = "data.mdbk"
	archiveManifestName = "manifest"
	// archiveKeyLabel separates the cluster archive key from other keys
	// derived from the cluster master key.
	archiveKeyLabel = "volume-archive"
)

// errArchiveRefused is a package that cannot be made or restored; it ends
// the archive (failed, unrestored) instead of retrying.
var errArchiveRefused = errors.New("volume archive refused")

// errArchivePackageGone is a Restoring archive whose package directory is
// gone: an earlier run restored it and lost its report, or the package was
// lost outside sfcd. The native tree tells which.
var errArchivePackageGone = errors.New("volume archive package gone")

func archiveRootConsumer(b control.VolumeArchiveBinding) string {
	d := b.Digest()
	return "volume-archive/" + hex.EncodeToString(d[:16])
}
func archiveRel(b control.VolumeArchiveBinding) string {
	return path.Join(".sfc-archive", b.Scope.Key(), b.ID)
}

// VolumeArchiveUnsealRequest asks a voter for a Restoring archive's data
// key. Keys are the sealed keys at the head of its data.mdbk.
type VolumeArchiveUnsealRequest struct {
	Selection control.VolumeArchiveSelection
	Keys      []clusterbackup.SealedMaster
}
type VolumeArchiveUnsealReply struct {
	Key []byte
}

func init() {
	defineNodeRead((*Runtime).nodeReadVolumeArchivePermit, true, "volume-archive-permit")
	defineNodeRead((*Runtime).nodeReadVolumeArchiveUnseal, true, "volume-archive-unseal")
}

func (r *Runtime) nodeReadVolumeArchivePermit(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[control.VolumeArchiveSelection](input)
	if err != nil {
		return nil, err
	}
	j, err := r.controlPolicy.VolumeArchivePermit(v.State, caller, q)
	if err != nil {
		return nil, err
	}
	return json.Marshal(j)
}

// nodeReadVolumeArchiveUnseal opens a Restoring archive's data key with the
// cluster archive key. Only a voter holds the master key it comes from; the
// key is bound to this archive's ID and this cluster, so sealed keys from
// any other file do not open here.
func (r *Runtime) nodeReadVolumeArchiveUnseal(ctx context.Context, method, key string, input []byte, v cluster.View) (json.RawMessage, error) {
	if v.Local {
		return nil, sfcp.ErrAdmission
	}
	caller, err := identity.ParseKey(key)
	if err != nil {
		return nil, err
	}
	q, err := schema.Decode[VolumeArchiveUnsealRequest](input)
	if err != nil || len(q.Keys) == 0 || len(q.Keys) > 8 {
		return nil, sfcp.ErrAdmission
	}
	j, err := r.controlPolicy.VolumeArchivePermit(v.State, caller, q.Selection)
	if err != nil || j.Phase != "Restoring" {
		return nil, sfcp.ErrAdmission
	}
	recipient, err := r.archiveRecipient()
	if err != nil || recipient.Public() != j.Binding.Recipients[0] {
		return nil, sfcp.ErrAdmission
	}
	data, err := recipient.UnsealDataKey(clusterbackup.SealedTo{Cluster: j.Binding.Scope.Cluster, Context: volumearchive.Context(j.Binding.ID)}, q.Keys)
	if err != nil {
		return nil, sfcp.ErrAdmission
	}
	defer clear(data)
	return json.Marshal(VolumeArchiveUnsealReply{Key: data})
}

func (r *Runtime) archiveRecipient() (clusterbackup.Recipient, error) {
	master, err := r.certificateMaster()
	if err != nil {
		return clusterbackup.Recipient{}, err
	}
	defer clear(master)
	return clusterbackup.RecipientFromSeed(master, archiveKeyLabel)
}

// reconcileVolumeArchives runs this node's archive work and, on a voter, the
// one-time cluster archive key report.
func (r *Runtime) reconcileVolumeArchives(ctx context.Context, view cluster.View, registry control.Volumes) error {
	failed := r.reportArchiveKey(ctx, view, registry)
	for _, j := range registry.Archives() {
		if j.Binding.Source.Owner.Key != r.Identity.Public {
			continue
		}
		switch j.Phase {
		case "Packing", "Cancelling", "Clearing", "Restoring", "Discarding":
		default:
			continue
		}
		failed = errors.Join(failed, r.stepVolumeArchive(ctx, view, j))
		if ctx.Err() != nil {
			break
		}
	}
	return failed
}

func (r *Runtime) reportArchiveKey(ctx context.Context, view cluster.View, registry control.Volumes) error {
	if registry.ArchiveKeys().Cluster != ([32]byte{}) {
		return nil
	}
	members, err := r.controlPolicy.Members(view.State)
	if err != nil || !members.VoterKey(r.Identity.Public) {
		return nil
	}
	recipient, err := r.archiveRecipient()
	if err != nil {
		return nil // this voter has not received the master key yet
	}
	report := control.VolumeArchiveKeyReport{Operation: "archive-key", Schema: 1, Cluster: r.controlPolicy.Cluster, Reporter: r.Identity.Public, Epoch: view.State.ModuleEpoch(), RootRevision: view.State.Object(control.VolumesKey).Revision, Key: recipient.Public()}
	report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeArchiveKeyReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "volume-archive-key-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}

// authorizeArchive is a fresh quorum read that the archive is still exactly
// this job.
func (r *Runtime) authorizeArchive(ctx context.Context, j control.VolumeArchive) error {
	body, _ := json.Marshal(control.VolumeArchiveSelection{Scope: j.Binding.Scope, ID: j.Binding.ID})
	reply, err := r.appCall(ctx, "volume-archive-permit", body)
	if err != nil {
		return err
	}
	current, err := schema.Decode[control.VolumeArchive](reply.Data)
	if err != nil || reply.Local || reply.RaftIndex == 0 || current.Binding.Digest() != j.Binding.Digest() || current.Phase != j.Phase || current.Revision != j.Revision {
		return sfcp.ErrAdmission
	}
	return nil
}

func (r *Runtime) stepVolumeArchive(ctx context.Context, view cluster.View, j control.VolumeArchive) error {
	if err := r.authorizeArchive(ctx, j); err != nil {
		return err
	}
	authorize := func(ctx context.Context, ready volumes.NativeReady, c volumes.Consumer) error {
		if ready.Owner != j.Binding.Source.Owner || c != j.Binding.Consumer {
			return sfcp.ErrAdmission
		}
		return r.authorizeArchive(ctx, j)
	}
	b := j.Binding
	o := b.Options()
	switch j.Phase {
	case "Packing":
		m, err := r.packArchive(ctx, view, j, authorize)
		if errors.Is(err, errArchiveRefused) {
			if err := r.removeArchivePackage(ctx, view, b); err != nil {
				return err
			}
			return r.reportArchive(ctx, j, "failed", nil, failureCode(err))
		}
		if err != nil {
			return err
		}
		return r.reportArchive(ctx, j, "packed", &m, "")
	case "Clearing":
		if err := r.nativeVolumes.WithCold(ctx, b.Source, b.Consumer, authorize, o, func(root *os.Root) error { return volumes.ClearRoot(ctx, root) }); err != nil {
			return err
		}
		return r.reportArchive(ctx, j, "cleared", nil, "")
	case "Restoring":
		err := r.restoreArchive(ctx, view, j, authorize)
		if errors.Is(err, errArchivePackageGone) {
			// The package is removed only after a whole restore, so the
			// native then holds exactly the archived tree. Anything else
			// means the package was lost elsewhere: say so, keep the native.
			restored := false
			e := r.nativeVolumes.WithCold(ctx, b.Source, b.Consumer, authorize, o, func(root *os.Root) error {
				got, err := volumes.WriteArchive(ctx, root, io.Discard, o)
				restored = err == nil && j.Manifest != nil && got == j.Manifest.Tar
				return nil
			})
			if e != nil {
				return e
			}
			// A stop after the tombstone but before the pin went back
			// leaves both; nothing else would clear them once reported.
			if e := r.removeArchivePackage(ctx, view, b); e != nil {
				return e
			}
			if restored {
				return r.reportArchive(ctx, j, "restored", nil, "")
			}
			return r.reportArchive(ctx, j, "unrestored", nil, "package-missing")
		}
		if errors.Is(err, errArchiveRefused) {
			// The package stays; the native is emptied again so a later
			// unarchive starts clean.
			if e := r.nativeVolumes.WithCold(ctx, b.Source, b.Consumer, authorize, o, func(root *os.Root) error { return volumes.ClearRoot(ctx, root) }); e != nil {
				return e
			}
			return r.reportArchive(ctx, j, "unrestored", nil, failureCode(err))
		}
		if err != nil {
			return err
		}
		if err := r.removeArchivePackage(ctx, view, b); err != nil {
			return err
		}
		return r.reportArchive(ctx, j, "restored", nil, "")
	case "Cancelling", "Discarding":
		if err := r.removeArchivePackage(ctx, view, b); err != nil {
			return err
		}
		kind := map[string]string{"Cancelling": "cancelled", "Discarding": "discarded"}[j.Phase]
		return r.reportArchive(ctx, j, kind, nil, "")
	}
	return nil
}

func failureCode(err error) string {
	var f archiveFailure
	if errors.As(err, &f) {
		return string(f)
	}
	return "package-failed"
}

// archiveFailure is a refused package with its reported code.
type archiveFailure string

func (f archiveFailure) Error() string        { return errArchiveRefused.Error() + ": " + string(f) }
func (f archiveFailure) Is(target error) bool { return target == errArchiveRefused }

// archiveStore opens the package directory on the archive's storage root,
// holding the root pin. create also makes the directory.
type archiveStore struct {
	pin  nodestorage.RootPin
	dir  *os.Root
	base *os.Root
}

func (s *archiveStore) Close() error {
	var err error
	if s.dir != nil {
		err = s.dir.Close()
	}
	if s.base != nil {
		err = errors.Join(err, s.base.Close())
	}
	if s.pin.Directory != nil {
		err = errors.Join(err, s.pin.Directory.Close())
	}
	return err
}

func (r *Runtime) openArchiveStore(ctx context.Context, view cluster.View, b control.VolumeArchiveBinding, create bool) (*archiveStore, bool, error) {
	consumer := archiveRootConsumer(b)
	_, recorded, err := r.nodeRoots.RecordedPin(b.Root, consumer)
	if err != nil {
		return nil, false, err
	}
	var pin nodestorage.RootPin
	switch {
	case recorded:
		pin, err = r.nodeRoots.OpenRecordedPin(b.Root, consumer)
	case !create:
		return nil, false, nil // never made: nothing on disk
	default:
		roots, e := r.controlPolicy.NodeStorage(view.State)
		if e != nil {
			return nil, false, e
		}
		root, ok := roots.Root(b.Root.Node, b.Root.ID)
		if !ok || root.Reference(r.controlPolicy.Cluster) != b.Root {
			return nil, false, errors.Join(reconcile.ErrPending, nodestorage.ErrStorage)
		}
		if err = r.nodeRoots.Desired(root); err != nil {
			return nil, false, err
		}
		pin, err = r.nodeRoots.Pin(ctx, root, consumer)
	}
	if err != nil {
		if pin.Directory != nil {
			_ = pin.Directory.Close()
		}
		return nil, false, err
	}
	s := &archiveStore{pin: pin}
	s.base, err = os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", pin.Directory.FD()))
	if err != nil {
		_ = s.Close()
		return nil, false, err
	}
	rel := archiveRel(b)
	if create {
		if err = s.base.MkdirAll(rel, 0700); err != nil {
			_ = s.Close()
			return nil, false, err
		}
	}
	s.dir, err = s.base.OpenRoot(rel)
	if errors.Is(err, os.ErrNotExist) && !create {
		return s, true, nil // pinned, directory already gone
	}
	if err != nil {
		_ = s.Close()
		return nil, false, err
	}
	return s, true, nil
}

// removeArchivePackage deletes the package and returns the root pin. A
// package that was never made is already removed.
func (r *Runtime) removeArchivePackage(ctx context.Context, view cluster.View, b control.VolumeArchiveBinding) error {
	s, ok, err := r.openArchiveStore(ctx, view, b, false)
	if err != nil || !ok {
		return err
	}
	if s.dir != nil {
		_ = s.dir.Close()
		s.dir = nil
	}
	err = removePackageDir(s.base, archiveRel(b))
	pin := s.pin
	err = errors.Join(err, s.Close())
	if err != nil {
		return err
	}
	pin.Directory = nil
	return r.nodeRoots.Return(pin)
}

// removePackageDir first renames the package directory to a tombstone in
// the same parent and syncs it, then removes the tombstone. So a directory
// under the package's own name is always a whole package: a stop part way
// leaves only a tombstone, which the next run removes.
func removePackageDir(base *os.Root, rel string) error {
	tomb := rel + ".gone"
	// A tombstone left by an earlier stop goes first.
	if err := base.RemoveAll(tomb); err != nil {
		return err
	}
	err := base.Rename(rel, tomb)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = syncDir(base, path.Dir(rel)); err != nil {
		return err
	}
	if err = base.RemoveAll(tomb); err != nil {
		return err
	}
	return syncDir(base, path.Dir(rel))
}

func syncDir(root *os.Root, name string) error {
	d, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// boundWriter refuses writes past the archive's reserved bound.
type boundWriter struct {
	w     io.Writer
	left  uint64
	stuck bool
}

func (w *boundWriter) Write(p []byte) (int, error) {
	if uint64(len(p)) > w.left {
		w.stuck = true
		return 0, archiveFailure("too-large")
	}
	n, err := w.w.Write(p)
	w.left -= uint64(n)
	return n, err
}

func validOwnManifest(m volumearchive.Manifest, b control.VolumeArchiveBinding, self [32]byte) bool {
	return m.Check(b.Options()) == nil && m.ID == b.ID && m.Scope == b.Scope && m.Compression == b.Compression && m.Node == self && m.DataBytes <= b.Bound()
}

// archiveSourceClean applies the backup rule: the last writer exited
// cleanly. A Volume no writer ever used here is clean too.
func (r *Runtime) archiveSourceClean(ctx context.Context, b control.VolumeArchiveBinding) error {
	_, err := r.activations.ColdSource(ctx, b.Source)
	if err == nil || volumes.ActivationReason(err) == "no-activation" {
		return nil
	}
	if _, stopped := r.activations.StoppedSource(ctx, b.Source); stopped == nil {
		return archiveFailure("unclean-exit")
	}
	return err
}

func (r *Runtime) packArchive(ctx context.Context, view cluster.View, j control.VolumeArchive, authorize volumes.ColdAuthority) (volumearchive.Manifest, error) {
	b := j.Binding
	if err := r.archiveSourceClean(ctx, b); err != nil {
		return volumearchive.Manifest{}, err
	}
	s, _, err := r.openArchiveStore(ctx, view, b, true)
	if err != nil {
		return volumearchive.Manifest{}, err
	}
	defer s.Close()
	// A manifest is written last: if it is there, the package is complete
	// and already verified (an earlier run's report was lost).
	if raw, err := s.dir.ReadFile(archiveManifestName); err == nil {
		var m volumearchive.Manifest
		if json.Unmarshal(raw, &m) == nil && validOwnManifest(m, b, r.Identity.Public) {
			return m, nil
		}
		return volumearchive.Manifest{}, archiveFailure("bad-manifest")
	}
	out, err := s.dir.OpenFile(archiveDataName, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return volumearchive.Manifest{}, err
	}
	var m volumearchive.Manifest
	var key []byte
	o := b.Options()
	err = r.nativeVolumes.WithCold(ctx, b.Source, b.Consumer, authorize, o, func(root *os.Root) error {
		bounded := &boundWriter{w: out, left: b.Bound()}
		var e error
		m, key, e = pack.PackKey(ctx, root, bounded, o, pack.Params{ID: b.ID, Scope: b.Scope, Compression: b.Compression, Recipients: b.Recipients[:]})
		if errors.Is(e, volumes.ErrArchive) || errors.Is(e, volumearchive.ErrPackage) {
			return errors.Join(e, archiveFailure("pack-failed"))
		}
		return e
	})
	defer clear(key)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return volumearchive.Manifest{}, err
	}
	open := func() (io.ReadCloser, error) { return s.dir.Open(archiveDataName) }
	if err := pack.Verify(ctx, open, key, m, o); err != nil {
		if ctx.Err() != nil {
			return volumearchive.Manifest{}, ctx.Err()
		}
		return volumearchive.Manifest{}, errors.Join(err, archiveFailure("verify-failed"))
	}
	m.Node, m.At = r.Identity.Public, time.Now().Unix()
	m = volumearchive.Sign(m, r.Identity.Private)
	raw, _ := json.Marshal(m)
	if err := writeSynced(s.dir, archiveManifestName, raw); err != nil {
		return volumearchive.Manifest{}, err
	}
	return m, nil
}

func writeSynced(dir *os.Root, name string, raw []byte) error {
	tmp := name + ".tmp"
	f, err := dir.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(raw)
	if err == nil {
		err = f.Sync()
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err = dir.Rename(tmp, name); err != nil {
		return err
	}
	return syncDir(dir, ".")
}

func (r *Runtime) restoreArchive(ctx context.Context, view cluster.View, j control.VolumeArchive, authorize volumes.ColdAuthority) error {
	b := j.Binding
	if j.Manifest == nil {
		return archiveFailure("no-manifest")
	}
	m := *j.Manifest
	s, ok, err := r.openArchiveStore(ctx, view, b, false)
	if err != nil {
		return err
	}
	if !ok || s.dir == nil {
		if ok {
			_ = s.Close()
		}
		return errArchivePackageGone
	}
	defer s.Close()
	open := func() (io.ReadCloser, error) { return s.dir.Open(archiveDataName) }
	head, err := open()
	if err != nil {
		return archiveFailure("package-damaged")
	}
	sealed, err := clusterbackup.SealedKeys(head)
	_ = head.Close()
	if err != nil {
		return archiveFailure("package-damaged")
	}
	body, _ := json.Marshal(VolumeArchiveUnsealRequest{Selection: control.VolumeArchiveSelection{Scope: b.Scope, ID: b.ID}, Keys: sealed})
	reply, err := r.appCall(ctx, "volume-archive-unseal", body)
	if err != nil {
		return err
	}
	unsealed, err := schema.Decode[VolumeArchiveUnsealReply](reply.Data)
	if err != nil || reply.Local || len(unsealed.Key) != 32 {
		return sfcp.ErrAdmission
	}
	key := unsealed.Key
	defer clear(key)
	return r.nativeVolumes.WithCold(ctx, b.Source, b.Consumer, authorize, b.Options(), func(root *os.Root) error {
		// An interrupted earlier restore may have left part of the tree.
		if err := volumes.ClearRoot(ctx, root); err != nil {
			return err
		}
		err := pack.Restore(ctx, root, open, key, m, b.Options())
		if errors.Is(err, volumearchive.ErrPackage) || errors.Is(err, volumes.ErrArchive) {
			return errors.Join(err, archiveFailure("restore-failed"))
		}
		return err
	})
}

func (r *Runtime) reportArchive(ctx context.Context, j control.VolumeArchive, kind string, m *volumearchive.Manifest, failure string) error {
	v, err := r.Engine().Read(ctx, false)
	if err != nil {
		return err
	}
	registry, err := r.controlPolicy.Volumes(v.State)
	if err != nil {
		return err
	}
	current, ok := registry.Archive(j.Binding.Scope, j.Binding.ID)
	if !ok || current.Binding.Digest() != j.Binding.Digest() || current.Revision != j.Revision {
		return reconcile.ErrPending
	}
	report := control.VolumeArchiveReport{Operation: "archive", Schema: 1, Scope: j.Binding.Scope, ID: j.Binding.ID, Epoch: v.State.ModuleEpoch(), RootRevision: v.State.Object(control.VolumesKey).Revision, Revision: j.Revision, At: time.Now().Unix(), Binding: j.Binding.Digest(), Kind: kind, Manifest: m, Failure: failure}
	switch kind {
	case "failed", "cancelled", "restored", "discarded":
		closed := volumes.Gone{Scope: j.Binding.Scope, Consumer: j.Binding.Consumer, Stopped: true, MountsGone: true}
		closed.Signature = ed25519.Sign(r.Identity.Private, volumes.GoneBytes(closed))
		report.Closed = &closed
	}
	report.Signature = ed25519.Sign(r.Identity.Private, control.VolumeArchiveReportBytes(report))
	raw, _ := json.Marshal(report)
	reply, err := r.appCall(ctx, "volume-archive-report", raw)
	if err != nil {
		return err
	}
	if reply.Committed == nil || reply.Committed.Result.Code != state.Applied {
		return reconcile.ErrPending
	}
	return nil
}
