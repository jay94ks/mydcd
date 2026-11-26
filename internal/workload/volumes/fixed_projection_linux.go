// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jay94ks/mydcd/internal/nodestorage"
	"github.com/jay94ks/mydcd/internal/schema"
	"golang.org/x/sys/unix"
)

// A projection is PRIVATE node state, never a user-supplied bind source. Its
// original inode/owner marker is synced before attaching any source mount.
// All functions run under FixedManager's guard. Source data is never created,
// chmod/chowned or removed by this adapter.
type projectionInode struct {
	Device, Inode uint64
	UID, Mode     uint32
}
type projectionOwner struct {
	Schema       uint8
	Spec         [32]byte
	Slot, Target projectionInode
}
type projectionEpoch struct {
	Schema                uint8
	Spec, Boot, Namespace [32]byte
	Signature             []byte
}
type fixedProjector struct {
	file    *os.File
	path    string
	private ed25519.PrivateKey
	node    [32]byte
}

func projectionSpec(spec NativeSpec) [32]byte {
	raw, _ := json.Marshal(spec)
	return sha256.Sum256(append([]byte("mydc-fixed-projection-owner-1\x00"), raw...))
}

func openPrivateProjection(path string, private ed25519.PrivateKey) (*fixedProjector, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, ErrNativeVolume
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "mounts" {
		return nil, ErrNativeVolume
	}
	parent, err := unix.Openat2(unix.AT_FDCWD, filepath.Dir(path), &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(parent)
	if err = unix.Mkdirat(parent, "mounts", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat2(parent, "mounts", &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := privateProjectionInode(fd, true)
	if err != nil || st.Mode&07777 != 0700 {
		_ = f.Close()
		return nil, errors.Join(ErrNativeVolume, err)
	}
	if err = unix.Fsync(parent); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &fixedProjector{file: f, path: path, private: bytes.Clone(private), node: [32]byte(private.Public().(ed25519.PublicKey))}, nil
}

func privateProjectionInode(fd int, private bool) (projectionInode, error) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return projectionInode{}, err
	}
	if s.Mode&unix.S_IFMT != unix.S_IFDIR || private && (s.Uid != uint32(os.Geteuid()) || s.Mode&07777 != 0700) {
		return projectionInode{}, ErrNativeVolume
	}
	return projectionInode{Device: uint64(s.Dev), Inode: s.Ino, UID: s.Uid, Mode: s.Mode}, nil
}

func openProjectionChild(parent int, name string) (*os.File, error) {
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

func (p *fixedProjector) sourcePath(spec NativeSpec) string {
	return filepath.Join(p.path, FixedNativeName(spec.Scope), "data")
}

func (p *fixedProjector) checkAnchor() error {
	fd, err := unix.Openat2(unix.AT_FDCWD, p.path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	a, err := privateProjectionInode(int(p.file.Fd()), true)
	if err != nil {
		return err
	}
	b, err := privateProjectionInode(fd, true)
	if err != nil || a != b {
		return errors.Join(ErrNativeVolume, err)
	}
	return nil
}

func projectionMarker(slot *os.File) (projectionOwner, error) {
	fd, err := unix.Openat(int(slot.Fd()), "owner.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return projectionOwner{}, err
	}
	f := os.NewFile(uintptr(fd), "owner.json")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 1 || info.Size() > 4096 {
		return projectionOwner{}, errors.Join(ErrNativeVolume, err)
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return projectionOwner{}, errors.Join(ErrNativeVolume, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return projectionOwner{}, err
	}
	owner, err := schema.Decode[projectionOwner](raw)
	canonical, _ := json.Marshal(owner)
	if err != nil || owner.Schema != 1 || owner.Spec == ([32]byte{}) || !bytes.Equal(raw, canonical) {
		return projectionOwner{}, ErrNativeVolume
	}
	return owner, nil
}

func sameProjectionInode(a, b projectionInode, sameBoot bool) bool {
	return a.Inode == b.Inode && a.UID == b.UID && a.Mode == b.Mode && (!sameBoot || a.Device == b.Device)
}

// stage publishes an already complete private slot with RENAME_NOREPLACE.
// A foreign/partial FINAL slot is never adopted or repaired. Temporary slots
// are in this manager's reserved namespace and contain no source mount.
func (p *fixedProjector) stage(spec NativeSpec) (projectionOwner, error) {
	if spec.Validate() != nil || spec.Kind != "node-fixed" {
		return projectionOwner{}, ErrNativeVolume
	}
	if err := p.checkAnchor(); err != nil {
		return projectionOwner{}, err
	}
	name := FixedNativeName(spec.Scope)
	if slot, err := openProjectionChild(int(p.file.Fd()), name); err == nil {
		_ = slot.Close()
		// A fresh Apply has no original checkpoint yet. Existing published
		// slots belong only to checkpoint recovery, never initial adoption.
		return projectionOwner{}, ErrNativeVolume
	} else if !errors.Is(err, unix.ENOENT) {
		return projectionOwner{}, err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return projectionOwner{}, err
	}
	tmp := ".tmp-" + name + "-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(int(p.file.Fd()), tmp, 0700); err != nil {
		return projectionOwner{}, err
	}
	slot, err := openProjectionChild(int(p.file.Fd()), tmp)
	if err != nil {
		return projectionOwner{}, err
	}
	defer slot.Close()
	// Do not recursively delete after failure. recoverStaging later checks
	// exact known files/inodes and absence of any mount before cleanup.
	if err = unix.Mkdirat(int(slot.Fd()), "data", 0700); err != nil {
		return projectionOwner{}, err
	}
	target, err := openProjectionChild(int(slot.Fd()), "data")
	if err != nil {
		return projectionOwner{}, err
	}
	defer target.Close()
	a, err := privateProjectionInode(int(slot.Fd()), true)
	if err != nil {
		return projectionOwner{}, err
	}
	b, err := privateProjectionInode(int(target.Fd()), true)
	if err != nil {
		return projectionOwner{}, err
	}
	owner := projectionOwner{Schema: 1, Spec: projectionSpec(spec), Slot: a, Target: b}
	raw, _ := json.Marshal(owner)
	fd, err := unix.Openat(int(slot.Fd()), "owner.json", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return projectionOwner{}, err
	}
	marker := os.NewFile(uintptr(fd), "owner.json")
	n, writeErr := marker.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = marker.Sync()
	}
	writeErr = errors.Join(writeErr, marker.Close())
	if writeErr != nil {
		return projectionOwner{}, writeErr
	}
	boot, namespace, err := nodestorage.NativeContext()
	if err != nil {
		return projectionOwner{}, err
	}
	if err = p.writeProjectionEpoch(slot, projectionEpoch{Schema: 1, Spec: owner.Spec, Boot: boot, Namespace: namespace}); err != nil {
		return projectionOwner{}, err
	}
	if err = target.Sync(); err != nil {
		return projectionOwner{}, err
	}
	if err = slot.Sync(); err != nil {
		return projectionOwner{}, err
	}
	if err = unix.Renameat2(int(p.file.Fd()), tmp, int(p.file.Fd()), name, unix.RENAME_NOREPLACE); err != nil {
		return projectionOwner{}, err
	}
	if err = p.file.Sync(); err != nil {
		return projectionOwner{}, err
	}
	return owner, nil
}

func projectionEpochBytes(e projectionEpoch) []byte {
	e.Signature = nil
	raw, _ := json.Marshal(e)
	return append([]byte("mydc-fixed-projection-epoch-1\x00"), raw...)
}

func (p *fixedProjector) readProjectionEpoch(slot *os.File) (projectionEpoch, error) {
	fd, err := unix.Openat(int(slot.Fd()), "epoch.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return projectionEpoch{}, err
	}
	f := os.NewFile(uintptr(fd), "epoch.json")
	defer f.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size <= 0 || st.Size > 4096 {
		return projectionEpoch{}, errors.Join(ErrNativeVolume, err)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return projectionEpoch{}, err
	}
	e, err := schema.Decode[projectionEpoch](raw)
	canonical, _ := json.Marshal(e)
	if err != nil || !bytes.Equal(raw, canonical) || e.Schema != 1 || e.Spec == ([32]byte{}) || e.Boot == ([32]byte{}) || e.Namespace == ([32]byte{}) || !ed25519.Verify(p.node[:], projectionEpochBytes(e), e.Signature) {
		return e, ErrNativeVolume
	}
	return e, nil
}

func removeEpochNext(slot *os.File) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(slot.Fd()), "epoch.next", &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 {
		return errors.Join(ErrNativeVolume, err)
	}
	return unix.Unlinkat(int(slot.Fd()), "epoch.next", 0)
}

func (p *fixedProjector) writeProjectionEpoch(slot *os.File, e projectionEpoch) error {
	if err := removeEpochNext(slot); err != nil {
		return err
	}
	e.Signature = ed25519.Sign(p.private, projectionEpochBytes(e))
	raw, _ := json.Marshal(e)
	fd, err := unix.Openat(int(slot.Fd()), "epoch.next", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "epoch.next")
	n, err := f.Write(raw)
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = unix.Renameat(int(slot.Fd()), "epoch.next", int(slot.Fd()), "epoch.json"); err != nil {
		return err
	}
	return slot.Sync()
}

// Keep the LAST current native namespace, not merely the initial registration
// boot. Otherwise Boot1 -> Boot2/NS2 -> Boot2/NS3 could falsely close a mount
// still alive in NS2. This is a native observation fence, not another writer.
func (p *fixedProjector) pinProjectionEpoch(slot *os.File, spec [32]byte, allowNewBoot bool) error {
	e, err := p.readProjectionEpoch(slot)
	if err != nil {
		return err
	}
	boot, ns, err := nodestorage.NativeContext()
	if err != nil {
		return err
	}
	if e.Spec != spec || e.Boot == boot && e.Namespace != ns {
		return ErrNativeVolume
	}
	if e.Boot != boot && allowNewBoot {
		return p.writeProjectionEpoch(slot, projectionEpoch{Schema: 1, Spec: spec, Boot: boot, Namespace: ns})
	}
	return nil
}

func mountCoordinate(fd int) (uint64, error) {
	var stat unix.Statx_t
	err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &stat)
	if err != nil || stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return 0, errors.Join(ErrNativeVolume, err)
	}
	return stat.Mnt_id, nil
}

func (p *fixedProjector) slot(spec NativeSpec, owner projectionOwner, sameBoot bool) (*os.File, *os.File, bool, error) {
	if err := p.checkAnchor(); err != nil {
		return nil, nil, false, err
	}
	slot, err := openProjectionChild(int(p.file.Fd()), FixedNativeName(spec.Scope))
	if err != nil {
		return nil, nil, false, err
	}
	fail := func(e error) (*os.File, *os.File, bool, error) { _ = slot.Close(); return nil, nil, false, e }
	actual, err := projectionMarker(slot)
	if err != nil || actual != owner || owner.Spec != projectionSpec(spec) {
		return fail(errors.Join(ErrNativeVolume, err))
	}
	st, err := privateProjectionInode(int(slot.Fd()), true)
	if err != nil || !sameProjectionInode(st, owner.Slot, sameBoot) {
		return fail(errors.Join(ErrNativeVolume, err))
	}
	target, err := openProjectionChild(int(slot.Fd()), "data")
	if err != nil {
		return fail(err)
	}
	parentMount, err := mountCoordinate(int(slot.Fd()))
	if err != nil {
		_ = target.Close()
		return fail(err)
	}
	targetMount, err := mountCoordinate(int(target.Fd()))
	if err != nil {
		_ = target.Close()
		return fail(err)
	}
	mounted := parentMount != targetMount
	if !mounted {
		st, err := privateProjectionInode(int(target.Fd()), true)
		if err != nil || !sameProjectionInode(st, owner.Target, sameBoot) {
			_ = target.Close()
			return fail(errors.Join(ErrNativeVolume, err))
		}
	}
	return slot, target, mounted, nil
}

func (p *fixedProjector) verifyData(spec NativeSpec, original nodestorage.Directory) error {
	h, err := nodestorage.OpenDirectory(p.sourcePath(spec))
	if err != nil {
		return err
	}
	defer h.Close()
	if !h.Identity().SameData(original) {
		return ErrNativeVolume
	}
	return nil
}

func (p *fixedProjector) ensure(spec NativeSpec, owner projectionOwner, source *nodestorage.DirectoryHandle, original nodestorage.Directory) error {
	if source == nil || !source.Identity().MatchesOriginal(original) {
		return ErrNativeVolume
	}
	sameBoot := source.Identity().Boot == original.Boot
	slot, target, mounted, err := p.slot(spec, owner, sameBoot)
	if err != nil {
		return err
	}
	defer slot.Close()
	defer target.Close()
	if err = p.pinProjectionEpoch(slot, owner.Spec, true); err != nil {
		return err
	}
	if mounted {
		return p.verifyData(spec, original)
	}
	// The source descriptor identifies the already verified original inode.
	// No PID/descriptor path is persisted in Docker's container configuration.
	tree, err := unix.OpenTree(source.FD(), "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return err
	}
	defer unix.Close(tree)
	if err = unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Propagation: unix.MS_PRIVATE}); err != nil {
		return err
	}
	if err = unix.MoveMount(tree, "", int(target.Fd()), "", unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return err
	}
	return p.verifyData(spec, original)
}

func exactSlotEntries(slot *os.File, marker bool) error {
	directory, err := openProjectionChild(int(slot.Fd()), ".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(5)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	for _, e := range entries {
		if e.Name() != "data" && (!marker || e.Name() != "owner.json" && e.Name() != "epoch.json" && e.Name() != "epoch.next") {
			return ErrNativeVolume
		}
	}
	if len(entries) > 4 {
		return ErrNativeVolume
	}
	return nil
}

// remove only unmounts this exact private projection; it never traverses or
// unlinks source data. EBUSY is unresolved, never converted to lazy unmount.
func (p *fixedProjector) remove(spec NativeSpec, owner projectionOwner, original nodestorage.Directory, sameBoot bool) error {
	if err := p.checkAnchor(); err != nil {
		return err
	}
	slot, err := openProjectionChild(int(p.file.Fd()), FixedNativeName(spec.Scope))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer slot.Close()
	st, err := privateProjectionInode(int(slot.Fd()), true)
	if err != nil || !sameProjectionInode(st, owner.Slot, sameBoot) || owner.Spec != projectionSpec(spec) {
		return errors.Join(ErrNativeVolume, err)
	}
	actual, markerErr := projectionMarker(slot)
	if markerErr != nil && !errors.Is(markerErr, unix.ENOENT) {
		return markerErr
	}
	if markerErr == nil && actual != owner {
		return ErrNativeVolume
	}
	target, openErr := openProjectionChild(int(slot.Fd()), "data")
	if openErr != nil && !errors.Is(openErr, unix.ENOENT) {
		return openErr
	}
	if openErr == nil && markerErr != nil {
		_ = target.Close()
		return ErrNativeVolume
	}
	if openErr == nil {
		if err = p.pinProjectionEpoch(slot, owner.Spec, false); err != nil {
			_ = target.Close()
			return err
		}
	} else if _, e := p.readProjectionEpoch(slot); e == nil {
		if err = p.pinProjectionEpoch(slot, owner.Spec, false); err != nil {
			return err
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	mounted := false
	if openErr == nil {
		a, e1 := mountCoordinate(int(slot.Fd()))
		b, e2 := mountCoordinate(int(target.Fd()))
		if e1 != nil || e2 != nil {
			_ = target.Close()
			return errors.Join(ErrNativeVolume, e1, e2)
		}
		mounted = a != b
		if !mounted {
			st, err := privateProjectionInode(int(target.Fd()), true)
			if err != nil || !sameProjectionInode(st, owner.Target, sameBoot) {
				_ = target.Close()
				return errors.Join(ErrNativeVolume, err)
			}
		}
	}
	if mounted {
		if err = p.verifyData(spec, original); err != nil {
			_ = target.Close()
			return err
		}
		_ = target.Close() // our own open mount FD must not make umount busy
		if err = unix.Unmount(p.sourcePath(spec), 0); err != nil {
			return err
		}
		target, err = openProjectionChild(int(slot.Fd()), "data")
		if err != nil {
			return err
		}
		st, e := privateProjectionInode(int(target.Fd()), true)
		if e != nil || !sameProjectionInode(st, owner.Target, sameBoot) {
			_ = target.Close()
			return errors.Join(ErrNativeVolume, e)
		}
	}
	if target != nil {
		_ = target.Close()
	}
	if err = exactSlotEntries(slot, markerErr == nil); err != nil {
		return err
	}
	if err = unix.Unlinkat(int(slot.Fd()), "data", unix.AT_REMOVEDIR); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err = removeEpochNext(slot); err != nil {
		return err
	}
	if err = unix.Unlinkat(int(slot.Fd()), "epoch.json", 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if markerErr == nil {
		if err = unix.Unlinkat(int(slot.Fd()), "owner.json", 0); err != nil {
			return err
		}
	}
	if err = slot.Sync(); err != nil {
		return err
	}
	if err = unix.Unlinkat(int(p.file.Fd()), FixedNativeName(spec.Scope), unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return p.file.Sync()
}

// Before the source checkpoint no mount may have been dispatched. Reconcile
// staging using the private marker and authoritative mount coordinates, not a
// missing mount observation used as evidence about an arbitrary accepted RPC.
func (p *fixedProjector) recoverStaging(spec NativeSpec) error {
	if err := p.checkAnchor(); err != nil {
		return err
	}
	prefix := ".tmp-" + FixedNativeName(spec.Scope) + "-"
	directory, err := openProjectionChild(int(p.file.Fd()), ".")
	if err != nil {
		return err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(2049)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(entries) > 2048 {
		return ErrNativeVolume
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != FixedNativeName(spec.Scope) && !strings.HasPrefix(name, prefix) {
			continue
		}
		slot, err := openProjectionChild(int(p.file.Fd()), name)
		if err != nil {
			return err
		}
		owner, markerErr := projectionMarker(slot)
		if markerErr != nil && (!strings.HasPrefix(name, prefix) || !errors.Is(markerErr, unix.ENOENT)) {
			_ = slot.Close()
			return markerErr
		}
		if markerErr == nil && owner.Spec != projectionSpec(spec) {
			_ = slot.Close()
			return ErrNativeVolume
		}
		// An interrupted temporary slot can lack its marker, but an existing
		// epoch must still be signed for this exact original declaration.
		if err = p.pinProjectionEpoch(slot, projectionSpec(spec), false); err != nil && !(strings.HasPrefix(name, prefix) && errors.Is(err, unix.ENOENT)) {
			_ = slot.Close()
			return err
		}
		if err = exactSlotEntries(slot, markerErr == nil); err != nil {
			_ = slot.Close()
			return err
		}
		target, openErr := openProjectionChild(int(slot.Fd()), "data")
		if openErr != nil && !errors.Is(openErr, unix.ENOENT) {
			_ = slot.Close()
			return openErr
		}
		if openErr == nil {
			a, e1 := mountCoordinate(int(slot.Fd()))
			b, e2 := mountCoordinate(int(target.Fd()))
			_, e3 := privateProjectionInode(int(target.Fd()), true)
			_ = target.Close()
			if e1 != nil || e2 != nil || e3 != nil || a != b {
				_ = slot.Close()
				return errors.Join(ErrNativeVolume, e1, e2, e3)
			}
			if err = unix.Unlinkat(int(slot.Fd()), "data", unix.AT_REMOVEDIR); err != nil {
				_ = slot.Close()
				return err
			}
		}
		if name == FixedNativeName(spec.Scope) {
			// Preserve the owner marker until the final name has disappeared.
			// A crash while removing metadata then leaves an owned temporary
			// slot, never an unverifiable empty final registration path.
			var random [16]byte
			if _, err = rand.Read(random[:]); err != nil {
				_ = slot.Close()
				return err
			}
			tmp := prefix + hex.EncodeToString(random[:])
			if err = unix.Renameat2(int(p.file.Fd()), name, int(p.file.Fd()), tmp, unix.RENAME_NOREPLACE); err != nil {
				_ = slot.Close()
				return err
			}
			name = tmp
			if err = p.file.Sync(); err != nil {
				_ = slot.Close()
				return err
			}
		}
		if markerErr == nil {
			err = unix.Unlinkat(int(slot.Fd()), "owner.json", 0)
		}
		if err == nil {
			err = removeEpochNext(slot)
		}
		if err == nil {
			err = unix.Unlinkat(int(slot.Fd()), "epoch.json", 0)
			if errors.Is(err, unix.ENOENT) {
				err = nil
			}
		}
		if err == nil {
			err = slot.Sync()
		}
		_ = slot.Close()
		if err != nil {
			return err
		}
		if err = unix.Unlinkat(int(p.file.Fd()), name, unix.AT_REMOVEDIR); err != nil {
			return err
		}
	}
	return p.file.Sync()
}
