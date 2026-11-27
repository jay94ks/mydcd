// SPDX-License-Identifier: Apache-2.0

package nodestorage

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ext4's Linux 6.6 UAPI: _IOR('f',44,struct fsuuid), whose fixed header is two
// uint32s. The UUID follows that header. No block-device read/global command or
// directory mutation is needed. Other filesystems are explicitly unsupported.
const ext4GetFSUUID = 0x8008662c

type DirectoryHandle struct {
	file     *os.File
	path     string
	identity Directory
}

func OpenDirectory(p string) (*DirectoryHandle, error) {
	if !cleanPath(p) {
		return nil, ErrStorage
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	return directoryHandle(fd, p)
}

func OpenWithin(root *DirectoryHandle, p string) (*DirectoryHandle, error) {
	if root == nil || root.file == nil || !cleanPath(p) || p == root.path || !within(root.path, p) {
		return nil, ErrStorage
	}
	relative := strings.TrimPrefix(p, root.path+"/")
	if relative == "" || relative == "." || path.Clean(relative) != relative {
		return nil, ErrStorage
	}
	fd, err := unix.Openat2(int(root.file.Fd()), relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV})
	if err != nil {
		return nil, err
	}
	h, err := directoryHandle(fd, p)
	if err != nil {
		return nil, err
	}
	if h.identity.UUID != root.identity.UUID || h.identity.MountID != root.identity.MountID || h.identity.Namespace != root.identity.Namespace || h.identity.DeviceMajor != root.identity.DeviceMajor || h.identity.DeviceMinor != root.identity.DeviceMinor {
		_ = h.Close()
		return nil, ErrStorage
	}
	return h, nil
}

func directoryHandle(fd int, p string) (*DirectoryHandle, error) {
	f := os.NewFile(uintptr(fd), p)
	d, err := identifyDirectory(fd, p)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &DirectoryHandle{file: f, path: p, identity: d}, nil
}
func (h *DirectoryHandle) Identity() Directory { return ownDirectory(h.identity) }
func (h *DirectoryHandle) Close() error {
	if h == nil || h.file == nil {
		return nil
	}
	return h.file.Close()
}

// FD is node-local native adapter input. It is never serialized into app.yaml
// or a shared permit. A future mount uses this exact retained inode, not a new
// resolution of a mutable pathname.
func (h *DirectoryHandle) FD() int { return int(h.file.Fd()) }

// Release hands the held descriptor to the caller, who closes it; the
// handle no longer owns it and Close becomes a no-op.
func (h *DirectoryHandle) Release() *os.File {
	f := h.file
	h.file = nil
	return f
}

func identifyDirectory(fd int, p string) (Directory, error) {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return Directory{}, err
	}
	if fs.Type != unix.EXT4_SUPER_MAGIC {
		return Directory{}, ErrUnsupported
	}
	var uuid struct {
		Length, Flags uint32
		Bytes         [16]byte
	}
	uuid.Length = 16
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), ext4GetFSUUID, uintptr(unsafe.Pointer(&uuid)))
	runtime.KeepAlive(&uuid)
	if errno != 0 {
		return Directory{}, errors.Join(ErrUnsupported, errno)
	}
	if uuid.Length != 16 || uuid.Flags != 0 || uuid.Bytes == ([16]byte{}) {
		return Directory{}, ErrUnsupported
	}
	handle, mount, err := unix.NameToHandleAt(fd, ".", 0)
	if err != nil {
		return Directory{}, errors.Join(ErrUnsupported, err)
	}
	var stat unix.Statx_t
	if err = unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID, &stat); err != nil {
		return Directory{}, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mask&unix.STATX_INO == 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR || mount <= 0 || uint64(mount) != stat.Mnt_id {
		return Directory{}, ErrUnsupported
	}
	boot, ns, err := NativeContext()
	if err != nil {
		return Directory{}, err
	}
	internal, err := internalFilesystemPath(p, stat.Mnt_id, stat.Dev_major, stat.Dev_minor)
	if err != nil {
		return Directory{}, err
	}
	d := Directory{Filesystem: "ext4", FilesystemPath: internal, UUID: uuid.Bytes, HandleType: handle.Type(), Handle: append([]byte(nil), handle.Bytes()...), Inode: stat.Ino, DeviceMajor: stat.Dev_major, DeviceMinor: stat.Dev_minor, Boot: boot, Namespace: ns, MountID: stat.Mnt_id}
	return d, d.Validate()
}

// NativeContext is shared by read-back and cleanup. A same-boot namespace
// change cannot prove closure of a mount that may still live in the old one.
func NativeContext() (boot, namespace [32]byte, err error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || len(strings.TrimSpace(string(raw))) != 36 {
		return boot, namespace, errors.Join(err, ErrStorage)
	}
	boot = sha256.Sum256(append([]byte("sfc-linux-boot-1/"), raw...))
	var st unix.Stat_t
	if err = unix.Stat("/proc/self/ns/mnt", &st); err != nil {
		return boot, namespace, err
	}
	namespace = sha256.Sum256([]byte(fmt.Sprintf("sfc-storage-mount-namespace-1/%x/%d/%d", boot, st.Dev, st.Ino)))
	return boot, namespace, nil
}

func mountPath(raw string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			b.WriteByte(raw[i])
			continue
		}
		if i+3 >= len(raw) {
			return "", ErrStorage
		}
		switch raw[i+1 : i+4] {
		case "040":
			b.WriteByte(' ')
		case "011":
			b.WriteByte('\t')
		case "012":
			b.WriteByte('\n')
		case "134":
			b.WriteByte('\\')
		default:
			return "", ErrStorage
		}
		i += 3
	}
	p := b.String()
	if !filesystemPath(p) {
		return "", ErrStorage
	}
	return p, nil
}

// Bind mounts can give two unrelated host paths to the same backing subtree.
// The mount's filesystem-root coordinate exposes physical overlap without
// opening a block device or escaping the declared root by open_by_handle_at.
func internalFilesystemPath(p string, id uint64, major, minor uint32) (string, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	if len(raw) > 4<<20 {
		return "", ErrStorage
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		mountID, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || mountID != id {
			continue
		}
		if fields[2] != fmt.Sprintf("%d:%d", major, minor) {
			return "", ErrStorage
		}
		separator := -1
		for i, f := range fields {
			if f == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+3 >= len(fields) || fields[separator+1] != "ext4" {
			return "", ErrUnsupported
		}
		root, err := mountPath(fields[3])
		if err != nil {
			return "", err
		}
		point, err := mountPath(fields[4])
		if err != nil {
			return "", err
		}
		if point != "/" && !within(point, p) {
			return "", ErrStorage
		}
		relative := strings.TrimPrefix(p, point)
		if point == "/" {
			relative = strings.TrimPrefix(p, "/")
		}
		return path.Join(root, relative), nil
	}
	return "", ErrStorage
}
