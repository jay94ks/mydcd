// SPDX-License-Identifier: Apache-2.0

// Package nodestorage owns declared node storage roots and their original
// directory identities. Shared transitions perform no filesystem I/O.
package nodestorage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

var ErrStorage = errors.New("node storage ownership, identity or revision conflict")
var ErrUnsupported = errors.New("filesystem does not provide a supported stable directory identity")

const maxRoots = 1024
const maxVolumes = 256

func identifier(s string) bool {
	if len(s) < 1 || len(s) > 63 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func cleanPath(p string) bool {
	return p != "/" && filesystemPath(p)
}

func ValidateRootPath(p string) error {
	if !cleanPath(p) {
		return ErrStorage
	}
	return nil
}

func filesystemPath(p string) bool {
	return len(p) >= 1 && len(p) <= 4096 && utf8.ValidString(p) && strings.HasPrefix(p, "/") && path.Clean(p) == p && !strings.ContainsAny(p, "\x00\r\n")
}

func within(parent, child string) bool {
	return parent == "/" && strings.HasPrefix(child, "/") || child == parent || strings.HasPrefix(child, parent+"/")
}

// Reference excludes mutable ACL/capacity policy. A policy change never
// retargets the original filesystem or invents a new registration generation.
type Reference struct {
	Cluster    [32]byte
	Node       string
	Key        [32]byte
	ID         string
	Generation uint64
	Path       string
}

func (r Reference) Validate() error {
	if r.Cluster == ([32]byte{}) || !identifier(r.Node) || r.Key == ([32]byte{}) || !identifier(r.ID) || r.Generation == 0 || !cleanPath(r.Path) {
		return ErrStorage
	}
	return nil
}

func (r Reference) Digest() [32]byte {
	raw, _ := json.Marshal(r)
	return sha256.Sum256(append([]byte("mydc-storage-root-ref-1\x00"), raw...))
}

// Directory binds an actual filesystem and exported inode generation, not just
// a path or a recyclable device/inode number. Volatile coordinates are retained
// for same-boot/native mount verification, not used as a permanent disk ID.
type Directory struct {
	Filesystem               string
	FilesystemPath           string
	UUID                     [16]byte
	HandleType               int32
	Handle                   []byte
	Inode                    uint64
	DeviceMajor, DeviceMinor uint32
	Boot, Namespace          [32]byte
	MountID                  uint64
}

func (d Directory) Validate() error {
	if d.Filesystem != "ext4" || !filesystemPath(d.FilesystemPath) || d.UUID == ([16]byte{}) || d.HandleType <= 0 || len(d.Handle) < 8 || len(d.Handle) > 128 || d.Inode == 0 || d.Boot == ([32]byte{}) || d.Namespace == ([32]byte{}) || d.MountID == 0 {
		return ErrStorage
	}
	return nil
}

func (d Directory) SameData(other Directory) bool {
	return d.Validate() == nil && other.Validate() == nil && d.Filesystem == other.Filesystem && d.FilesystemPath == other.FilesystemPath && d.UUID == other.UUID && d.HandleType == other.HandleType && bytes.Equal(d.Handle, other.Handle) && d.Inode == other.Inode
}

func (d Directory) SameMount(other Directory) bool {
	return d.SameData(other) && d.Boot == other.Boot && d.Namespace == other.Namespace && d.MountID == other.MountID && d.DeviceMajor == other.DeviceMajor && d.DeviceMinor == other.DeviceMinor
}

func ownDirectory(d Directory) Directory { d.Handle = slices.Clone(d.Handle); return d }

// RootFact attests initial native registration. It is not current serving or
// Start permission; every consumer still needs a current quorum permit and a
// fresh local read-back against this same original identity.
type RootFact struct {
	Schema    uint8
	Root      Reference
	Directory Directory
	Signature []byte
}

func RootFactBytes(f RootFact) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("mydc-storage-root-fact-1\x00"), raw...)
}
func (f RootFact) Verify() error {
	if f.Schema != 1 || f.Root.Validate() != nil || f.Directory.Validate() != nil || !ed25519.Verify(ed25519.PublicKey(f.Root.Key[:]), RootFactBytes(f), f.Signature) {
		return ErrStorage
	}
	return nil
}
func ownFact(f RootFact) RootFact {
	f.Directory = ownDirectory(f.Directory)
	f.Signature = slices.Clone(f.Signature)
	return f
}

type RootClosed struct {
	Schema             uint8
	Root               Reference
	NoUsers, NoPending bool
	Signature          []byte
}

func RootClosedBytes(f RootClosed) []byte {
	f.Signature = nil
	raw, _ := json.Marshal(f)
	return append([]byte("mydc-storage-root-closed-1\x00"), raw...)
}
func (f RootClosed) Verify() error {
	if f.Schema != 1 || f.Root.Validate() != nil || !f.NoUsers || !f.NoPending || !ed25519.Verify(ed25519.PublicKey(f.Root.Key[:]), RootClosedBytes(f), f.Signature) {
		return ErrStorage
	}
	return nil
}

// FixedDirectory is an immutable tenant registration input. The path must
// already exist strictly within the declared root and on the same filesystem.
// It grants no migration, creation, recursive deletion or activation authority.
type FixedDirectory struct {
	Root          RootFact
	RootDirectory Directory
	Path          string
	Directory     Directory
}

// FixedSelection is known before native leaf discovery. It binds an accepted
// registration to the original signed root and preexisting child path, never
// to a guessed inode or a synthetic NativeReady.
type FixedSelection struct {
	Root RootFact
	Path string
}

func (s FixedSelection) Validate() error {
	if s.Root.Verify() != nil || !cleanPath(s.Path) || s.Path == s.Root.Root.Path || !within(s.Root.Root.Path, s.Path) {
		return ErrStorage
	}
	return nil
}
func (s FixedSelection) Clone() FixedSelection { s.Root = ownFact(s.Root); return s }
func (s FixedSelection) Digest() [32]byte {
	raw, _ := json.Marshal(s)
	return sha256.Sum256(append([]byte("mydc-fixed-selection-1\x00"), raw...))
}
func (s FixedSelection) FilesystemPath() string {
	return path.Join(s.Root.Directory.FilesystemPath, strings.TrimPrefix(s.Path, s.Root.Root.Path+"/"))
}
func (s FixedSelection) Overlaps(other FixedSelection) bool {
	a, b := s.Root, other.Root
	return s.Validate() == nil && other.Validate() == nil && a.Root.Node == b.Root.Node && a.Root.Key == b.Root.Key && a.Directory.Filesystem == b.Directory.Filesystem && a.Directory.UUID == b.Directory.UUID && (within(s.FilesystemPath(), other.FilesystemPath()) || within(other.FilesystemPath(), s.FilesystemPath()))
}
func (d FixedDirectory) Selection() FixedSelection {
	return FixedSelection{Root: ownFact(d.Root), Path: d.Path}
}

func (d FixedDirectory) Validate() error {
	if d.Root.Verify() != nil || !cleanPath(d.Path) || d.Path == d.Root.Root.Path || !within(d.Root.Root.Path, d.Path) || !d.RootDirectory.MatchesOriginal(d.Root.Directory) || d.Directory.Validate() != nil || d.Directory.Filesystem != d.RootDirectory.Filesystem || d.Directory.UUID != d.RootDirectory.UUID || d.Directory.Boot != d.RootDirectory.Boot || d.Directory.Namespace != d.RootDirectory.Namespace || d.Directory.MountID != d.RootDirectory.MountID || d.Directory.DeviceMajor != d.RootDirectory.DeviceMajor || d.Directory.DeviceMinor != d.RootDirectory.DeviceMinor {
		return ErrStorage
	}
	if d.Directory.FilesystemPath != path.Join(d.RootDirectory.FilesystemPath, strings.TrimPrefix(d.Path, d.Root.Root.Path+"/")) {
		return ErrStorage
	}
	return nil
}
func (d FixedDirectory) Clone() FixedDirectory {
	d.Root = ownFact(d.Root)
	d.RootDirectory = ownDirectory(d.RootDirectory)
	d.Directory = ownDirectory(d.Directory)
	return d
}

func (d FixedDirectory) Digest() [32]byte {
	raw, _ := json.Marshal(d)
	return sha256.Sum256(append([]byte("mydc-fixed-directory-1\x00"), raw...))
}

// Overlaps compares backing filesystem coordinates as well as exported inode
// identity. Lexically unrelated bind aliases may still refer to one subtree.
func (d Directory) Overlaps(other Directory) bool {
	return d.Validate() == nil && other.Validate() == nil && d.Filesystem == other.Filesystem && d.UUID == other.UUID && (within(d.FilesystemPath, other.FilesystemPath) || within(other.FilesystemPath, d.FilesystemPath) || d.HandleType == other.HandleType && bytes.Equal(d.Handle, other.Handle))
}

func (d Directory) MatchesOriginal(original Directory) bool {
	return d.SameData(original) && (d.Boot != original.Boot || d.SameMount(original))
}
