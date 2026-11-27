// SPDX-License-Identifier: Apache-2.0

package control

import (
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
)

// NodeDiskOp is one disk change a system administrator asks of one server
// (devel/proposals/node-disk-management.md §4). It never goes through Raft:
// the server checks the session at a quorum read, keeps the operation in its
// own journal and records the outcome in its signed event log.
//
// Action format makes Part an ext4 filesystem; when Part is the whole disk
// (Part == Disk) it first writes a new GPT table with one partition. mount
// mounts Part's ext4 filesystem at MountPath (empty: the default under
// /var/lib/sfc-disks) and remembers it for the next start; unmount undoes
// that. forget drops the record of a recorded disk that is gone. status
// reads an earlier operation by its ID.
//
// The fence fields are what the screen showed. The server refuses when the
// device no longer matches them: Serial/WWN/Size of the disk, TableID of its
// partition table and UUID of the part's filesystem, each when not empty.
type NodeDiskOp struct {
	Operation, Node, Action string
	Disk, Part              string `json:",omitempty"`
	Serial, WWN             string `json:",omitempty"`
	Size                    uint64 `json:",omitempty"`
	TableID, UUID           string `json:",omitempty"`
	MountPath, Label        string `json:",omitempty"`
}

var NodeDiskActions = []string{"format", "mount", "unmount", "forget", "status"}

// NodeDiskMountBase is the default parent of disk mounts.
const NodeDiskMountBase = "/var/lib/sfc-disks"

func diskDeviceName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func diskText(s string, limit int) bool {
	if len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (o NodeDiskOp) Valid() bool {
	if !lifecycle.ValidID(o.Operation) || !lifecycle.ValidID(o.Node) {
		return false
	}
	switch o.Action {
	case "status":
		return o == NodeDiskOp{Operation: o.Operation, Node: o.Node, Action: o.Action}
	case "format", "mount", "unmount", "forget":
	default:
		return false
	}
	ok := diskDeviceName(o.Disk) && diskDeviceName(o.Part) && strings.HasPrefix(o.Part, o.Disk) && diskText(o.Serial, 128) && diskText(o.WWN, 128) && diskText(o.TableID, 64) && diskText(o.UUID, 64)
	switch o.Action {
	case "format":
		// ext4 labels are at most 16 bytes; a format names its device.
		ok = ok && o.MountPath == "" && len(o.Label) <= 16 && diskText(o.Label, 16) && o.Size > 0 && (o.Serial != "" || o.WWN != "")
	case "mount":
		ok = ok && o.Label == "" && o.UUID != "" && (o.MountPath == "" || ValidDiskMountPath(o.MountPath))
	case "unmount":
		ok = ok && o.Label == "" && o.MountPath == ""
	case "forget":
		// Drops the mount record of a disk that is gone (the screen's
		// 기록 지우기); the disk itself is not touched.
		ok = ok && o.Label == "" && o.MountPath == "" && o.UUID != "" && o.Size == 0 && o.TableID == ""
	}
	return ok
}

// systemMountPaths may never be a disk mount point nor contain one.
var systemMountPaths = []string{"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32", "/proc", "/root", "/run", "/sbin", "/snap", "/sys", "/tmp", "/usr", "/var/lib/docker", "/var/lib/sfe", "/var/lib/sfc", "/var/lib/containerd", "/var/log", "/var/cache", "/var/tmp"}

// ValidDiskMountPath accepts a clean absolute path that is not "/" and not
// in or above a system path. The server also refuses a path inside another
// mount or storage root, and one that exists and is not an empty directory.
func ValidDiskMountPath(path string) bool {
	if len(path) > 1024 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || !diskText(path, 1024) || strings.ContainsAny(path, " \t") {
		return false
	}
	for _, system := range systemMountPaths {
		if path == system || strings.HasPrefix(path, system+"/") || strings.HasPrefix(system, path+"/") {
			return false
		}
	}
	return path != "/var" && path != "/var/lib" && path != "/home" && path != "/opt" && path != "/srv" && path != "/mnt" && path != "/media"
}

// DefaultDiskMountPath is where a mount without MountPath goes.
func DefaultDiskMountPath(part string) string { return NodeDiskMountBase + "/" + part }

// NodeDiskRead is the server's authority for one disk operation: the
// session checked at a quorum read, the owner key and the open storage roots
// of that server (a format, mount or unmount never touches one).
type NodeDiskRead struct {
	Session                   access.Session
	Op                        NodeDiskOp
	Owner                     [32]byte
	At                        int64
	Index, MembersRoot, Epoch uint64
	RootsRevision             uint64
	RootPaths                 []string
}

// ReadNodeDisk authorizes a system administrator's disk operation on one
// installed server.
func (p Policy) ReadNodeDisk(s state.State, session access.Session, at int64, op NodeDiskOp) (NodeDiskRead, error) {
	current, err := p.Current(s)
	if err != nil {
		return NodeDiskRead{}, err
	}
	c, err := current.Catalog(s)
	if err != nil {
		return NodeDiskRead{}, err
	}
	if !op.Valid() || c.AuthorizeSession(session, p.Cluster, current.Issuer(session.Issuer), at, "", access.ManageCluster, "") != nil || !c.SystemAllowed(session.User) {
		return NodeDiskRead{}, access.ErrDenied
	}
	owner, err := current.nodeOwner(s, op.Node)
	if err != nil {
		return NodeDiskRead{}, err
	}
	roots, err := current.NodeStorage(s)
	if err != nil {
		return NodeDiskRead{}, err
	}
	paths := []string{}
	for _, root := range roots.Roots() {
		if root.Definition.Node == op.Node && root.Closed == nil {
			paths = append(paths, root.Definition.Path)
		}
	}
	return NodeDiskRead{Session: session, Op: op, Owner: owner, At: at, Index: s.Index(), MembersRoot: s.Object(MembersKey).Revision, Epoch: s.ModuleEpoch(), RootsRevision: s.Object(NodeStorageKey).Revision, RootPaths: paths}, nil
}

// NodeDiskResult is the server's journal row for one operation. State is
// running, done or failed; Step the last step reached. Code is a fixed
// reason (NodeDiskCodes); Error a bounded local detail.
type NodeDiskResult struct {
	Schema                         uint8
	Operation, Node, Action, User  string
	Disk, Part                     string `json:",omitempty"`
	State, Step                    string
	Code                           string `json:",omitempty"`
	Error                          string `json:",omitempty"`
	UUID, Device, MountPath, Label string `json:",omitempty"`
	StartedAt, FinishedAt          int64  `json:",omitempty"`
}

// NodeDiskCodes are the fixed refusal and failure reasons.
var NodeDiskCodes = []string{
	"system-disk",        // the disk holds "/": do it by hand on the server
	"busy",               // mounted, swap or held by LVM/dm-crypt/RAID
	"storage-root",       // a storage root is on it: drain and remove it first
	"changed",            // the device no longer matches what the screen showed
	"not-found",          // no such disk or part now
	"not-ext4",           // mount needs an ext4 filesystem
	"mount-path",         // the mount point is not allowed or not empty
	"not-managed",        // unmount of a mount sfcd did not make
	"in-use",             // unmount refused by the kernel (files open)
	"operation-conflict", // the ID is in use for another request
	"tool",               // mkfs.ext4 failed or is missing
	"io",                 // a device read/write failed
	"interrupted",        // sfcd stopped in the middle; see Step
}

func (r NodeDiskResult) Valid() bool {
	codeOK := r.Code == ""
	for _, c := range NodeDiskCodes {
		codeOK = codeOK || r.Code == c
	}
	return r.Schema == 1 && lifecycle.ValidID(r.Operation) && lifecycle.ValidID(r.Node) && (r.Action == "format" || r.Action == "mount" || r.Action == "unmount" || r.Action == "forget") && (r.State == "running" || r.State == "done" || r.State == "failed") && codeOK && (r.State == "failed") == (r.Code != "") && diskText(r.Error, 512) && diskText(r.Step, 32) && diskText(r.UUID, 64) && diskText(r.Device, 128) && diskText(r.MountPath, 1024) && diskText(r.Label, 16)
}
