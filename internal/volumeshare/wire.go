// SPDX-License-Identifier: Apache-2.0

package volumeshare

// wireRequest is the JSON header of one VolumeFS operation (SFCP purpose
// 24, tag 1). Write data travels in the frame's data extension, never here.
type wireRequest struct {
	Schema  uint8
	Op      string
	Session uint64 `json:",omitempty"`
	Volume  string `json:",omitempty"` // mount only

	Handle  Handle `json:",omitempty"`
	Dir     Handle `json:",omitempty"`
	NewDir  Handle `json:",omitempty"`
	Name    string `json:",omitempty"`
	NewName string `json:",omitempty"`
	Target  string `json:",omitempty"`
	Flags   uint32 `json:",omitempty"`
	Mode    uint32 `json:",omitempty"`
	Caller  Caller
	Set     *SetAttr `json:",omitempty"`

	File     FileID `json:",omitempty"`
	Off      uint64 `json:",omitempty"`
	Size     uint32 `json:",omitempty"`
	Datasync bool   `json:",omitempty"`
	Owner    uint64 `json:",omitempty"`
	Lock     *Lock  `json:",omitempty"`
	Flock    bool   `json:",omitempty"`
	Cookie   uint64 `json:",omitempty"`
	Max      int    `json:",omitempty"`
}

// wireReply is the JSON answer (tag 1); read data is in the extension.
type wireReply struct {
	Schema  uint8
	Errno   uint32     `json:",omitempty"`
	Session uint64     `json:",omitempty"`
	Root    Handle     `json:",omitempty"`
	Entry   *Entry     `json:",omitempty"`
	Attr    *Attr      `json:",omitempty"`
	Target  string     `json:",omitempty"`
	File    FileID     `json:",omitempty"`
	N       uint32     `json:",omitempty"`
	Rows    []DirEntry `json:",omitempty"`
	StatFs  *StatFs    `json:",omitempty"`
	Lock    *Lock      `json:",omitempty"`
}

// Operations. Retry-safe ones may be resent when a reply is lost; the
// others report EIO instead, because their effect is unknown.
const (
	opMount    = "mount"
	opPing     = "ping"
	opUnmount  = "unmount"
	opLookup   = "lookup"
	opGetAttr  = "getattr"
	opSetAttr  = "setattr"
	opReadlink = "readlink"
	opSymlink  = "symlink"
	opMkdir    = "mkdir"
	opUnlink   = "unlink"
	opRmdir    = "rmdir"
	opRename   = "rename"
	opLink     = "link"
	opReadDir  = "readdir"
	opStatFs   = "statfs"
	opOpen     = "open"
	opCreate   = "create"
	opRead     = "read"
	opWrite    = "write"
	opFsync    = "fsync"
	opClose    = "close"
	opGetLk    = "getlk"
	opSetLk    = "setlk"
	opRelOwner = "release-owner"
)

var retrySafe = map[string]bool{
	opPing: true, opLookup: true, opGetAttr: true, opSetAttr: true, opReadlink: true,
	opReadDir: true, opStatFs: true, opRead: true, opWrite: true, opFsync: true, opGetLk: true,
}
