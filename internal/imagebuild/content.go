// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"crypto/sha256"
	"slices"
)

type ContentQuery struct {
	Version [32]byte
	Part    string
	Path    string `json:",omitempty"`
	Offset  uint64 `json:",omitempty"`
}

func (q ContentQuery) Valid() bool {
	return q.Version != ([32]byte{}) && (q.Part == "file" && ContextPath(q.Path) && uint64(q.Offset) <= uint64(MaxExpandedBytes) || (q.Part == "tree" || q.Part == "dockerfile") && q.Path == "" && q.Offset == 0)
}

type ContentPage struct {
	Schema        uint8
	Version, Tree [32]byte
	Part          string
	Offset, Total uint32
	Entries       []Entry   `json:",omitempty"`
	Data          []byte    `json:",omitempty"`
	Next          uint32    `json:",omitempty"`
	File          *FilePage `json:",omitempty"`
}

// Content owns one immutable, bounded projection of an inspected artifact.
// Validation happens once; paging never hashes or reparses the ZIP again.
type Content struct {
	version, digest [32]byte
	tree            Tree
}

func NewContent(tree Tree, scope UploadScope, seal SealReceipt) (*Content, error) {
	if !seal.Valid(scope) || len(tree.Entries) > MaxTreeEntries || tree.Digest() != seal.Tree || uint32(len(tree.Entries)) != seal.Entries || tree.Bytes != seal.ExpandedBytes || len(tree.Dockerfile) > MaxDockerfileBytes {
		return nil, ErrInvalid
	}
	found := false
	for i, entry := range tree.Entries {
		if !validContentEntry(entry) || i > 0 && tree.Entries[i-1].Path >= entry.Path {
			return nil, ErrInvalid
		}
		if entry.Path == scope.Dockerfile && !entry.Directory {
			if int64(len(tree.Dockerfile)) != entry.Bytes || sha256.Sum256(tree.Dockerfile) != entry.Digest {
				return nil, ErrDigest
			}
			found = true
		}
	}
	if !found {
		return nil, ErrInvalid
	}
	tree.Entries, tree.Dockerfile = slices.Clone(tree.Entries), slices.Clone(tree.Dockerfile)
	return &Content{version: VersionID(seal), digest: seal.Tree, tree: tree}, nil
}
func validContentEntry(e Entry) bool {
	if !ContextPath(e.Path) || e.Bytes < 0 || e.Bytes > MaxExpandedBytes {
		return false
	}
	if e.Directory {
		return e.Bytes == 0 && !e.Executable && e.Digest == ([32]byte{})
	}
	return e.Digest != ([32]byte{})
}
func (c *Content) Read(q ContentQuery, offset uint32) (ContentPage, error) {
	if c == nil || !q.Valid() || q.Version != c.version {
		return ContentPage{}, ErrInvalid
	}
	out := ContentPage{Schema: 1, Version: c.version, Tree: c.digest, Part: q.Part, Offset: offset}
	if q.Part == "file" {
		return ContentPage{}, ErrInvalid // File bytes require the original native artifact.
	}
	if q.Part == "tree" {
		out.Total = uint32(len(c.tree.Entries))
		if offset > out.Total {
			return ContentPage{}, ErrInvalid
		}
		end := min(out.Total, offset+8)
		out.Entries = slices.Clone(c.tree.Entries[offset:end])
		if end < out.Total {
			out.Next = end
		}
	} else {
		out.Total = uint32(len(c.tree.Dockerfile))
		if offset > out.Total {
			return ContentPage{}, ErrInvalid
		}
		end := min(out.Total, offset+PartBytes)
		out.Data = slices.Clone(c.tree.Dockerfile[offset:end])
		if end < out.Total {
			out.Next = end
		}
	}
	return out, nil
}
func (p ContentPage) Valid(q ContentQuery) bool {
	if !q.Valid() || p.Schema != 1 || p.Version != q.Version || p.Tree == ([32]byte{}) || p.Part != q.Part || p.Offset > p.Total {
		return false
	}
	if p.Part == "file" {
		return p.Offset == 0 && p.Total == 0 && p.Next == 0 && len(p.Entries) == 0 && len(p.Data) == 0 && p.File != nil && p.File.Valid(q.Path, p.File.Offset)
	}
	var end uint32
	if p.Part == "tree" {
		if p.File != nil || p.Total == 0 || p.Total > MaxTreeEntries || len(p.Data) != 0 || len(p.Entries) > 8 {
			return false
		}
		end = min(p.Total, p.Offset+8)
		if uint32(len(p.Entries)) != end-p.Offset {
			return false
		}
		for i, e := range p.Entries {
			if !validContentEntry(e) || i > 0 && p.Entries[i-1].Path >= e.Path {
				return false
			}
		}
	} else {
		if p.File != nil || p.Total > MaxDockerfileBytes {
			return false
		}

		if len(p.Entries) != 0 || len(p.Data) > PartBytes {
			return false
		}
		end = min(p.Total, p.Offset+PartBytes)
		if uint32(len(p.Data)) != end-p.Offset {
			return false
		}
	}
	if end < p.Total {
		return p.Next == end
	}
	return p.Next == 0
}

// FileEntry selects only an inspected regular file, never a host path.
func (c *Content) FileEntry(q ContentQuery) (Entry, error) {
	if c == nil || !q.Valid() || q.Part != "file" || q.Version != c.version {
		return Entry{}, ErrInvalid
	}
	for _, entry := range c.tree.Entries {
		if entry.Path == q.Path && !entry.Directory {
			return entry, nil
		}
	}
	return Entry{}, ErrInvalid
}

// PageOffset and PageNext preserve the schema-1 tree/Dockerfile fields while
// allowing expanded regular files larger than 4 GiB through File.
func (p ContentPage) PageOffset() uint64 {
	if p.Part == "file" && p.File != nil {
		return p.File.Offset
	}
	return uint64(p.Offset)
}
func (p ContentPage) PageNext() uint64 {
	if p.Part == "file" && p.File != nil {
		return p.File.Next
	}
	return uint64(p.Next)
}
