// SPDX-License-Identifier: Apache-2.0

package imagebuild

import (
	"encoding/json"
	"math"
	"slices"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/nodestorage"
)

// Native metadata is bounded independently of file bytes. The same bound is
// checked before an edit and on reopen, so an accepted edit cannot make its
// own journal unreadable. This is not a filesystem storage quota.
const MaxDraftMetadataBytes = 8 << 20

// DraftScope binds editable content to its original tenant/context policy.
// Changing a context definition cannot silently reuse another draft's files.
type DraftScope struct {
	Schema                          uint8
	Tenant, Context                 string
	Root                            nodestorage.Reference
	ContextRevision, PolicyRevision uint64
	Dockerfile                      string
	ExpandedLimit                   int64
	Generation                      uint64 `json:",omitempty"`
}

// DraftData is a storage lifetime, independent of authority/configuration
// revisions. Legacy scopes use their original context revision as the anchor.
type DraftData struct {
	Tenant, Context string
	Root            nodestorage.Reference
	Generation      uint64
}

func (s DraftScope) Data() DraftData {
	g := s.Generation
	if g == 0 {
		g = s.ContextRevision
	}
	return DraftData{Tenant: s.Tenant, Context: s.Context, Root: s.Root, Generation: g}
}
func (d DraftData) Digest() [32]byte { return digestJSON("mydc-imagebuild-draft-data-1", d) }

func (s DraftScope) Validate() error {
	if s.Schema != 1 || !lifecycle.ValidID(s.Tenant) || !lifecycle.ValidID(s.Context) || s.Root.Validate() != nil || s.ContextRevision == 0 || s.PolicyRevision == 0 || s.Generation > s.ContextRevision || !ContextPath(s.Dockerfile) || s.ExpandedLimit <= 0 || s.ExpandedLimit > MaxExpandedBytes {
		return ErrInvalid
	}
	return nil
}
func (s DraftScope) Digest() [32]byte { return digestJSON("mydc-imagebuild-draft-scope-1", s) }

// Draft stores only immutable file descriptors. Bytes stay below the pinned
// node root; this same transition is consumed by the real DraftStore adapter.
type Draft struct {
	Scope    DraftScope
	Revision uint64
	Entries  []Entry
}

type DraftEdit struct {
	ID, Kind, Path, To string
	Expected           uint64
	File               *Entry `json:",omitempty"`
}

func (e DraftEdit) Digest() [32]byte { return digestJSON("mydc-imagebuild-draft-edit-1", e) }
func (e DraftEdit) Validate() error {
	if !lifecycle.ValidID(e.ID) || e.Expected == 0 || e.Expected == math.MaxUint64 || !ContextPath(e.Path) {
		return ErrInvalid
	}
	switch e.Kind {
	case "put":
		if e.To != "" || e.File == nil || e.File.Path != e.Path || e.File.Directory || e.File.Bytes < 0 || e.File.Bytes > MaxZIPBytes || e.File.Digest == ([32]byte{}) {
			return ErrInvalid
		}
	case "mkdir", "delete":
		if e.File != nil || e.To != "" {
			return ErrInvalid
		}
	case "move":
		if e.File != nil || !ContextPath(e.To) || e.Path == e.To || strings.HasPrefix(e.To, e.Path+"/") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func NewDraft(scope DraftScope) (Draft, error) {
	if err := scope.Validate(); err != nil {
		return Draft{}, err
	}
	return Draft{Scope: scope, Revision: 1}, nil
}

func (d Draft) shape() error {
	if d.Scope.Validate() != nil || d.Revision == 0 || len(d.Entries) > MaxTreeEntries {
		return ErrInvalid
	}
	paths := make(map[string]bool, len(d.Entries))
	var size int64
	for i, e := range d.Entries {
		if !ContextPath(e.Path) || i > 0 && d.Entries[i-1].Path >= e.Path || e.Bytes < 0 || e.Bytes > MaxZIPBytes || e.Directory && (e.Bytes != 0 || e.Digest != ([32]byte{}) || e.Executable) || !e.Directory && e.Digest == ([32]byte{}) || e.Bytes > MaxExpandedBytes-size {
			return ErrInvalid
		}
		size += e.Bytes
		paths[e.Path] = e.Directory
	}
	for _, e := range d.Entries {
		for i := strings.IndexByte(e.Path, '/'); i >= 0; {
			if dir, ok := paths[e.Path[:i]]; ok && !dir {
				return ErrInvalid
			}
			next := strings.IndexByte(e.Path[i+1:], '/')
			if next < 0 {
				break
			}
			i += next + 1
		}
	}
	return nil
}

func (d Draft) usage() (total, script int64) {
	for _, e := range d.Entries {
		total += e.Bytes
		if !e.Directory && e.Path == d.Scope.Dockerfile {
			script = e.Bytes
		}
	}
	return
}
func (d Draft) metadataFits() bool {
	raw, err := json.Marshal(d)
	return err == nil && len(raw) <= MaxDraftMetadataBytes
}
func (d Draft) Validate() error {
	if d.shape() != nil || !d.metadataFits() {
		return ErrInvalid
	}
	total, script := d.usage()
	if total > d.Scope.ExpandedLimit || script > MaxDockerfileBytes {
		return ErrInvalid
	}
	return nil
}

// Edit is atomic, immutable and CAS ordered. Directory operations include
// implicit descendants; move never merges/overwrites an occupied destination.
func (d Draft) Edit(e DraftEdit) (Draft, error) {
	if d.shape() != nil || e.Validate() != nil {
		return Draft{}, ErrInvalid
	}
	if e.Expected != d.Revision || d.Revision == math.MaxUint64 {
		return Draft{}, ErrConflict
	}
	exists := false
	directory := false
	for _, row := range d.Entries {
		if row.Path == e.Path {
			exists, directory = true, row.Directory
		} else if strings.HasPrefix(row.Path, e.Path+"/") {
			exists, directory = true, true
		}
		if e.Kind == "move" && (row.Path == e.To || strings.HasPrefix(row.Path, e.To+"/")) {
			return Draft{}, ErrConflict
		}
	}
	next := Draft{Scope: d.Scope, Revision: d.Revision + 1, Entries: make([]Entry, 0, len(d.Entries)+1)}
	switch e.Kind {
	case "put", "mkdir":
		if exists && (e.Kind == "mkdir" || directory) {
			return Draft{}, ErrConflict
		}
		for _, row := range d.Entries {
			if row.Path != e.Path {
				next.Entries = append(next.Entries, row)
			}
		}
		if e.Kind == "put" {
			next.Entries = append(next.Entries, *e.File)
		} else {
			next.Entries = append(next.Entries, Entry{Path: e.Path, Directory: true})
		}
	case "delete", "move":
		if !exists {
			return Draft{}, ErrConflict
		}
		for _, row := range d.Entries {
			if row.Path == e.Path || strings.HasPrefix(row.Path, e.Path+"/") {
				if e.Kind == "delete" {
					continue
				}
				row.Path = e.To + strings.TrimPrefix(row.Path, e.Path)
			}
			next.Entries = append(next.Entries, row)
		}
	}
	slices.SortFunc(next.Entries, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	if next.shape() != nil || !next.metadataFits() {
		return Draft{}, ErrInvalid
	}
	beforeBytes, beforeScript := d.usage()
	afterBytes, afterScript := next.usage()
	if afterBytes > d.Scope.ExpandedLimit && afterBytes > beforeBytes || afterScript > MaxDockerfileBytes && afterScript > beforeScript {
		return Draft{}, ErrInvalid
	}
	return next, nil
}

func (d Draft) Digest() [32]byte { return digestJSON("mydc-imagebuild-draft-1", d) }
