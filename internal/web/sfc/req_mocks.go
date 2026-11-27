// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"github.com/jay94ks/seafield/internal/cluster/control"
)

// Small REQ-n (mock) methods and actions. Names follow REQUEST.md and may be
// renamed when sfcd publishes them.

// --- REQ-31: image reference check ---

// ImageRegistryBuiltin names the tenant's built-in registry in the fake's
// registry images and build policies. image-resolve itself is
// Conn.ResolveImage (fake_image_resolve_real.go).
const ImageRegistryBuiltin = "builtin"

// --- REQ-23: manual raft log compaction ---

const ActionRaftCompact = "raft-compact"

// Manual raft log compaction (raft-maintenance.md, system admin):
// raft-compact-plan Compact:{Selection} pages the fixed target roster (64 a
// page) under one Target fingerprint; raft-compact (Expected 0, root
// RootFor: CompactKey) carries CompactChange{Operation, Selection, Target};
// raft-compact-status Compact:{Operation} pages the job (4 nodes a page).
type (
	CompactSelection  = control.CompactSelection
	CompactChange     = control.CompactChange
	CompactPlanPage   = control.CompactPlanPage
	CompactStatusPage = control.CompactStatusPage
)

// FixtureRaftCompaction: one manual compaction job in the fake
// (FixtureRaft.LastCompaction is the newest; raft-status reports it as
// LastManualCompact and each node's LastManualCompact).
type FixtureRaftCompaction struct {
	Operation     string // the job's Operation (CompactChange.Operation)
	By            string // user ID
	At            int64
	Retain        string // mode: keep / minimal
	Minimal       uint64 // minimal's retained entries
	Parallel      bool
	Target        [32]byte
	Selection     CompactSelection
	AcceptedIndex uint64
	Results       []FixtureRaftCompactResult
}

type FixtureRaftCompactResult struct {
	Node                              string
	State                             string // queued / running / done / failed / skipped
	SnapshotIndex, SnapshotBytes      uint64
	LogEntriesBefore, LogEntriesAfter uint64
	LogBytesBefore, LogBytesAfter     uint64
	// LogFileBytes: the bolt log file does not shrink until the next restart
	// compacts it; LogBytesAfter is the space actually in use.
	LogFileBytes uint64
	DurationMS   int64
	Error        string `json:",omitempty"`
}

// --- REQ-45: image trust rules and their uses ---

// ImageTrust: REQ-45 (mock) `image-trust` (tenant Read). Revision is the
// tenant revision, set-trust's Expected. Uses lists every current image of
// the tenant's app services and standalone containers with the indexes of
// the Rules that admit it; removing all of them makes it untrusted.
type ImageTrust struct {
	Tenant   string
	Revision uint64
	Rules    []TrustRule
	Uses     []ImageTrustUse
}

type ImageTrustUse struct {
	App        string `json:",omitempty"`
	Deployment string `json:",omitempty"`
	Service    string `json:",omitempty"`
	Standalone string `json:",omitempty"`
	Image      string // normalized reference
	Rules      []int  // indexes into ImageTrust.Rules; empty = not trusted now
}
