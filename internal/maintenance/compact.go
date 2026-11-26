// SPDX-License-Identifier: Apache-2.0

// Package maintenance holds bounded metadata for explicit cluster maintenance.
// Native work uses the installed SDK; this package does not implement Raft.
package maintenance

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

var ErrCompact = errors.New("invalid or busy Raft compaction")

type CompactOptions struct {
	Mode   string
	Retain uint64
}

func (o CompactOptions) Validate() error {
	if o.Mode == "keep" && o.Retain == 0 || o.Mode == "minimal" && o.Retain > 0 && o.Retain <= 1<<30 {
		return nil
	}
	return ErrCompact
}
func (o CompactOptions) Effective(configured uint64) uint64 {
	if o.Mode == "minimal" && o.Retain < configured {
		return o.Retain
	}
	return configured
}

type CompactMetrics struct {
	LogKnown, LogFileKnown, LogUsedKnown, SnapshotKnown bool
	FirstIndex, LastIndex, LogEntries                   uint64
	LogFileBytes, LogUsedBytes, LogFreeBytes            uint64
	SnapshotIndex, SnapshotBytes                        uint64
}

func (m CompactMetrics) Valid() bool {
	if m.LogKnown && (m.FirstIndex == 0 && (m.LastIndex != 0 || m.LogEntries != 0) || m.FirstIndex > 0 && (m.LastIndex < m.FirstIndex || m.LogEntries != m.LastIndex-m.FirstIndex+1)) {
		return false
	}
	if m.LogUsedKnown && (!m.LogFileKnown || m.LogUsedBytes > m.LogFileBytes || m.LogFreeBytes > m.LogFileBytes || m.LogUsedBytes != m.LogFileBytes-m.LogFreeBytes) {
		return false
	}
	return !m.SnapshotKnown || m.SnapshotIndex > 0
}

type CompactDispatch struct {
	Schema                                uint8
	Operation                             string
	At                                    int64  // UTC Unix nanoseconds, owner-local receipt, not a consensus clock
	MinimumIndex                          uint64 // durable Raft position of the accepted original
	Options                               CompactOptions
	ConfiguredTrailing, EffectiveTrailing uint64
	Before                                CompactMetrics
}

func (d CompactDispatch) Validate() error {
	if d.Schema != 1 || d.Operation == "" || len(d.Operation) > 256 || !utf8.ValidString(d.Operation) || d.At <= 0 || d.MinimumIndex == 0 || d.Options.Validate() != nil || d.EffectiveTrailing != d.Options.Effective(d.ConfiguredTrailing) || !d.Before.Valid() {
		return ErrCompact
	}
	return nil
}

type CompactResult struct {
	ObservedRecovery bool `json:",omitempty"`
	Schema           uint8
	Dispatch         CompactDispatch
	After            CompactMetrics
	DurationMillis   uint64
	ConfigRestored   bool
	TargetMet        bool
	ErrorCode, Error string
	FileReclamation  string
}

func (r CompactResult) Validate() error {
	if r.Schema != 1 || r.Dispatch.Validate() != nil || !r.After.Valid() || len(r.FileReclamation) > 512 || len(r.Error) > 1024 || !utf8.ValidString(r.Error) || len(r.ErrorCode) > 64 || r.TargetMet != (r.Compacted() && RetentionMet(r.After, r.Dispatch.EffectiveTrailing)) || r.ErrorCode == "" && (!r.ConfigRestored || !r.Compacted()) {
		return ErrCompact
	}
	encoded, err := json.Marshal(r)
	if err != nil || len(encoded) > 8<<10 {
		return ErrCompact
	}
	return nil
}
func (r CompactResult) Compacted() bool {
	return r.After.SnapshotKnown && r.After.SnapshotIndex >= r.Dispatch.MinimumIndex && r.After.LogKnown
}
func RetentionMet(m CompactMetrics, retain uint64) bool { return m.LogKnown && m.LogEntries <= retain }
