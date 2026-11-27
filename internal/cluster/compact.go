// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/seafield/internal/maintenance"

	"github.com/hashicorp/raft"
)

// CompactMetrics inspects the existing SDK stores. Used bytes are allocated
// Bolt pages minus its free allocation, not payload size or an fsync guarantee.
// No DB copy, file replacement, direct DeleteRange or vacuum is performed.
func (e *Engine) CompactMetrics() (maintenance.CompactMetrics, error) {
	var m maintenance.CompactMetrics
	if e.log == nil || e.snapshots == nil {
		return m, raft.ErrRaftShutdown
	}
	first, err := e.log.FirstIndex()
	if err != nil {
		return m, err
	}
	last, err := e.log.LastIndex()
	if err != nil {
		return m, err
	}
	// SDK truncation may interleave these two reads. Retry the same observation,
	// never synthesize a negative/huge range or declare storage corruption.
	if first > last && first != 0 {
		first, err = e.log.FirstIndex()
		if err != nil {
			return m, err
		}
		last, err = e.log.LastIndex()
		if err != nil {
			return m, err
		}
	}
	if first == 0 && last == 0 || first > 0 && last >= first {
		m.LogKnown = true
		m.FirstIndex = first
		m.LastIndex = last
		if first > 0 {
			m.LogEntries = last - first + 1
		}
	}
	if info, err := os.Stat(filepath.Join(e.root, "control", "raft.db")); err == nil && info.Size() >= 0 {
		m.LogFileKnown = true
		m.LogFileBytes = uint64(info.Size())
		stats := e.log.Stats()
		if stats.FreeAlloc >= 0 && uint64(stats.FreeAlloc) <= m.LogFileBytes {
			m.LogUsedKnown = true
			m.LogFreeBytes = uint64(stats.FreeAlloc)
			m.LogUsedBytes = m.LogFileBytes - m.LogFreeBytes
		}
	}
	snapshots, err := e.snapshots.List()
	if err != nil {
		return m, err
	}
	for _, s := range snapshots {
		if s.Index > 0 && (!m.SnapshotKnown || s.Index >= m.SnapshotIndex) {
			m.SnapshotKnown = true
			m.SnapshotIndex = s.Index
			if s.Size >= 0 {
				m.SnapshotBytes = uint64(s.Size)
			}
		}
	}
	if !m.Valid() {
		return maintenance.CompactMetrics{}, maintenance.ErrCompact
	}
	return m, nil
}

// ManualCompact executes exactly one SDK snapshot under a single owner. save
// must sync the original dispatch BEFORE configuration reload/SDK dispatch.
// Once started, caller cancellation cannot manufacture completion or restore
// retention while that same future is still running. The tracked call joins
// the actual SDK future, then restores only the temporary TrailingLogs field.
// The runtime owns the signed grant/job and the durable terminal result.
func (e *Engine) ManualCompact(ctx context.Context, operation string, minimum uint64, options maintenance.CompactOptions, save func(maintenance.CompactDispatch) error) (result maintenance.CompactResult, err error) {
	if ctx == nil || save == nil || options.Validate() != nil || minimum == 0 {
		return result, maintenance.ErrCompact
	}
	if !e.compactMu.TryLock() {
		return result, maintenance.ErrCompact
	}
	defer e.compactMu.Unlock()
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return result, raft.ErrRaftShutdown
	}
	e.wg.Add(1)
	e.mu.Unlock()
	defer e.wg.Done()
	if err = ctx.Err(); err != nil {
		return result, err
	}
	view, readErr := e.Read(ctx, false)
	if readErr != nil {
		return result, readErr
	}
	if view.RaftIndex < minimum {
		return result, ErrRecovering
	}
	before, err := e.CompactMetrics()
	if err != nil {
		return result, err
	}
	original := e.raft.ReloadableConfig()
	dispatch := maintenance.CompactDispatch{Schema: 1, Operation: operation, At: time.Now().UnixNano(), MinimumIndex: minimum, Options: options, ConfiguredTrailing: original.TrailingLogs, EffectiveTrailing: options.Effective(original.TrailingLogs), Before: before}
	if err = dispatch.Validate(); err != nil {
		return result, err
	}
	if err = save(dispatch); err != nil {
		return result, err
	}
	result = maintenance.CompactResult{Schema: 1, Dispatch: dispatch, ConfigRestored: true, FileReclamation: "Bolt retains allocated file pages; free pages are reused. Physical file shrinking requires a separate offline maintenance operation."}
	start := time.Now()
	defer func() {
		result.DurationMillis = uint64(max(0, time.Since(start).Milliseconds()))
		after, observeErr := e.CompactMetrics()
		if observeErr == nil {
			result.After = after
			result.TargetMet = result.Compacted() && maintenance.RetentionMet(after, dispatch.EffectiveTrailing)
		} else {
			err = errors.Join(err, observeErr)
		}
		if err == nil && !result.Compacted() {
			err = fmt.Errorf("accepted prefix was not captured by the SDK snapshot")
		}
		if err != nil {
			if result.ErrorCode == "" {
				result.ErrorCode = compactErrorCode(err)
			}
			result.Error = compactErrorText(err)
		}
	}()
	if err = ctx.Err(); err != nil {
		return result, err
	} // saved original, no SDK call yet
	temporary := original
	temporary.TrailingLogs = dispatch.EffectiveTrailing
	changed := temporary.TrailingLogs != original.TrailingLogs
	if changed {
		if err = e.raft.ReloadConfig(temporary); err != nil {
			result.ErrorCode = "reload-failed"
			return result, err
		}
		result.ConfigRestored = false
		defer func() {
			current := e.raft.ReloadableConfig()
			if current.TrailingLogs != temporary.TrailingLogs {
				result.ErrorCode = "restore-conflict"
				err = errors.Join(err, fmt.Errorf("Raft retention changed during the original maintenance"))
				return
			}
			current.TrailingLogs = original.TrailingLogs
			if restoreErr := e.raft.ReloadConfig(current); restoreErr != nil {
				result.ErrorCode = "restore-failed"
				err = errors.Join(err, restoreErr)
				return
			}
			result.ConfigRestored = true
		}()
	}
	// SDK snapshot persists/closes its sink before SDK-controlled log deletion.
	// Its file-store failure path cancels the unfinished snapshot; errors are not
	// replaced with direct log deletion or a successful zero-sized snapshot.
	err = e.raft.Snapshot().Error()
	return result, err
}
func compactErrorCode(err error) string {
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "no space left"):
		return "disk-full"
	case errors.Is(err, raft.ErrRaftShutdown):
		return "shutdown"
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return "canceled-before-sdk"
	default:
		return "snapshot-failed"
	}
}
func compactErrorText(err error) string {
	text := strings.ToValidUTF8(err.Error(), "?")
	if len(text) > 1024 {
		text = text[:1024]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return text
}

// RecoverManualCompact accepts positive equivalent SDK state only. A missing
// reply, expired caller or absent local record is never proof of execution.
func (e *Engine) RecoverManualCompact(ctx context.Context, d maintenance.CompactDispatch) (maintenance.CompactResult, bool, error) {
	var result maintenance.CompactResult
	if d.Validate() != nil {
		return result, false, maintenance.ErrCompact
	}
	if err := ctx.Err(); err != nil {
		return result, false, err
	}
	after, err := e.CompactMetrics()
	if err != nil {
		return result, false, err
	}
	if !after.SnapshotKnown || after.SnapshotIndex < d.MinimumIndex || !maintenance.RetentionMet(after, d.EffectiveTrailing) || e.raft.ReloadableConfig().TrailingLogs != d.ConfiguredTrailing {
		return result, false, nil
	}
	result = maintenance.CompactResult{Schema: 1, Dispatch: d, After: after, ConfigRestored: true, TargetMet: true, ObservedRecovery: true, FileReclamation: "Equivalent SDK snapshot/log state observed; allocated Bolt file pages are reused, not physically shrunk."}
	return result, true, result.Validate()
}
