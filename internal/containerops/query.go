// SPDX-License-Identifier: Apache-2.0

// Package containerops defines bounded user observations of owned containers.
// It has no transport, journal or independent process of its own.
package containerops

import (
	"errors"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
)

var ErrQuery = errors.New("invalid container observation")
var ErrTarget = errors.New("container target unavailable or ambiguous")
var ErrLimit = errors.New("container observation output limit")

const MaxOutput = 24 << 10

type Selection struct {
	App, Service, Instance string
	Standalone             string `json:",omitempty"`
}

func (s Selection) Valid() bool {
	return (s.Standalone == "" && lifecycle.ValidID(s.App) && lifecycle.ValidID(s.Service) || lifecycle.ValidID(s.Standalone) && s.App == "" && (s.Service == "" || lifecycle.ValidID(s.Service))) && len(s.Instance) <= 512 && !strings.ContainsAny(s.Instance, "\x00\r\n")
}

// Matches compares the public selector's owner kind and requested fields.
// Standalone targets keep their immutable internal App scope as native identity.
func (s Selection) Matches(target Target) bool {
	if !s.Valid() || !target.Valid() || s.Instance != "" && s.Instance != target.Instance {
		return false
	}
	if s.Standalone != "" {
		return s.Standalone == target.Standalone && (s.Service == "" || s.Service == target.Service)
	}
	return target.Standalone == "" && s.App == target.App && s.Service == target.Service
}

type Query struct {
	Schema                     uint8
	Selection                  Selection
	Kind                       string
	Tail                       int
	Since, Until               string
	Timestamps, Stdout, Stderr bool
	MaxBytes                   int
	Cursor                     string `json:",omitempty"`
	HistoryLimit               int    `json:",omitempty"`
}

func (q Query) Validate() error {
	if q.Schema != 1 || !q.Selection.Valid() || q.MaxBytes < 1 || q.MaxBytes > MaxOutput {
		return ErrQuery
	}
	switch q.Kind {
	case "logs":
		if q.HistoryLimit != 0 {
			return ErrQuery
		}
		if q.Cursor != "" && !ValidLogCursor(q.Cursor) {
			return ErrQuery
		}
		if q.Tail < 1 || q.Tail > 10000 || !q.Stdout && !q.Stderr {
			return ErrQuery
		}
		var since, until time.Time
		var err error
		if q.Since != "" {
			since, err = time.Parse(time.RFC3339Nano, q.Since)
			if err != nil {
				return ErrQuery
			}
		}
		if q.Until != "" {
			until, err = time.Parse(time.RFC3339Nano, q.Until)
			if err != nil {
				return ErrQuery
			}
		}
		if !since.IsZero() && !until.IsZero() && until.Before(since) {
			return ErrQuery
		}
	case "top", "stats", "inspect":
		if q.HistoryLimit < 0 || q.HistoryLimit > 100 || q.HistoryLimit != 0 && q.Kind != "inspect" {
			return ErrQuery
		}
		if q.Tail != 0 || q.Since != "" || q.Until != "" || q.Stdout || q.Stderr || q.Timestamps || q.Cursor != "" && (q.Kind != "inspect" || !ValidLogCursor(q.Cursor)) {
			return ErrQuery
		}
	default:
		return ErrQuery
	}
	return nil
}

// Instance is a logical Task key, never a caller-supplied Docker native ID.
// NativeID/StartedAt may initially be unknown; the owner resolves them from the
// exact journal and returns concrete values without changing the binding.
type Target struct {
	Standalone                           string `json:",omitempty"`
	Cluster, Owner, Binding              [32]byte
	Tenant, App, Service, Node, Instance string
	Generation, Revision                 uint64
	NativeID, StartedAt                  string `json:",omitempty"`
}

func (t Target) Valid() bool {
	return (t.Standalone == "" || lifecycle.ValidID(t.Standalone)) && t.Cluster != ([32]byte{}) && t.Owner != ([32]byte{}) && t.Binding != ([32]byte{}) && lifecycle.ValidID(t.Tenant) && lifecycle.ValidID(t.App) && lifecycle.ValidID(t.Service) && lifecycle.ValidID(t.Node) && t.Instance != "" && len(t.Instance) <= 512 && t.Generation != 0 && t.Revision >= t.Generation && len(t.NativeID) <= 256 && !strings.ContainsAny(t.NativeID, "\x00\r\n/") && len(t.StartedAt) <= 64
}
func (t Target) Matches(expected Target) bool {
	native, started := t.NativeID, t.StartedAt
	t.NativeID, t.StartedAt = expected.NativeID, expected.StartedAt
	// Public standalone names may change after pin; the immutable scope, Task,
	// binding and native generation remain the target identity.
	if (t.Standalone == "") != (expected.Standalone == "") {
		return false
	}
	t.Standalone = expected.Standalone
	return t == expected && (expected.NativeID == "" || native == expected.NativeID) && (expected.StartedAt == "" || started == expected.StartedAt)
}

type Stats struct {
	SampleAt                                             time.Time
	CPUPercent                                           *float64 `json:",omitempty"`
	CPUStatus                                            string
	MemoryBytes, MemoryWorkingSetBytes, MemoryLimitBytes *uint64 `json:",omitempty"`
	NetworkRXBytes, NetworkTXBytes                       *uint64 `json:",omitempty"`
	BlockReadBytes, BlockWriteBytes, PIDs                *uint64 `json:",omitempty"`
}
type Result struct {
	DetailPart     *DetailPart      `json:",omitempty"`
	DetailCode     string           `json:",omitempty"`
	Detail         *ContainerDetail `json:",omitempty"`
	NextCursor     string           `json:",omitempty"`
	LogCode        string           `json:",omitempty"`
	LogDriver      string           `json:",omitempty"`
	Schema         uint8
	Kind           string
	Target         Target
	ObservedAt     time.Time
	TTY, Truncated bool
	Stdout, Stderr []byte     `json:",omitempty"`
	Titles         []string   `json:",omitempty"`
	Processes      [][]string `json:",omitempty"`
	Stats          *Stats     `json:",omitempty"`
}

func (r Result) Validate(q Query, expected Target) error {
	return r.validate(q, expected, q.MaxBytes)
}

// ValidateDetailWindow is owner/client-local; only Validate permits a wire
// response. Large complete objects are fragmented before transport encoding.
func (r Result) ValidateDetailWindow(q Query, expected Target) error {
	if q.Kind != "inspect" || q.Cursor != "" || r.Detail == nil || r.DetailPart != nil || r.DetailCode != "" {
		return ErrQuery
	}
	return r.validate(q, expected, MaxDetailWindowBytes)
}

func (r Result) validate(q Query, expected Target, maxDetail int) error {
	if q.Validate() != nil || r.Schema != 1 || r.Kind != q.Kind || !r.Target.Valid() || !r.Target.Matches(expected) || r.Target.NativeID == "" || r.ObservedAt.IsZero() || !ValidLogDriver(r.LogDriver) {
		return ErrQuery
	}
	if len(r.Stdout)+len(r.Stderr) > q.MaxBytes {
		return ErrLimit
	}
	switch q.Kind {
	case "logs":
		if r.Detail != nil || r.DetailPart != nil || r.DetailCode != "" || r.Titles != nil || r.Processes != nil || r.Stats != nil || r.TTY && len(r.Stderr) != 0 {
			return ErrQuery
		}
		if r.NextCursor != "" && (!ValidLogCursor(r.NextCursor) || !r.Truncated) {
			return ErrQuery
		}
		if r.LogCode != "" && (r.LogCode != "CURSOR_EXPIRED" && r.LogCode != "LOG_WINDOW_LIMIT" && r.LogCode != "LOG_CURSOR_CAPACITY" || r.LogCode == "CURSOR_EXPIRED" && q.Cursor == "" || len(r.Stdout)+len(r.Stderr) != 0 || r.Truncated || r.NextCursor != "") {
			return ErrQuery
		}
	case "top":
		if r.Detail != nil || r.DetailPart != nil || r.DetailCode != "" || r.NextCursor != "" || r.LogCode != "" {
			return ErrQuery
		}
		if r.Stdout != nil || r.Stderr != nil || r.Stats != nil || len(r.Titles) > 32 || len(r.Processes) > 256 {
			return ErrQuery
		}
		total := 0
		for _, v := range r.Titles {
			total += len(v)
		}
		for _, row := range r.Processes {
			if len(row) != len(r.Titles) {
				return ErrQuery
			}
			for _, v := range row {
				total += len(v)
			}
		}
		if total > q.MaxBytes {
			return ErrLimit
		}
	case "stats":
		if r.Detail != nil || r.DetailPart != nil || r.DetailCode != "" || r.NextCursor != "" || r.LogCode != "" {
			return ErrQuery
		}
		if r.Stdout != nil || r.Stderr != nil || r.Titles != nil || r.Processes != nil || r.Stats == nil {
			return ErrQuery
		}
	case "inspect":
		if r.Stdout != nil || r.Stderr != nil || r.Titles != nil || r.Processes != nil || r.Stats != nil || r.LogCode != "" {
			return ErrQuery
		}
		if r.DetailCode != "" {
			if r.DetailCode != "CURSOR_EXPIRED" && r.DetailCode != "DETAIL_WINDOW_LIMIT" && r.DetailCode != "DETAIL_CURSOR_CAPACITY" || r.DetailCode == "CURSOR_EXPIRED" && q.Cursor == "" || r.Detail != nil || r.DetailPart != nil || r.NextCursor != "" || r.Truncated {
				return ErrQuery
			}
			return nil
		}
		if r.DetailPart != nil {
			if r.Detail != nil || r.DetailPart.validate(q, r.NextCursor, r.Truncated) != nil {
				return ErrQuery
			}
		} else if r.Detail == nil || !r.Detail.Valid(maxDetail) || r.NextCursor != "" || r.Truncated || q.Cursor != "" {
			return ErrQuery
		}
	}
	return nil
}
