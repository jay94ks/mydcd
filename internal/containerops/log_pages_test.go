// SPDX-License-Identifier: Apache-2.0

package containerops

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func logPageFixture() (Target, Query, Result) {
	target := Target{Cluster: [32]byte{1}, Owner: [32]byte{2}, Binding: [32]byte{3}, Tenant: "tenant", App: "app", Service: "web", Node: "node", Instance: "workload/task/tenant/app/web", Generation: 1, Revision: 1, NativeID: "native", StartedAt: "2026-11-21T00:00:00Z"}
	query := Query{Schema: 1, Selection: Selection{App: "app", Service: "web"}, Kind: "logs", Tail: 200, Stdout: true, Stderr: true, MaxBytes: MaxOutput}
	// Identical timestamps/content must remain distinguishable by byte position.
	result := Result{Schema: 1, Kind: "logs", Target: target, ObservedAt: time.Unix(100, 0).UTC(), LogDriver: "json-file", Stdout: []byte(strings.Repeat("same-time same-line\n", 5000)), Stderr: []byte(strings.Repeat("same-time diagnostic\n", 2000))}
	return target, query, result
}

func TestReadPagesPreserveEveryByteAcrossRepeatedLinesAndIndependentRequests(t *testing.T) {
	target, query, original := logPageFixture()
	var pages ReadPages
	defer pages.Clear()
	page, err := pages.Open("alice", target, query, original, [32]byte{1}, 100)
	if err != nil {
		t.Fatal(err)
	}
	first := page
	var stdout, stderr []byte
	for n := 0; ; n++ {
		if n > 100 || page.Validate(query, target) != nil {
			t.Fatal("invalid/repeated page")
		}
		stdout = append(stdout, page.Stdout...)
		stderr = append(stderr, page.Stderr...)
		if page.NextCursor == "" {
			break
		}
		query.Cursor = page.NextCursor
		page, err = pages.Next("alice", target, query, 101)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(stdout, original.Stdout) || !bytes.Equal(stderr, original.Stderr) {
		t.Fatal("pagination skipped or repeated identical timestamp lines")
	}
	query.Cursor = first.NextCursor
	page, err = pages.Next("alice", target, query, 102)
	if err != nil {
		t.Fatal("same cursor is not repeatable", err)
	}
	page.Stdout[0] = '!'
	again, err := pages.Next("alice", target, query, 102)
	if err != nil || bytes.Equal(page.Stdout, again.Stdout) {
		t.Fatal("client mutated retained window", err)
	}
}

func TestReadPagesRejectOtherUserTargetOptionsAndExpiredOrRestartedCursor(t *testing.T) {
	target, query, original := logPageFixture()
	var pages ReadPages
	defer pages.Clear()
	page, err := pages.Open("alice", target, query, original, [32]byte{4}, 100)
	if err != nil {
		t.Fatal(err)
	}
	query.Cursor = page.NextCursor
	if _, err = pages.Next("bob", target, query, 101); !errors.Is(err, ErrLogCursorExpired) {
		t.Fatal("cross-user cursor", err)
	}
	for _, change := range []func(*Target){func(t *Target) { t.Tenant = "other" }, func(t *Target) { t.NativeID = "replacement" }, func(t *Target) { t.StartedAt = "2026-11-21T00:01:00Z" }, func(t *Target) { t.Generation++; t.Revision++ }} {
		x := target
		change(&x)
		if _, err = pages.Next("alice", x, query, 101); !errors.Is(err, ErrLogCursorExpired) {
			t.Fatal("rebound cursor", err)
		}
	}
	changed := query
	changed.MaxBytes--
	if _, err = pages.Next("alice", target, changed, 101); !errors.Is(err, ErrLogCursorExpired) {
		t.Fatal("query options changed", err)
	}
	if _, err = pages.Next("alice", target, query, 100+LogWindowSeconds); !errors.Is(err, ErrLogCursorExpired) || pages.bytes != 0 {
		t.Fatal("expired window retained", err)
	}
	var restarted ReadPages
	if _, err = restarted.Next("alice", target, query, 101); !errors.Is(err, ErrLogCursorExpired) {
		t.Fatal("restart forged old window", err)
	}
	if (SessionSpec{Kind: "logs", Query: &query}).Validate() == nil {
		t.Fatal("cursor accepted as follow stream")
	}
}

func TestReadPagesDoNotEvictLiveWindowsToHideCapacityOrOversize(t *testing.T) {
	target, query, original := logPageFixture()
	var pages ReadPages
	defer pages.Clear()
	for i := byte(1); i <= maxLogWindows; i++ {
		if _, err := pages.Open("alice", target, query, original, [32]byte{i}, 100); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pages.Open("alice", target, query, original, [32]byte{99}, 100); !errors.Is(err, ErrLogCursorCapacity) {
		t.Fatal("window capacity exceeded", err)
	}
	original.Stdout = make([]byte, MaxLogWindowBytes+1)
	original.Stderr = nil
	if _, err := pages.Open("alice", target, query, original, [32]byte{100}, 100); !errors.Is(err, ErrLogWindowLimit) {
		t.Fatal("incomplete window treated as complete", err)
	}
	for _, bad := range []string{"", "../foreign:1", strings.Repeat("0", 64) + ":1", strings.Repeat("a", 64) + ":01", strings.Repeat("a", 64) + ":-1", strings.Repeat("a", 64) + ":99999999"} {
		if ValidLogCursor(bad) {
			t.Fatal("invalid cursor", bad)
		}
	}
}
