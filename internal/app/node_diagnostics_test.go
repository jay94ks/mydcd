// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/eventlog"
	"io"
	"testing"
	"time"
)

func TestNodeDiagnosticsArchiveUsesAllowlistedLogsAndBoundedPrivateFiles(t *testing.T) {
	const secret = "never-copy-this-token-or-private-error"
	logs := diagnosticLogs([]eventlog.Item{{Event: eventlog.Event{Kind: "probe-failed", Scope: "node", At: 10, Target: eventlog.Target{Node: "node-a"}, Detail: eventlog.Detail{Reason: secret, OperatorReason: secret, Code: "CHECK_FAILED", State: "failed"}}}})
	bundle, err := packNodeDiagnostics("node-a", time.Unix(10, 0), struct{ Managed bool }{true}, struct{ Ready bool }{false}, logs, false)
	if err != nil || !bundle.Valid("node-a") {
		t.Fatal(bundle, err)
	}
	zip, err := gzip.NewReader(bytes.NewReader(bundle.Data))
	if err != nil {
		t.Fatal(err)
	}
	defer zip.Close()
	archive := tar.NewReader(zip)
	files := 0
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Mode != 0600 || header.Typeflag != tar.TypeReg {
			t.Fatal("non-private archive member", header)
		}
		raw, err := io.ReadAll(io.LimitReader(archive, 129<<10))
		if err != nil || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret/raw reason entered archive", err)
		}
		files++
	}
	if files != 3 {
		t.Fatal("missing config/status/sfcd event logs", files)
	}
	changed := bundle
	changed.Data = bytes.Clone(bundle.Data)
	changed.Data[0] ^= 1
	if changed.Valid("node-a") {
		t.Fatal("modified download accepted")
	}
	for _, mutate := range []func(){
		func() { changed.LimitBytes++ },
		func() { changed.ExpandedLimitBytes++ },
	} {
		changed = bundle
		mutate()
		if changed.Valid("node-a") {
			t.Fatal("modified archive budget accepted")
		}
	}
}

// A CPU profile asked for with the read lands in the bundle next to the
// goroutine profile; only one CPU profile runs per process at a time.
func TestNodeDiagnosticsCarryProfiles(t *testing.T) {
	profiles, err := diagnosticProfiles(context.Background(), 1)
	if err != nil || len(profiles) != 2 || profiles[0].name != "profile-cpu.pb.gz" || profiles[1].name != "profile-goroutine.pb.gz" {
		t.Fatal(profiles, err)
	}
	for _, p := range profiles {
		if len(p.data) < 2 || p.data[0] != 0x1f || p.data[1] != 0x8b {
			t.Fatal("profile is not gzip pprof", p.name)
		}
	}
	bundle, err := packNodeDiagnostics("node-a", time.Unix(1, 0), struct{}{}, struct{}{}, nil, false, profiles...)
	if err != nil || !bundle.Valid("node-a") || bundle.Truncated {
		t.Fatal(bundle.Truncated, err)
	}
	names := diagnosticMembers(t, bundle.Data)
	if !slices.Contains(names, "profile-cpu.pb.gz") || !slices.Contains(names, "profile-goroutine.pb.gz") {
		t.Fatal(names)
	}
	// Profiles that do not fit are dropped from the end; the bundle says so.
	big := diagnosticProfile{"profile-goroutine.pb.gz", bytes.Repeat([]byte{0x1f}, control.NodeDiagnosticsExpandedBytes)}
	bundle, err = packNodeDiagnostics("node-a", time.Unix(1, 0), struct{}{}, struct{}{}, nil, false, profiles[0], big)
	if err != nil || !bundle.Valid("node-a") || !bundle.Truncated {
		t.Fatal(bundle.Truncated, err)
	}
	if names = diagnosticMembers(t, bundle.Data); !slices.Contains(names, "profile-cpu.pb.gz") || slices.Contains(names, "profile-goroutine.pb.gz") {
		t.Fatal(names)
	}
	// While a CPU profile runs, a second one is refused, not queued.
	diagnosticCPUProfile.Lock()
	_, err = diagnosticProfiles(context.Background(), 1)
	diagnosticCPUProfile.Unlock()
	if !errors.Is(err, ErrProfileBusy) {
		t.Fatal("concurrent CPU profile", err)
	}
	// A read cancelled during its CPU profile fails and frees the profiler.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = diagnosticProfiles(ctx, 5); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled profile", err)
	}
	if _, err = diagnosticProfiles(context.Background(), 1); err != nil {
		t.Fatal("profiler not freed", err)
	}
}

func diagnosticMembers(t *testing.T, data []byte) []string {
	t.Helper()
	zip, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	archive := tar.NewReader(zip)
	for {
		h, err := archive.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
}
