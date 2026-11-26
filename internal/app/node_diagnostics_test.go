// SPDX-License-Identifier: Apache-2.0

package app

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"github.com/jay94ks/mydcd/internal/eventlog"
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
		t.Fatal("missing config/status/mydcd event logs", files)
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
