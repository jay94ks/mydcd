// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"strings"
	"testing"

	"github.com/jay94ks/mydcd/internal/cliprofile"
)

func TestContainerLogsCLIKeepsOriginalCursorAndRejectsFollowOrOtherQueries(t *testing.T) {
	cursor := strings.Repeat("a", 64) + ":16384"
	opts, err := parseComposeOptions([]string{"logs", "-p", "app", "web", "--cursor", cursor, "--json"}, io.Discard)
	if err != nil || opts.container.query.Cursor != cursor {
		t.Fatal("log cursor lost", err)
	}
	for _, args := range [][]string{{"logs", "-p", "app", "web", "--cursor", cursor, "--follow"}, {"top", "-p", "app", "web", "--cursor", cursor}, {"logs", "-p", "app", "web", "--cursor", "invalid"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("invalid cursor/stream options", args)
		}
	}
}

func TestContainerReadCLIParsesOneServiceBeforeOrAfterFlags(t *testing.T) {
	for _, args := range [][]string{{"logs", "-p", "app", "web", "--tail", "2", "--json"}, {"-p", "app", "logs", "--tail", "2", "web", "--json"}, {"top", "-p", "app", "web", "--json"}, {"stats", "-p", "app", "--json", "web"}} {
		o, err := parseComposeOptions(args, io.Discard)
		if err != nil || o.container.service != "web" || o.container.query.Selection.App != "app" || !o.container.json {
			t.Fatal(args, o, err)
		}
	}
	o, err := parseComposeDefaults([]string{"logs", "web"}, io.Discard, cliprofile.Selection{Project: "app"})
	if err != nil || o.container.query.Tail != 200 || !o.container.query.Stdout || !o.container.query.Stderr {
		t.Fatal(o, err)
	}
}

func TestContainerInspectCLIUsesTaskSelectionAndBoundedHistory(t *testing.T) {
	o, err := parseComposeOptions([]string{"inspect", "-p", "app", "web", "--history", "5"}, io.Discard)
	if err != nil || o.container.query.Kind != "inspect" || o.container.query.HistoryLimit != 5 || o.container.query.MaxBytes != 24576 {
		t.Fatal("inspect selection/budget", err)
	}
	for _, args := range [][]string{{"inspect", "-p", "app", "web", "--follow"}, {"inspect", "-p", "app", "web", "--history", "101"}, {"logs", "-p", "app", "web", "--history", "5"}, {"inspect", "-p", "app", "web", "--tail", "3"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("mixed/unbounded inspect options", args)
		}
	}
}
func TestContainerReadCLIRejectsDeploymentAndStreamOptions(t *testing.T) {
	for _, args := range [][]string{{"logs", "-p", "app"}, {"logs", "-p", "app", "web", "other"}, {"logs", "web"}, {"top", "-p", "app", "web", "--tail", "2"}, {"stats", "-p", "app", "web", "--timestamps"}, {"logs", "-p", "app", "web", "--tail", "0"}, {"logs", "-p", "app", "web", "--max-bytes", "24577"}, {"logs", "-p", "app", "web", "--operation", "new"}, {"logs", "-p", "app", "web", "-f", "app.yaml"}, {"status", "-p", "app", "--json"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("unsupported/mixed options accepted", args)
		}
	}
}
