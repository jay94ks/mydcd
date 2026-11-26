// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"github.com/jay94ks/mydcd/internal/cliprofile"
	"github.com/jay94ks/mydcd/internal/containerops"
	"github.com/jay94ks/mydcd/internal/mydcp"
	"github.com/jay94ks/mydcd/internal/userauth"
	"io"
	"strings"
	"testing"
)

func TestStandaloneCLIUsesExplicitOwnerSelectionAndBoundedLifetime(t *testing.T) {
	for _, args := range [][]string{{"up", "debug", "-f", "debug.yaml", "--operation", "create", "--mode", "shell", "--ttl-seconds", "3600"}, {"pin", "debug", "--name", "kept", "--operation", "pin"}, {"remove", "kept", "--operation", "remove"}, {"attach", "debug", "--operation", "connect", "-it"}, {"exec", "debug", "--operation", "run", "-it", "--", "/bin/sh", "-c", "echo x"}, {"logs", "debug", "--follow"}, {"stats", "debug", "--watch", "--interval", "2s"}, {"logs-clear", "debug", "--preview"}, {"logs-clear", "debug", "--recreate", "--operation", "clear"}} {
		o, err := parseStandaloneOptions(args, io.Discard)
		if err != nil {
			t.Fatal(args, err)
		}
		if containerReadMethod(o.method) && (!o.container.query.Selection.Valid() || o.container.query.Selection.App != "" || o.container.query.Selection.Standalone != "debug") {
			t.Fatal("ordinary app selection leaked", o.container.query)
		}
	}
	for _, args := range [][]string{{"up", "debug", "-f", "debug.yaml"}, {"up", "debug", "-f", "debug.yaml", "--operation", "create", "--ttl-seconds", "86401"}, {"attach", "debug", "--operation", "connect", "--", "/bin/sh"}, {"start", "debug"}, {"pin", "debug"}, {"logs-clear", "debug", "--operation", "clear"}, {"list", "debug"}} {
		if _, err := parseStandaloneOptions(args, io.Discard); err == nil {
			t.Fatal("invalid standalone syntax accepted", args)
		}
	}
	if (containerops.Selection{App: "internal", Standalone: "debug"}).Valid() {
		t.Fatal("mixed owner selection accepted")
	}
}

func TestRQ9UserHelpKeepsStandaloneAndEarlierCommands(t *testing.T) {
	for _, test := range []struct{ command, fragment string }{
		{"standalone", "standalone plan|up NAME"},
		{"service-call", "service-call APP SERVICE"},
	} {
		var out bytes.Buffer
		if !userHelp([]string{test.command, "--help"}, &out) || !strings.Contains(out.String(), test.fragment) {
			t.Fatal("merged user help missing", test.command)
		}
	}
}

func TestStandaloneCLIRejectsConflictingOrMissingSelectedTenantBeforeIO(t *testing.T) {
	for _, stored := range []userauth.Stored{{}, {TargetTenant: "selected", Tenant: "other"}} {
		var out, diagnostic bytes.Buffer
		code := runStandalone(context.Background(), []string{"list"}, userauth.Client{}, mydcp.Peer{}, stored, t.TempDir(), cliprofile.Selection{}, &out, &diagnostic)
		if code != 2 || out.Len() != 0 || diagnostic.Len() == 0 {
			t.Fatal("invalid tenant selection reached remote I/O", code, out.String(), diagnostic.String())
		}
	}
}

func TestStandaloneGroupInputsReuseExistingComposeApprovalDescriptors(t *testing.T) {
	for _, args := range [][]string{
		{"up", "debug", "-f", "debug.yaml", "--operation", "original", "--no-input", "--group-password-fd", "tenant/group=3"},
		{"resume", "debug", "--operation", "original", "--group-password-fd", "/group=5"},
	} {
		o, err := parseStandaloneOptions(args, io.Discard)
		if err != nil || len(o.passwordFDs.values) != 1 {
			t.Fatal("valid protected Group input rejected", args, err)
		}
	}
	for _, args := range [][]string{
		{"plan", "debug", "-f", "debug.yaml", "--no-input"},
		{"get", "debug", "--group-password-fd", "tenant/group=3"},
		{"up", "debug", "-f", "debug.yaml", "--operation", "original", "--group-password-fd", "tenant/group=2"},
		{"up", "debug", "-f", "debug.yaml", "--operation", "original", "--group-password-fd", "tenant/group=3", "--group-password-fd", "tenant/other=3"},
	} {
		if _, err := parseStandaloneOptions(args, io.Discard); err == nil {
			t.Fatal("Group input crossed the approval command/descriptor boundary", args)
		}
	}
}
