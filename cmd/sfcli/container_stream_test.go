// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"slices"
	"testing"
)

func TestContainerExecCLIKeepsArgvAndRequiresOneOriginalID(t *testing.T) {
	for _, args := range [][]string{
		{"exec", "-p", "app", "web", "--operation", "exec-one", "-it", "--", "/backend", "", "-it", "value with spaces"},
		{"-p", "app", "exec", "--operation", "exec-one", "-i", "-t", "web", "--", "/backend", "", "-it", "value with spaces"},
	} {
		o, err := parseComposeOptions(args, io.Discard)
		if err != nil || !o.container.interactive.value || !o.container.tty.value || !slices.Equal(o.container.argv, []string{"/backend", "", "-it", "value with spaces"}) {
			t.Fatal("argv/TTY parsing", err)
		}
	}
	for _, args := range [][]string{
		{"exec", "-p", "app", "web", "--", "cmd"},
		{"exec", "-p", "app", "web", "--operation", "x", "cmd"},
		{"exec", "-p", "app", "web", "--operation", "x", "--"},
		{"exec", "-p", "app", "web", "--operation", "x", "--json", "--", "cmd"},
		{"exec", "-p", "app", "web", "--operation", "x", "--watch", "--", "cmd"},
		{"exec-status", "-p", "app", "--operation", "x", "web"},
		{"logs", "-p", "app", "web", "-i"},
	} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("mixed/unsafe exec flags", args)
		}
	}
}

func TestContainerFollowAndWatchCLIReuseFiniteQueries(t *testing.T) {
	for _, args := range [][]string{{"logs", "-p", "app", "web", "--follow", "--tail", "2"}, {"top", "-p", "app", "web", "--watch", "--interval", "1s"}, {"stats", "-p", "app", "web", "--watch", "--json"}} {
		o, err := parseComposeOptions(args, io.Discard)
		if err != nil || !composeStreaming(o) || o.container.query.Validate() != nil {
			t.Fatal(args, err)
		}
	}
	for _, args := range [][]string{{"logs", "-p", "app", "web", "--watch"}, {"top", "-p", "app", "web", "--follow"}, {"stats", "-p", "app", "web", "--watch", "--interval", "10ms"}, {"stats", "-p", "app", "web", "--interval", "2s"}, {"logs", "-p", "app", "web", "--follow", "--until", "2026-01-01T00:00:00Z"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("invalid continuous query", args)
		}
	}
}
