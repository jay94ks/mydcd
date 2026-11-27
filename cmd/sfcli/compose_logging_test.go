// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"
)

func TestLogClearRequiresExplicitPlanOrRecreationAndExactOriginalSelection(t *testing.T) {
	for _, args := range [][]string{
		{"logs-clear", "-p", "app", "web", "--preview"},
		{"logs-clear", "-p", "app", "web", "--recreate", "--operation", "one", "--instance", "workload/task/tenant/app/web"},
		{"logs-clear-status", "-p", "app", "--operation", "one"},
	} {
		if _, err := parseComposeOptions(args, io.Discard); err != nil {
			t.Fatal("valid log operation", args, err)
		}
	}
	for _, args := range [][]string{
		{"logs-clear", "-p", "app", "web"},
		{"logs-clear", "-p", "app", "web", "--recreate"},
		{"logs-clear", "-p", "app", "web", "--preview", "--recreate", "--operation", "one"},
		{"logs-clear", "-p", "app", "web", "--preview", "--operation", "one"},
		{"logs-clear", "-p", "app", "web", "--recreate", "--operation", "../other"},
		{"logs-clear", "-p", "app", "web", "--preview", "--tail", "2"},
		{"logs-clear", "-p", "app", "web", "--preview", "--f", "app.yaml"},
		{"logs-clear-status", "-p", "app", "--operation", "one", "--instance", "other"},
		{"logs-clear-status", "-p", "app", "--operation", "one", "--recreate"},
		{"logs", "-p", "app", "web", "--preview"},
	} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("ambiguous/destructive options accepted", args)
		}
	}
}
