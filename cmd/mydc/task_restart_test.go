// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"
)

func TestComposeTaskRestartRequiresExplicitOriginalAndKeepsExactSelector(t *testing.T) {
	for _, args := range [][]string{{"restart", "-p", "app", "web", "--preview"}, {"restart", "-p", "app", "web", "--operation", "incident-1", "--instance", "workload/task/tenant/app/web"}, {"restart-status", "-p", "app", "--operation", "incident-1"}} {
		o, err := parseComposeOptions(args, io.Discard)
		if err != nil {
			t.Fatal(args, err)
		}
		if o.project.value != "app" || o.method == "restart" && o.container.service != "web" {
			t.Fatal("selector changed")
		}
	}
	for _, args := range [][]string{{"restart", "-p", "app", "web"}, {"restart", "-p", "app", "web", "--preview", "--operation", "x"}, {"restart", "-p", "app", "web", "--recreate", "--operation", "x"}, {"restart", "-p", "app", "web", "--operation", "x", "--tail", "5"}, {"restart-status", "-p", "app", "--operation", "x", "--preview"}, {"restart", "-p", "app", "web", "--operation", "x", "--file", "app.yaml"}} {
		if _, err := parseComposeOptions(args, io.Discard); err == nil {
			t.Fatal("ambiguous restart options accepted", args)
		}
	}
}
