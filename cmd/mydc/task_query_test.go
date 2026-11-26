// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"testing"
)

func TestTaskQueryCommandKeepsFiltersAndAllTenantIntent(t *testing.T) {
	o, err := parseTaskListOptions([]string{"--node", "node-a", "--app", "shop", "--after", "opaque", "--all-tenants"}, io.Discard)
	if err != nil || !o.all || o.after != "opaque" || o.selection.Node != "node-a" || o.selection.App != "shop" || o.selection.Tenant != "" {
		t.Fatal("task filters changed", err)
	}
	for _, args := range [][]string{{"extra"}, {"--node", "../node"}, {"--app", "a", "--app", "b"}, {"--unknown"}} {
		if _, err := parseTaskListOptions(args, io.Discard); err == nil {
			t.Fatal("invalid task command", args)
		}
	}
}
