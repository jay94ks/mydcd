// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

const webRoutes = `name: cluster-app/web
x-sfc:
  ingress:
  - node: node-a
    host: sfc.example.com
`

// cluster-app/web goes through app diff/deploy/down as a cluster setting.
func TestAppCommandsTakeClusterAppRoutes(t *testing.T) {
	n := newGroup9Node(t)
	file := n.file("web.yaml", webRoutes)
	if out := n.run(0, "app", "diff", "-f", file); !strings.Contains(out, "cluster-app/web") || !strings.Contains(out, "create") {
		t.Fatal("diff before deploy:\n" + out)
	}
	n.run(0, "app", "deploy", "-f", file)
	if out := n.run(0, "app", "diff", "-f", file); strings.Contains(out, "create") || strings.Contains(out, "update") {
		t.Fatal("diff after deploy:\n" + out)
	}
	changed := n.file("web2.yaml", strings.Replace(webRoutes, "sfc.example.com", "ui.example.com", 1))
	if out := n.run(0, "app", "diff", "-f", changed); !strings.Contains(out, "route route-1") || !strings.Contains(out, "sfc.example.com/ -> ui.example.com/") {
		t.Fatal("diff of a changed route:\n" + out)
	}
	n.run(0, "app", "deploy", "-f", changed)
	n.run(0, "app", "down", "cluster-app/web")
	n.run(1, "app", "down", "cluster-app/web")
	n.run(2, "app", "down", "cluster-app/other")
	bad := n.file("bad.yaml", webRoutes+"services:\n  web:\n    image: x\n")
	n.run(1, "app", "deploy", "-f", bad)
}
