// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/observability"
)

// The "기본 제공 앱" card reads the server's cluster apps from the admin
// summary; node-config allows no web action.
func TestNodeSummaryCarriesClusterApps(t *testing.T) {
	host := observability.Host{ClusterApps: []observability.ClusterApp{{Name: "web", Control: "node-config", Image: "sfc/web", Version: "0.9.0", Ports: []observability.ClusterAppPort{{Name: "web", Port: 8080, Protocol: "tcp"}, {Name: "acme", Port: 8081, Protocol: "tcp"}}, Digest: "sha256:" + strings.Repeat("a", 64), State: "running", Address: "10.254.1.2", Restarts: 1}}}
	v := newSummaryView(control.NodeSummaryView{Node: "node-a", Admin: &control.NodeAdminView{Host: &host}})
	raw, _ := json.Marshal(v)
	if !strings.Contains(string(raw), `"clusterApps":[{"name":"web","image":"sfc/web","version":"0.9.0","digest":"sha256:`) || !strings.Contains(string(raw), `"ports":[{"name":"web","port":8080,"protocol":"tcp"},{"name":"acme","port":8081,"protocol":"tcp"}],"state":"running","address":"10.254.1.2","restarts":1,"control":"node-config","actions":[]}]`) {
		t.Fatal(string(raw))
	}
	if raw, _ = json.Marshal(newSummaryView(control.NodeSummaryView{Node: "node-a"})); strings.Contains(string(raw), "clusterApps") {
		t.Fatal("a tenant view carries cluster apps", string(raw))
	}
}

func TestNodeSummaryCarriesBuild(t *testing.T) {
	raw, _ := json.Marshal(newSummaryView(control.NodeSummaryView{Node: "node-a", Build: control.NodeBuildView{Reason: "ENGINE_BUILD_OFF"}}))
	if !strings.Contains(string(raw), `"build":{"enabled":false,"reason":"ENGINE_BUILD_OFF"}`) {
		t.Fatal(string(raw))
	}
	raw, _ = json.Marshal(newSummaryView(control.NodeSummaryView{Node: "node-a", Build: control.NodeBuildView{Enabled: true}}))
	if !strings.Contains(string(raw), `"build":{"enabled":true}`) {
		t.Fatal(string(raw))
	}
}
