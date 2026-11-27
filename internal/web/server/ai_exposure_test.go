// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/web/store"
)

var updateGolden = flag.Bool("update", false, "rewrite golden files")

func routePatterns(t *testing.T) []string {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(Options{Client: strictFake(), Store: st, Logger: discardLogger()}).mux.patterns
}

// Every tool names a registered route.
func TestAIToolsNameRoutes(t *testing.T) {
	routes := routePatterns(t)
	for _, d := range aiCatalog {
		if p := d.Method + " " + d.Path; !slices.Contains(routes, p) {
			t.Errorf("tool %s: %s is not a registered route", d.Name, p)
		}
	}
}

// Every route is a tool or has a reason not to be one.
func TestAIExposureCoversRoutes(t *testing.T) {
	routes := routePatterns(t)
	tools := map[string]bool{}
	for _, d := range aiCatalog {
		tools[d.Method+" "+d.Path] = true
	}
	var missing []string
	for _, p := range routes {
		if !tools[p] && aiHiddenReason(p) == "" {
			missing = append(missing, p)
		}
	}
	if len(missing) > 0 {
		var b strings.Builder
		for _, p := range missing {
			fmt.Fprintf(&b, "\t%q,\n", p)
		}
		t.Errorf("%d routes are neither a coordinator tool nor in aiHidden; add a tool or a rule with its reason:\n%s", len(missing), b.String())
	}
	// No stale decisions: each undecided route exists and is not a tool,
	// and each rule still matches a route.
	for _, u := range aiUndecided {
		if !slices.Contains(routes, u) || tools[u] {
			t.Errorf("aiUndecided %q: not a route, or already a tool", u)
		}
	}
	for i, re := range aiHiddenRE {
		if !slices.ContainsFunc(routes, func(p string) bool {
			return re.MatchString(p) || !strings.Contains(p, " ") && re.MatchString("GET "+p)
		}) {
			t.Errorf("aiHidden %q matches no route", aiHidden[i].Match)
		}
	}
}

// The catalog the model sees stays byte-identical unless changed on
// purpose (the request prefix is cached; R19 refactors must not move it).
func TestAICatalogGolden(t *testing.T) {
	type row struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Core        bool           `json:"core,omitempty"`
		Schema      map[string]any `json:"schema"`
	}
	var rows []row
	for _, x := range aiTools {
		rows = append(rows, row{x.Name, x.Description, x.Core, x.Schema})
	}
	got, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "ai_catalog.golden.json")
	if *updateGolden {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("coordinator catalog changed; if on purpose, run go test -run TestAICatalogGolden -update")
	}
}

// Every path value has a description and every argument of a change tool
// has a card label.
func TestAIArgInfo(t *testing.T) {
	for _, d := range aiCatalog {
		for _, p := range d.pathParams() {
			if aiArgInfos[p].PathDesc == "" {
				t.Errorf("tool %s: path value %q has no description in aiArgInfos", d.Name, p)
			}
		}
		if d.Kind != aiKindChange {
			continue
		}
		for k := range d.schema()["properties"].(map[string]any) {
			if aiArgInfos[k].Label == "" {
				t.Errorf("tool %s: argument %q has no card label in aiArgInfos", d.Name, k)
			}
		}
	}
}

// Every change the AI leads to has one row in webActions, and none of the
// ones it may propose is high (R19 3.5).
func TestAIActionsTable(t *testing.T) {
	for _, d := range aiCatalog {
		if d.Kind != aiKindChange {
			continue
		}
		w, ok := webActions[d.Action]
		if !ok {
			t.Errorf("tool %s: action %q has no webActions row", d.Name, d.Action)
			continue
		}
		if !aiAllows(w.Impact) {
			t.Errorf("tool %s: %s is high impact; the AI must not propose it", d.Name, d.Action)
		}
		if !w.Reversible && w.Confirm == "" {
			t.Errorf("tool %s: irreversible %s needs a Confirm argument", d.Name, d.Action)
		}
	}
	for _, a := range incidentActions {
		if _, ok := webActions[a.Action]; !ok {
			t.Errorf("incident action %s: %q has no webActions row", a.ID, a.Action)
		}
	}
}

func TestMCPImpact(t *testing.T) {
	for _, c := range []struct {
		tool store.MCPTool
		want string
	}{
		{store.MCPTool{Kind: "read"}, impactLow},
		{store.MCPTool{Kind: "notify"}, impactLow},
		{store.MCPTool{Kind: "change"}, impactMedium},
		{store.MCPTool{Kind: "change", Auto: &store.MCPAuto{Floor: impactHigh}}, impactHigh},
		{store.MCPTool{Kind: "change", Auto: &store.MCPAuto{Floor: impactLow}}, impactLow},
	} {
		if got := mcpImpact(&c.tool); got != c.want {
			t.Errorf("mcpImpact(%+v) = %s, want %s", c.tool, got, c.want)
		}
	}
}

func TestInProcessRoutesRegistered(t *testing.T) {
	routes := routePatterns(t)
	for _, p := range inProcessRoutes {
		if !slices.Contains(routes, p) {
			t.Errorf("%s is not a registered route", p)
		}
	}
	if m, p := routePath(routeTunnelReconnect, "t", "a b", "name", "n/1"); m != "POST" || p != "/api/v1/t/a%20b/networks/n%2F1/tunnels/reconnect" {
		t.Errorf("routePath = %s %s", m, p)
	}
}
