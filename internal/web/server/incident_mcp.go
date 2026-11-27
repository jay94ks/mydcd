// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/web/store"
)

// MCP in incident diagnosis (W2.3a): read tools set to "diagnose" that
// the incident's workspace may use are called before the diagnosis, and
// their answers go to it as data (<mcp-results>). When the incident's
// guidelines name servers, only those are used. Arguments come from the
// tool's input limits (auto.inputs) filled from the incident; a tool with a
// required argument left open is skipped. Answers are not stored; the
// incident keeps how many calls each server got.

const (
	incidentMCPMax     = 4
	incidentMCPTimeout = 20 * time.Second
	incidentMCPText    = 2000
)

// incidentMCPArgs fills the tool's arguments for in (ok false when a
// required one stays open).
func incidentMCPArgs(t *store.MCPTool, in *store.Incident) (map[string]any, bool) {
	args := map[string]any{}
	for _, a := range t.Args {
		var x store.MCPInput
		have := false
		if t.Auto != nil {
			x, have = t.Auto.Inputs[a.Name]
		}
		if !have {
			if a.Required {
				return nil, false
			}
			continue
		}
		v := mcpFill(in, x)
		if x.Kind == "max" {
			v = x.Value
		}
		args[a.Name] = v
	}
	return args, true
}

// incidentMCPReads calls the diagnose tools for in: the <mcp-results>
// block and the names used ("mcp.{server}.{tool}"). in.MCPCalls counts.
func (s *Server) incidentMCPReads(ctx context.Context, in *store.Incident, gd incidentGuides) (string, []string) {
	all, err := s.opt.Store.ListMCPServers()
	if err != nil || len(all) == 0 {
		return "", nil
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })
	ctx, cancel := context.WithTimeout(ctx, incidentMCPTimeout)
	defer cancel()
	var b strings.Builder
	var used []string
	for _, m := range all {
		if len(gd.mcp) > 0 && !slices.Contains(gd.mcp, m.Name) {
			continue
		}
		for _, t := range m.Tools {
			if len(used) >= incidentMCPMax || ctx.Err() != nil {
				break
			}
			if t.Incident != "diagnose" || t.Kind != "read" || !mcpToolFor(m, t, in.Tenant) {
				continue
			}
			args, ok := incidentMCPArgs(t, in)
			if !ok {
				continue
			}
			shown := mcpShown(m.Name, t.Name)
			text, isErr, err := s.mcpCall(ctx, m, t.Name, args)
			if in.MCPCalls == nil {
				in.MCPCalls = map[string]int{}
			}
			in.MCPCalls[m.Name]++
			used = append(used, shown)
			switch {
			case err != nil:
				text = "error: " + mcpErrText(err)
			case isErr:
				text = "the tool reported an error: " + text
			}
			if r := []rune(text); len(r) > incidentMCPText {
				text = string(r[:incidentMCPText]) + "…"
			}
			fmt.Fprintf(&b, "\n<result tool=%q>\n%s\n</result>", shown, guideEscape(text))
		}
	}
	if b.Len() == 0 {
		return "", nil
	}
	return "\n\n<mcp-results>" + b.String() + "\n</mcp-results>", used
}
