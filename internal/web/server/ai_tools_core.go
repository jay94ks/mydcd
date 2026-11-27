// SPDX-License-Identifier: Apache-2.0

package server

// Coordinator tools: always-loaded and cross-area reads (operations,
// workspaces, dashboard, incidents). One line per tool; see ai_tools.go
// for the fields and R19 for the rules.
var aiToolsCore = []aiToolDef{
	{Name: "ops_list", Desc: "List the person's recent operations (changes sent from the web) with state.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/ops"},
	{Name: "ops_get", Desc: "Read one operation's state and result by op ID (after a proposal was approved).", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/ops/{id}"},
	{Name: "tenants_list", Desc: "List the workspaces (tenants) the person can see.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/tenants"},
	{Name: "dashboard_get", Desc: "Cluster dashboard summary: servers, apps, alerts.", Kind: aiKindRead, Core: true, Method: "GET", Path: "/api/v1/dashboard"},
	{Name: "incidents_list", Desc: "List incidents (detected faults) the person can see, newest first, with the decision on each temporary action.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/incidents",
		Props: map[string]any{"scope": str("app or cluster"), "decision": str("pending, auto, approved, rejected, expired, none"), "tenant": str("workspace"), "app": str("app name")}},
	{Name: "incidents_get", Desc: "Read one incident: signals, timeline, candidates, assessment and any pending approval.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/incidents/{id}"},
}
