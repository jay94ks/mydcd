// SPDX-License-Identifier: Apache-2.0

package server

// Coordinator tools: the cluster and its servers. One line per tool; see ai_tools.go
// for the fields and R19 for the rules.
var aiToolsCluster = []aiToolDef{
	{Name: "nodes_list", Desc: "List cluster servers (nodes) with role, state, cordon and revision.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes", Props: afterQ},
	{Name: "nodes_summary", Desc: "Per-server CPU, memory and disk usage summary.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/summary", Props: tenantQ},
	{Name: "node_tasks", Desc: "Containers (tasks) running on one server.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/tasks", Props: map[string]any{"tenant": str("workspace ID to narrow to"), "after": str("page cursor")}},
	{Name: "node_storage", Desc: "Storage roots of one server and their space.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/storage", Props: afterQ},
	{Name: "node_disks", Desc: "Disks of one server (size, used, mount).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/disks"},
	{Name: "node_firewall", Desc: "One server's inbound firewall: whether sfcd controls it, policy, locked and operator rules.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/firewall"},
	{Name: "cluster_firewall", Desc: "The cluster firewall every managed server applies under its own: default policy and shared rules (required ones no server can override).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/firewall"},
	{Name: "node_firewall_log", Desc: "Earlier firewall changes of one server, newest first.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/firewall/log", Props: map[string]any{"before": str("only changes before this revision")}},
	{Name: "node_image_prune_plan", Desc: "Plan which unused images on a server can be removed and the space freed. Its plan value goes to node_image_prune.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/image-prune-plan"},
	{Name: "node_drain_plan", Desc: "Plan moving every task off a server: what moves where and what is blocked. Draining is high impact: a person does it on the server screen, never through a proposal.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/drain-plan"},
	{Name: "node_remove_plan", Desc: "What removing a server from the cluster would need and block.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/nodes/{node}/remove-plan"},
	{Name: "cluster_raft", Desc: "Control plane (Raft) status: leader, voters, health.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/raft"},
	{Name: "cluster_mesh", Desc: "Server-to-server network (mesh) links and their state.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/mesh"},
	{Name: "events_list", Desc: "Recent cluster events, newest first.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/events",
		Props: map[string]any{"tenant": str("workspace ID to narrow to"), "since": str("event cursor to read after"), "limit": integer("at most this many (default 50)")}},
	{Name: "node_cordon", Desc: "Stop new placements on a server (running tasks stay).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/cordon",
		Props: map[string]any{"reason": str("why, shown with the operation")}, Title: "{node} 서버에 새 배치 막기", Action: "cordon-node", Target: "node/{node}"},
	{Name: "node_uncordon", Desc: "Allow new placements on a cordoned server again.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/uncordon",
		Title: "{node} 서버에 배치 다시 허용", Action: "uncordon-node", Target: "node/{node}"},
	{Name: "node_image_prune", Desc: "Remove a server's unused images (from node_image_prune_plan).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/nodes/{node}/image-prune",
		Props: map[string]any{"plan": str("plan value from node_image_prune_plan")}, Required: []string{"plan"},
		Title: "{node} 서버의 쓰지 않는 이미지 정리", Action: "prune-node-images", Target: "node/{node}"},
}
