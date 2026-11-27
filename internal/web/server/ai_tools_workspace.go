// SPDX-License-Identifier: Apache-2.0

package server

// Coordinator tools: resources of one workspace. One line per tool; see ai_tools.go
// for the fields and R19 for the rules.
var aiToolsWorkspace = []aiToolDef{
	{Name: "apps_list", Desc: "Apps in a workspace with deployment state and health.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps", Props: afterQ},
	{Name: "tasks_list", Desc: "All containers (tasks) of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/tasks", Props: afterQ},
	{Name: "resources_list", Desc: "Shared resources of a workspace (networks, volumes, vault, registries…).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/resources", Props: afterQ},
	{Name: "networks_list", Desc: "Networks of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/networks", Props: afterQ},
	{Name: "volumes_list", Desc: "Data stores (volumes) of a workspace with size and placement.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volumes", Props: afterQ},
	{Name: "volume_get", Desc: "One data store (volume) with its backups and users.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volumes/{name}"},
	{Name: "volume_backups_list", Desc: "Backups of a workspace's data stores.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/volume-backups", Props: afterQ},
	{Name: "vault_list", Desc: "Secret vault entries of a workspace: paths, key names and access. Never values.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/vault", Props: afterQ},
	{Name: "lifecycles_list", Desc: "Lifecycle scripts of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/lifecycles", Props: afterQ},
	{Name: "routes_list", Desc: "External access routes of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/routes"},
	{Name: "registries_list", Desc: "Image registries of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/registries"},
	{Name: "builds_list", Desc: "Image builds of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/builds"},
	{Name: "standalone_list", Desc: "Single containers (standalone) of a workspace.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/standalone"},
	{Name: "volume_backup", Desc: "Start a backup of one data store (volume).", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/volumes/{name}/backups",
		Props: map[string]any{"app": str("app that owns the data store, if any")},
		Title: "{name} 데이터 저장소 백업", Action: "begin-volume-backup", Target: "volume/{name}"},
}
