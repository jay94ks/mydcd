// SPDX-License-Identifier: Apache-2.0

package server

// Coordinator tools: one app and its tasks. One line per tool; see ai_tools.go
// for the fields and R19 for the rules.
var aiToolsApp = []aiToolDef{
	{Name: "app_tasks", Desc: "Containers (tasks) of one app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/tasks", Props: afterQ},
	{Name: "app_operation", Desc: "One app operation's progress and result.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/operations/{id}"},
	{Name: "app_source", Desc: "The running app.yaml of an app (secret-like values masked).", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/source", Props: map[string]any{"version": integer("app version (default: current)")}},
	{Name: "app_revisions", Desc: "Version history of an app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/revisions", Props: afterQ},
	{Name: "app_cd", Desc: "Automatic deployment (CD) state of an app: candidate, pause, last sync.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/cd"},
	{Name: "app_cd_history", Desc: "Automatic deployment history of an app.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/cd/history", Props: afterQ},
	{Name: "app_relocation_check", Desc: "Whether an app's tasks can move to other servers.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/relocation-check"},
	{Name: "app_stored_logs", Desc: "What each server's log store keeps for an app (or one service): container, task key, lines, size; includes containers that are gone.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/logs/stored", Props: map[string]any{"app": str("app name"), "service": str("service name")}, Required: []string{"app"}},
	{Name: "task_detail", Desc: "One task's detail: state, restarts, last exit code, placement.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task", Props: sel, Required: []string{"service"}},
	{Name: "task_history", Desc: "One task's recent state changes and exits.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task/history", Props: sel, Required: []string{"service"}},
	{Name: "task_stats", Desc: "One task's CPU and memory samples.", Kind: aiKindRead, Method: "GET", Path: "/api/v1/t/{t}/apps/{app}/task/stats", Props: sel, Required: []string{"service"}},
	{Name: "task_restart", Desc: "Restart one task of an app.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/task/restart",
		Props: sel, Required: []string{"service", "instance"},
		Title: "{app}의 {service} 작업 다시 시작", Action: "restart-task", Target: "app/{app}"},
	{Name: "app_cd_sync", Desc: "Deploy an app's automatic deployment candidate now.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/sync",
		Title: "{app} 자동 배포 후보 지금 배포", Action: "sync-app", Target: "app/{app}"},
	{Name: "app_cd_pause", Desc: "Pause an app's automatic deployment.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/pause",
		Title: "{app} 자동 배포 멈추기", Action: "pause-app-cd", Target: "app/{app}"},
	{Name: "app_cd_resume", Desc: "Resume an app's paused automatic deployment.", Kind: aiKindChange, Method: "POST", Path: "/api/v1/t/{t}/apps/{app}/cd/resume",
		Title: "{app} 자동 배포 다시 켜기", Action: "resume-app-cd", Target: "app/{app}"},
}
