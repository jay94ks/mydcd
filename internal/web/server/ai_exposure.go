// SPDX-License-Identifier: Apache-2.0

package server

import (
	"regexp"
	"strings"
)

// What the coordinator does not get (R19). Every screen API route is
// either a tool of aiCatalog or matches one rule here; a new route that is
// neither fails TestAIExposureCoversRoutes. A tool wins over a rule.
//
// Match is "METHOD /path" with the route's own {params}; METHOD may be *,
// and * in the path matches anything (slashes too).
type aiHiddenRule struct {
	Match  string
	Reason string
}

const (
	hideLogin     = "로그인·세션: 사람의 자격 증명을 다룬다"
	hideSelf      = "자기 계정·알림: 사람 자신의 설정이다"
	hideAISelf    = "AI·자동 대응 자신의 설정과 대화: AI가 자기 범위를 바꾸지 않는다"
	hideApproval  = "사람의 승인 단계: AI가 누르면 승인이 아니다"
	hideSecret    = "비밀값·키·봉인: 값이 외부 AI로 가면 안 된다"
	hideShell     = "셸·exec·스트림: 대화형이거나 끝나지 않는 흐름이다"
	hideBytes     = "파일 바이트·업로드 조각: 도구 인자와 결과에 담지 않는다"
	hideLogs      = "로그 원문: 서버 쪽 가림(REQ-20 4) 전에는 보내지 않는다"
	hideHigh      = "높은 영향: AI는 제안하지 않는다(R19 3.5)"
	hideUndecided = "아직 정하지 않음: 영역별로 정해 도구로 내거나 이유를 바꾼다"
)

var aiHidden = []aiHiddenRule{
	{"* /api/", hideLogin},
	{"GET /healthz", hideLogin},
	{"* /api/v1/auth/*", hideLogin},
	{"* /api/v1/login/*", hideLogin},

	{"* /api/v1/me/*", hideSelf},
	{"* /api/v1/prefs", hideSelf},
	{"* /api/v1/notify-prefs", hideSelf},
	{"* /api/v1/notifications*", hideSelf},

	{"* /api/v1/ai/*", hideAISelf},
	{"* /api/v1/system/ai*", hideAISelf},
	{"* /api/v1/system/mcp*", hideAISelf},
	{"* /api/v1/system/automation*", hideAISelf},
	{"* /api/v1/guides*", hideAISelf},
	{"* /api/v1/incidents/policy", hideAISelf},
	{"POST /api/v1/incidents/stop", hideAISelf},
	{"POST /api/v1/incidents/resume", hideAISelf},
	{"* /api/v1/t/{t}/apps/{app}/incident*", hideAISelf},

	{"POST */approve", hideApproval},
	{"POST */reject", hideApproval},
	{"POST /api/v1/t/{t}/apps/{app}/cd/approvals", hideApproval},
	{"POST /api/v1/ops/{id}/result", hideApproval},

	{"POST /api/v1/vault*", hideSecret},
	{"PATCH /api/v1/vault/acl", hideSecret},
	{"PUT /api/v1/vault/approval-age", hideSecret},
	{"POST /api/v1/t/{t}/vault*", hideSecret},
	{"PATCH /api/v1/t/{t}/vault/acl", hideSecret},
	{"PUT /api/v1/t/{t}/vault/approval-age", hideSecret},
	{"* /api/v1/system/seal*", hideSecret},
	{"* /api/v1/system/backup", hideSecret},
	{"PUT /api/v1/dns/providers/{id}/token", hideSecret},
	{"POST /api/v1/certificates", hideSecret},
	{"* /api/v1/acme/accounts*", hideSecret},
	{"POST /api/v1/t/{t}/registries/{id}/credential", hideSecret},
	{"POST /api/v1/system/vps/accounts*", hideSecret},
	{"POST /api/v1/system/owned-vps/accounts*", hideSecret},
	{"POST /api/v1/nodes", hideSecret},
	{"GET /api/v1/nodes/{node}/invitation*", hideSecret},
	{"POST /api/v1/users/{u}/invites*", hideSecret},

	{"* /api/v1/node-shell*", hideShell},
	{"GET /api/v1/nodes/{node}/shell", hideShell},
	{"GET */exec", hideShell},
	{"GET */stream", hideShell},
	{"GET /api/v1/live", hideShell}, // WebSocket 스트림: 바뀐 기록 참조를 끝없이 밀어 준다
	{"POST /api/v1/t/{t}/apps/{app}/call", hideShell},

	{"* */chunks/{n}", hideBytes},
	{"* /api/v1/t/{t}/build-contexts/{id}/zip*", hideBytes},
	{"* /api/v1/t/{t}/build-contexts/{id}/file*", hideBytes},
	{"* /api/v1/t/{t}/volumes/{name}/file", hideBytes},
	{"* /api/v1/t/{t}/registries/{id}/uploads*", hideBytes},
	{"GET /api/v1/t/{t}/registries/{id}/images/layer", hideBytes},
	{"GET /api/v1/acme/certs/{name}/chain", hideBytes},
	{"GET /api/v1/certificates/{id}/chain", hideBytes},

	{"GET */task/logs", hideLogs},
	{"GET /api/v1/t/{t}/builds/{id}/log", hideLogs},
	{"* /api/v1/diag/provider-log*", hideLogs},

	{"* /api/v1/system/restore*", hideHigh},
	{"POST /api/v1/nodes/{node}/drain", hideHigh},
	{"POST /api/v1/nodes/{node}/disks/{disk}/{action}", hideHigh},        // 포맷·마운트: 데이터가 지워질 수 있다
	{"POST /api/v1/nodes/{node}/disk-bundles", hideHigh},                 // 디스크 묶기: 구성원 디스크를 지운다
	{"POST /api/v1/nodes/{node}/disk-bundles/{name}/{action}", hideHigh}, // 묶음 풀기·구성원 교체
	{"POST /api/v1/nodes/{node}/firewall", hideHigh},                     // 방화벽: 서버 접속이 끊길 수 있다
	{"POST /api/v1/firewall", hideHigh},                                  // 클러스터 방화벽: 모든 서버 접속이 끊길 수 있다
	{"POST /api/v1/nodes/{node}/remove", hideHigh},
	{"POST /api/v1/nodes/{node}/force-remove", hideHigh},
	{"POST /api/v1/nodes/{node}/rotate-identity", hideHigh},
	{"POST /api/v1/tenants/{t}/retire*", hideHigh},
	{"POST /api/v1/ledger/rotate", hideHigh},
	{"DELETE /api/v1/trash/{id}", hideHigh},
	{"POST /api/v1/t/{t}/archived/{key}/purge", hideHigh},
	{"DELETE /api/v1/t/{t}/volumes/{name}", hideHigh},
	{"DELETE /api/v1/t/{t}/volumes/{name}/archives/{id}", hideHigh}, // discards the only copy of the data
	{"POST /api/v1/t/{t}/networks/{name}/retire", hideHigh},
	{"POST /api/v1/t/{t}/lifecycles/{name}/retire", hideHigh},
	{"POST /api/v1/t/{t}/registries/{id}/delete", hideHigh},
	{"POST /api/v1/t/{t}/apps/{app}/down", hideHigh},
	{"DELETE /api/v1/system/vps/servers/{name}", hideHigh},
}

// aiUndecided: routes no one has decided on yet. The list only shrinks:
// expose a route as a tool or move it under a reason above.
var aiUndecided = []string{
	"POST /api/v1/ops",
	"GET /api/v1/ops/actions",
	"POST /api/v1/ops/actions/{action}/base",
	"POST /api/v1/ops/{id}/resume",
	"GET /api/v1/ops/{id}/reason",
	"GET /api/v1/ops/{id}/revert",
	"POST /api/v1/ops/{id}/revert",
	"GET /api/v1/trash",
	"GET /api/v1/trash/{id}",
	"POST /api/v1/trash/{id}/restore",
	"POST /api/v1/nodes/{node}/promote",
	"POST /api/v1/nodes/{node}/isolate",
	"POST /api/v1/nodes/{node}/restore",
	"GET /api/v1/nodes/{node}/drain-status",
	"GET /api/v1/nodes/{node}/voter-plan",
	"POST /api/v1/nodes/{node}/demote",
	"GET /api/v1/nodes/{node}/force-remove-plan",
	"GET /api/v1/nodes/{node}/diagnostics",
	"GET /api/v1/image-prunes/{operation}",
	"POST /api/v1/nodes/{node}/storage",
	"PATCH /api/v1/nodes/{node}/storage/{id}",
	"POST /api/v1/nodes/{node}/storage/{id}/drain",
	"DELETE /api/v1/nodes/{node}/storage/{id}",
	"POST /api/v1/nodes/{node}/storage/{id}/remove",
	"GET /api/v1/nodes/{node}/storage/{id}/space",
	"GET /api/v1/nodes/{node}/disk-operations/{operation}",
	"GET /api/v1/storage",
	"GET /api/v1/disks",
	"GET /api/v1/cluster/features",
	"GET /api/v1/raft/compact",
	"POST /api/v1/raft/compact",
	"GET /api/v1/raft/compact/plan",
	"GET /api/v1/raft/compactions/{operation}",
	"GET /api/v1/node-cli-policy",
	"GET /api/v1/tenants/{t}",
	"GET /api/v1/tenants/{t}/members",
	"GET /api/v1/tenants/{t}/retirement",
	"GET /api/v1/users",
	"GET /api/v1/users/{u}",
	"GET /api/v1/users/{u}/scope",
	"PATCH /api/v1/users/{u}/scope",
	"PUT /api/v1/t/{t}/limits/{node}",
	"GET /api/v1/t/{t}/storage",
	"POST /api/v1/t/{t}/images/resolve",
	"GET /api/v1/t/{t}/image-trust",
	"PATCH /api/v1/t/{t}/image-trust",
	"POST /api/v1/t/{t}/image-trust/preview",
	"PUT /api/v1/t/{t}/registries/{id}",
	"GET /api/v1/t/{t}/registries/{id}/images",
	"POST /api/v1/t/{t}/registries/{id}/images/delete",
	"POST /api/v1/t/{t}/registries/{id}/gc",
	"POST /api/v1/t/{t}/registries/{id}/prune/preview",
	"POST /api/v1/t/{t}/registries/{id}/prune",
	"GET /api/v1/t/{t}/registry-maintenance/{operation}",
	"GET /api/v1/t/{t}/registry-maintenance/{operation}/items",
	"POST /api/v1/t/{t}/image-usage",
	"GET /api/v1/t/{t}/registries/{id}/images/manifest",
	"POST /api/v1/t/{t}/registries/{id}/images/tag",
	"GET /api/v1/t/{t}/external-registries",
	"GET /api/v1/t/{t}/external-registries/{id}/users",
	"POST /api/v1/t/{t}/external-registries/{id}/test",
	"PUT /api/v1/t/{t}/external-registries/{id}",
	"DELETE /api/v1/t/{t}/external-registries/{id}",
	"POST /api/v1/t/{t}/external-registries/{id}/bind",
	"POST /api/v1/t/{t}/external-registries/{id}/unbind",
	"GET /api/v1/t/{t}/build-policy",
	"PUT /api/v1/t/{t}/build-policy",
	"GET /api/v1/t/{t}/build-contexts",
	"PUT /api/v1/t/{t}/build-contexts/{id}",
	"POST /api/v1/t/{t}/build-contexts/{id}/delete",
	"POST /api/v1/t/{t}/build-contexts/{id}/commit",
	"POST /api/v1/t/{t}/build-contexts/{id}/versions/{version}/delete",
	"GET /api/v1/t/{t}/build-contexts/{id}/tree",
	"POST /api/v1/t/{t}/build-contexts/{id}/verify",
	"POST /api/v1/t/{t}/build-contexts/{id}/build",
	"POST /api/v1/t/{t}/builds/{id}/cancel",
	"POST /api/v1/t/{t}/builds/{id}/delete",
	"GET /api/v1/t/{t}/build-cache",
	"GET /api/v1/t/{t}/build-cache/entries",
	"POST /api/v1/t/{t}/build-cache/prune",
	"POST /api/v1/t/{t}/registries/{id}/start",
	"POST /api/v1/t/{t}/registries/{id}/stop",
	"GET /api/v1/t/{t}/uploads",
	"POST /api/v1/t/{t}/apps/{app}/observe",
	"GET /api/v1/t/{t}/standalone/{name}/task",
	"GET /api/v1/t/{t}/standalone/{name}/task/history",
	"GET /api/v1/t/{t}/standalone/{name}/task/stats",
	"POST /api/v1/t/{t}/logs/clear", // a direct request with no op: an AI proposal needs one
	"POST /api/v1/t/{t}/apps/plan",
	"POST /api/v1/t/{t}/apps/deploy",
	"GET /api/v1/t/{t}/vault/approvals",
	"GET /api/v1/t/{t}/vault/approvals/granted",
	"PUT /api/v1/t/{t}/apps/{app}/cd/policy",
	"GET /api/v1/t/{t}/apps/{app}/cd/field",
	"GET /api/v1/t/{t}/apps/{app}/cd/values",
	"GET /api/v1/t/{t}/apps/{app}/cd/changes",
	"PUT /api/v1/t/{t}/apps/{app}/cd/overrides",
	"DELETE /api/v1/t/{t}/apps/{app}/cd/overrides",
	"POST /api/v1/t/{t}/apps/{app}/cd/recover",
	"POST /api/v1/t/{t}/apps/{app}/cd/replan",
	"POST /api/v1/t/{t}/apps/{app}/cd/abandon",
	"GET /api/v1/t/{t}/apps/{app}/cd/approvals",
	"POST /api/v1/t/{t}/apps/{app}/cd/probe",
	"GET /api/v1/t/{t}/apps/{app}/cd/local",
	"PUT /api/v1/t/{t}/apps/{app}/cd/local",
	"GET /api/v1/t/{t}/apps/{app}/cd/approvers",
	"POST /api/v1/t/{t}/apps/{app}/cd/approvers",
	"DELETE /api/v1/t/{t}/apps/{app}/cd/approvers",
	"POST /api/v1/t/{t}/networks",
	"POST /api/v1/t/{t}/networks/{name}/dns",
	"GET /api/v1/t/{t}/networks/{name}/dns/names",
	"PATCH /api/v1/t/{t}/networks/{name}/dns/records",
	"GET /api/v1/t/{t}/networks/{name}/change",
	"POST /api/v1/t/{t}/networks/{name}/change",
	"POST /api/v1/t/{t}/networks/{name}/change/drain",
	"POST /api/v1/t/{t}/networks/{name}/change/cancel",
	"POST /api/v1/t/{t}/networks/{name}/change/fence",
	"POST /api/v1/t/{t}/networks/{name}/change/commit",
	"POST /api/v1/t/{t}/networks/{name}/reconfigure",
	"POST /api/v1/t/{t}/networks/{name}/members",
	"POST /api/v1/t/{t}/networks/{name}/members/leave",
	"POST /api/v1/t/{t}/networks/{name}/toggles",
	"GET /api/v1/t/{t}/route-endpoints",
	"POST /api/v1/t/{t}/routes",
	"POST /api/v1/t/{t}/routes/{source}/{id}/withdraw",
	"GET /api/v1/t/{t}/bridge-endpoints",
	"POST /api/v1/t/{t}/bridges",
	"POST /api/v1/t/{t}/bridges/{owner}/{name}/close",
	"POST /api/v1/t/{t}/volumes",
	"POST /api/v1/t/{t}/volumes/{name}/backups/{id}/cancel",
	"DELETE /api/v1/t/{t}/volumes/{name}/backups/{id}",
	"POST /api/v1/t/{t}/volumes/{name}/restore",
	"POST /api/v1/t/{t}/volumes/{name}/restores/{id}/cancel",
	"POST /api/v1/t/{t}/volumes/{name}/archive",
	"POST /api/v1/t/{t}/volumes/{name}/unarchive",
	"POST /api/v1/t/{t}/volumes/{name}/archives/{id}/cancel",
	"PUT /api/v1/t/{t}/volumes/{name}/capacity",
	"POST /api/v1/t/{t}/volumes/{name}/move-plan",
	"POST /api/v1/t/{t}/volumes/{name}/move",
	"GET /api/v1/t/{t}/volumes/{name}/files",
	"POST /api/v1/t/{t}/volumes/{name}/file-grants",
	"DELETE /api/v1/t/{t}/volumes/{name}/file-grants",
	"POST /api/v1/t/{t}/volumes/{name}/move/cancel",
	"DELETE /api/v1/t/{t}/volumes/{name}/retained/{id}",
	"PUT /api/v1/t/{t}/backup-limits/{node}",
	"GET /api/v1/t/{t}/backup-limits",
	"GET /api/v1/t/{t}/volumes/{name}/users",
	"GET /api/v1/t/{t}/networks/{name}/users",
	"GET /api/v1/t/{t}/networks/{name}/tunnels",
	"POST /api/v1/t/{t}/networks/{name}/tunnels/reconnect",
	"POST /api/v1/nodes/{node}/tunnels/{peer}/reconnect",
	"GET /api/v1/tunnel-reconnects/{operation}",
	"GET /api/v1/t/{t}/vault/usages",
	"GET /api/v1/vault",
	"GET /api/v1/vault/usages",
	"GET /api/v1/t/{t}/lifecycle-scripts",
	"GET /api/v1/t/{t}/lifecycles/{name}",
	"PUT /api/v1/t/{t}/lifecycles/{name}",
	"DELETE /api/v1/t/{t}/lifecycles/{name}",
	"GET /api/v1/t/{t}/lifecycle-policy",
	"PUT /api/v1/t/{t}/lifecycle-policy",
	"POST /api/v1/t/{t}/standalone/plan",
	"POST /api/v1/t/{t}/standalone/up",
	"GET /api/v1/t/{t}/standalone/{name}",
	"POST /api/v1/t/{t}/standalone/{name}/{verb}",
	"POST /api/v1/t/{t}/standalone/{name}/observe",
	"GET /api/v1/t/{t}/apps/{app}/layout",
	"PUT /api/v1/t/{t}/apps/{app}/layout",
	"GET /api/v1/t/{t}/archived",
	"GET /api/v1/t/{t}/archived/{key}",
	"GET /api/v1/system/settings",
	"PUT /api/v1/system/settings",
	"DELETE /api/v1/incidents/{id}",
	"GET /api/v1/ingress",
	"GET /api/v1/ingress/blocks",
	"POST /api/v1/ingress/blocks",
	"PUT /api/v1/ingress/blocks/{id}",
	"DELETE /api/v1/ingress/blocks/{id}",
	"GET /api/v1/t/{t}/apps/{app}/ingress",
	"GET /api/v1/ingress/history",
	"GET /api/v1/cluster-apps/{app}/routes",
	"PUT /api/v1/cluster-apps/{app}/routes",
	"DELETE /api/v1/cluster-apps/{app}/routes",
	"GET /api/v1/nodes/{n}/gateways",
	"PUT /api/v1/nodes/{n}/gateways",
	"PUT /api/v1/t/{t}/apps/{app}/ingress/balance",
	"POST /api/v1/t/{t}/apps/{app}/ingress/drain",
	"DELETE /api/v1/t/{t}/apps/{app}/ingress/drain",
	"GET /api/v1/webhooks",
	"POST /api/v1/webhooks",
	"GET /api/v1/webhooks/{name}",
	"PUT /api/v1/webhooks/{name}",
	"DELETE /api/v1/webhooks/{name}",
	"POST /api/v1/webhooks/{name}/rotate",
	"POST /api/v1/webhooks/{name}/test",
	"GET /api/v1/webhooks/{name}/deliveries",
	"GET /api/v1/webhook-links",
	"POST /api/v1/webhook-links",
	"PUT /api/v1/webhook-links/{id}",
	"DELETE /api/v1/webhook-links/{id}",
	"GET /api/v1/system/auto-backup",
	"PUT /api/v1/system/auto-backup",
	"POST /api/v1/system/auto-backup/run",
	"GET /api/v1/audit",
	"GET /api/v1/system/vps",
	"GET /api/v1/system/vps/accounts/{account}/offer",
	"PATCH /api/v1/system/vps/accounts/{account}",
	"DELETE /api/v1/system/vps/accounts/{account}",
	"POST /api/v1/system/vps/servers",
	"POST /api/v1/system/vps/servers/{name}/stop",
	"POST /api/v1/system/vps/servers/{name}/start",
	"POST /api/v1/system/vps/servers/{name}/cap",
	"GET /api/v1/system/vps/servers/{name}/dns-plan",
	"DELETE /api/v1/system/vps/servers/{name}/dns-holds/{domain}",
	"GET /api/v1/system/owned-vps",
	"GET /api/v1/system/owned-vps/accounts/{account}/instances",
	"DELETE /api/v1/system/owned-vps/accounts/{account}",
	"POST /api/v1/system/owned-vps/servers",
	"PATCH /api/v1/system/owned-vps/servers/{name}",
	"DELETE /api/v1/system/owned-vps/servers/{name}",
	"GET /api/v1/certificates",
	"POST /api/v1/certificates/check",
	"GET /api/v1/certificates/{id}",
	"DELETE /api/v1/certificates/{id}",
	"POST /api/v1/certificates/{id}/disable",
	"GET /api/v1/acme/responder",
	"GET /api/v1/acme/auto",
	"PUT /api/v1/acme/auto",
	"POST /api/v1/acme/auto/ignore",
	"GET /api/v1/acme/cas",
	"GET /api/v1/acme/certs",
	"POST /api/v1/acme/certs",
	"GET /api/v1/acme/certs/{name}",
	"PUT /api/v1/acme/certs/{name}",
	"DELETE /api/v1/acme/certs/{name}",
	"POST /api/v1/acme/certs/{name}/issue",
	"POST /api/v1/acme/certs/{name}/revoke",
	"GET /api/v1/dns/vendors",
	"GET /api/v1/dns/providers",
	"POST /api/v1/dns/providers",
	"POST /api/v1/dns/providers/{id}/check",
	"PUT /api/v1/dns/providers/{id}",
	"DELETE /api/v1/dns/providers/{id}",
	"GET /api/v1/dns/providers/{id}/domains",
	"GET /api/v1/dns/domains",
	"POST /api/v1/dns/domains",
	"PUT /api/v1/dns/domains/{domain}",
	"DELETE /api/v1/dns/domains/{domain}",
	"PUT /api/v1/dns/domains/{domain}/provider",
	"DELETE /api/v1/dns/domains/{domain}/provider",
	"GET /api/v1/dns/domains/{domain}/records",
	"GET /api/v1/dns/domains/{domain}/servers",
	"PUT /api/v1/dns/domains/{domain}/servers/{node}",
	"POST /api/v1/dns/domains/{domain}/servers/check",
	"POST /api/v1/dns/domains/{domain}/plan",
	"POST /api/v1/dns/domains/{domain}/apply",
	"GET /api/v1/dns/domains/{domain}/history",
	"GET /api/v1/dns/domains/{domain}/propagation",
	"POST /api/v1/dns/domains/{domain}/history/{id}/revert",
	"DELETE /api/v1/dns/domains/{domain}/history/{id}",
	"GET /api/v1/dns/domains/{domain}/snapshots",
	"POST /api/v1/dns/domains/{domain}/snapshots/{id}/restore",
}

var aiHiddenRE = func() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(aiHidden))
	for i, h := range aiHidden {
		method, path, _ := strings.Cut(h.Match, " ")
		m := regexp.QuoteMeta(method)
		if method == "*" {
			m = "[A-Z]*"
		}
		p := strings.ReplaceAll(regexp.QuoteMeta(path), `\*`, ".*")
		out[i] = regexp.MustCompile("^" + m + " " + p + "$")
	}
	return out
}()

// aiHiddenReason is why a route is not a tool ("" = no rule).
func aiHiddenReason(pattern string) string {
	if !strings.Contains(pattern, " ") {
		pattern = "* " + pattern
	}
	for _, u := range aiUndecided {
		if u == pattern {
			return hideUndecided
		}
	}
	for i, re := range aiHiddenRE {
		if re.MatchString(pattern) || strings.HasPrefix(pattern, "* ") && re.MatchString("GET"+pattern[1:]) {
			return aiHidden[i].Reason
		}
	}
	return ""
}
