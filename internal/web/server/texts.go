// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"maps"
	"net/http"
	"strings"

	"github.com/jay94ks/seafield/internal/web/store"
)

// Web-made text people read, in each screen language
// (devel/design/web-i18n.md). Korean is the source; a code missing in
// another language falls back to Korean. {name} takes Args[name] as is:
// values such as sfcd error codes, hosts and names are never translated.
var texts = map[string]map[string]string{
	// operations (notify.go)
	"op-failed":         {langKorean: "작업 실패: {what}", langEnglish: "Operation failed: {what}"},
	"op-failed.code":    {langKorean: "{code}", langEnglish: "{code}"},
	"op-unknown":        {langKorean: "결과 확인 필요: {what}", langEnglish: "Check the result: {what}"},
	"op-unknown.body":   {langKorean: "결과를 알 수 없습니다. 같은 작업으로 결과를 확인하세요.", langEnglish: "The result is unknown. Check it with the same operation."},
	"deploy-done":       {langKorean: "배포 완료: {target}", langEnglish: "Deployed: {target}"},
	"move-started":      {langKorean: "저장소 옮기기 시작: {target}", langEnglish: "Volume move started: {target}"},
	"move-started.body": {langKorean: "서버들이 자료를 복사하고 있습니다. 진행 상태는 저장소 화면에서 볼 수 있습니다.", langEnglish: "The servers are copying the data. See progress on the Volumes screen."},

	// certificates (acme.go, acme_auto.go)
	"cert-key-type":          {langKorean: "인증서 키 형식 바꿈: {name}", langEnglish: "Certificate key type changed: {name}"},
	"cert-key-type.body":     {langKorean: "{from} 대신 {to}로 받습니다", langEnglish: "Requesting {to} instead of {from}"},
	"cert-issue-failed":      {langKorean: "인증서 발급 실패: {name}", langEnglish: "Certificate issuance failed: {name}"},
	"cert-expiring":          {langKorean: "인증서 만료 {days}일 전: {name}", langEnglish: "Certificate expires in {days} days: {name}"},
	"cert-manual-renew":      {langKorean: "인증서 직접 갱신 필요: {name}", langEnglish: "Renew the certificate yourself: {name}"},
	"cert-manual-renew.body": {langKorean: "웹 자동 작업 계정이 없어 자동으로 갱신하지 못합니다. 자동 작업 계정을 만들거나 발급을 눌러 주세요.", langEnglish: "There is no web automation account, so it cannot renew automatically. Create an automation account or press Issue."},
	"cert-auto-wait":         {langKorean: "인증서 자동 발급 대기: {host}", langEnglish: "Automatic certificate waiting: {host}"},
	"cert-auto-wait.not-registered": {langKorean: "클러스터에 등록된 도메인 아래 이름이 아니라 받을 수 없습니다.",
		langEnglish: "The name is not under a domain registered in the cluster, so it cannot be issued."},
	"cert-auto-wait.no-responder": {langKorean: "DNS 공급자가 없는 도메인인데 HTTP 확인 응답기가 꺼져 있거나 클러스터에 등록되지 않았습니다.",
		langEnglish: "The domain has no DNS provider, and the HTTP challenge responder is off or not registered in the cluster."},
	"cert-auto-wait.not-assigned": {langKorean: "이 호스트를 쓰는 작업 공간에 그 이름이 배정되지 않았습니다.", langEnglish: "The name is not assigned to the workspace that uses this host."},
	"cert-auto-wait.auto-off":     {langKorean: "이 도메인은 자동 발급이 꺼져 있습니다.", langEnglish: "Automatic issuance is off for this domain."},
	"cert-auto-wait.caa-blocked":  {langKorean: "CAA 레코드가 이 인증 기관을 막습니다.", langEnglish: "A CAA record blocks this certificate authority."},
	"cert-auto-wait.rate-limit":   {langKorean: "인증 기관 요청 수 한도에 닿았습니다.", langEnglish: "The certificate authority's rate limit was reached."},

	// web data backup (auto_backup.go)
	"backup-failed": {langKorean: "웹 데이터 자동 백업을 하지 못했습니다", langEnglish: "Automatic web data backup failed"},
	"backup-failed.body": {langKorean: "예약된 백업을 쓰지 못했습니다({code}). 설정 화면에서 '지금 백업'을 누르거나 자동 작업 계정을 확인해 주세요.",
		langEnglish: "The scheduled backup could not be written ({code}). Press 'Back up now' in Settings or check the automation account."},
	"backup-failed.no-automation": {langKorean: "자동 작업 계정이 없어 예약된 백업을 쓰지 못했습니다. 설정 화면에서 자동 작업 계정을 만들거나 '지금 백업'을 눌러 주세요.",
		langEnglish: "There is no automation account, so the scheduled backup could not be written. Create one in Settings or press 'Back up now'."},

	// DNS and VPS (dns.go, vps_dns.go)
	"dns-failed":          {langKorean: "DNS 변경 실패: {domain}", langEnglish: "DNS change failed: {domain}"},
	"dns-failed.error":    {langKorean: "{error}", langEnglish: "{error}"},
	"vps-dns-failed":      {langKorean: "VPS 중지: DNS 변경 실패: {domain}", langEnglish: "VPS stopped: DNS change failed: {domain}"},
	"vps-dns-failed.body": {langKorean: "{vps} 주소를 DNS에서 빼지 못했습니다({kind}).", langEnglish: "Could not remove {vps}'s address from DNS ({kind})."},
	"vps-stopped":         {langKorean: "VPS 중지: {domain}", langEnglish: "VPS stopped: {domain}"},
	"vps-stopped.body": {langKorean: "{vps}을(를) 멈춰 DNS 레코드 {sets}개에서 그 주소를 임시로 뺐습니다(재개하면 되돌림).",
		langEnglish: "{vps} was stopped, so its address was taken out of {sets} DNS records for now (restored on resume)."},
	"vps-stopped.kept":   {langKorean: "이 서버만 받는 레코드 {kept}개는 남겼습니다.", langEnglish: "{kept} records that only this server serves were kept."},
	"vps-restore-failed": {langKorean: "DNS 원복 못 함: {domain}", langEnglish: "DNS not restored: {domain}"},
	"vps-restore-failed.body": {langKorean: "{vps}을(를) 재개했지만 {records} 레코드는 되돌리지 않았습니다. 중지 동안 레코드가 바뀌었습니다. 외부 도메인에서 확인하고 직접 고치세요.",
		langEnglish: "{vps} was resumed, but the {records} records were not restored because they changed while it was stopped. Check them at the domain provider and fix them yourself."},

	// incidents, MCP, webhooks
	"incident-approval":         {langKorean: "승인 요청: {title}", langEnglish: "Approval requested: {title}"},
	"incident-approval.note":    {langKorean: "{note}", langEnglish: "{note}"},
	"mcp-tools-changed":         {langKorean: "MCP 서버 {name}의 도구가 바뀌었어요", langEnglish: "The tools of MCP server {name} changed"},
	"mcp-tools-changed.added":   {langKorean: "새 도구 {count}개(꺼진 채): {tools}", langEnglish: "{count} new tools (off): {tools}"},
	"mcp-tools-changed.removed": {langKorean: "없어진 도구 {removedCount}개: {removedTools}", langEnglish: "{removedCount} tools removed: {removedTools}"},
	"webhook-off":               {langKorean: "웹훅 {name}이(가) 꺼졌어요", langEnglish: "Webhook {name} was turned off"},
	"webhook-off.body":          {langKorean: "{count}번 잇달아 보내지 못해 껐어요 ({error}). 확인한 뒤 다시 켜 주세요.", langEnglish: "It failed {count} times in a row, so it was turned off ({error}). Check it and turn it on again."},

	// a value shown as it is (an MCP tool title, a name)
	"text": {langKorean: "{text}", langEnglish: "{text}"},

	// incidents: rules (incident_watch.go incidentRules; Korean matches the table)
	"incident.title":                           {langKorean: "{rule}: {where}", langEnglish: "{rule}: {where}"},
	"incident-rule.task-restarted.title":       {langKorean: "컨테이너 재시작 반복", langEnglish: "Container keeps restarting"},
	"incident-rule.task-restarted.words":       {langKorean: "10분 안에 3번 재시작", langEnglish: "3 restarts in 10 minutes"},
	"incident-rule.probe-failed.title":         {langKorean: "상태 검사 연속 실패", langEnglish: "Health checks keep failing"},
	"incident-rule.probe-failed.words":         {langKorean: "10분 안에 상태 검사 5번 실패", langEnglish: "5 failed health checks in 10 minutes"},
	"incident-rule.task-exited.title":          {langKorean: "컨테이너 시작 직후 종료", langEnglish: "Container exits right after start"},
	"incident-rule.task-exited.words":          {langKorean: "10분 안에 2번 종료", langEnglish: "2 exits in 10 minutes"},
	"incident-rule.node-unreachable.title":     {langKorean: "서버 연결 끊김", langEnglish: "Server unreachable"},
	"incident-rule.node-unreachable.words":     {langKorean: "서버 연결 끊김", langEnglish: "Server unreachable"},
	"incident-rule.node-resource-low.title":    {langKorean: "서버 자원 부족", langEnglish: "Server low on resources"},
	"incident-rule.node-resource-low.words":    {langKorean: "서버 자원 부족", langEnglish: "Server low on resources"},
	"incident-rule.tunnel-down.title":          {langKorean: "서버 간 망 끊김", langEnglish: "Link between servers down"},
	"incident-rule.tunnel-down.words":          {langKorean: "서버 간 망 끊김", langEnglish: "Link between servers down"},
	"incident-rule.cd-post-check-failed.title": {langKorean: "배포 후 확인 실패", langEnglish: "Post-deploy check failed"},
	"incident-rule.cd-post-check-failed.words": {langKorean: "배포 후 확인 실패", langEnglish: "Post-deploy check failed"},

	// incidents: temporary actions (incident_policy.go incidentActions; Korean matches the table)
	"incident-action.restart-task":      {langKorean: "재시작 반복 중인 컨테이너 재시작", langEnglish: "Restart the restarting container"},
	"incident-action.pause-cd":          {langKorean: "자동 배포 일시 정지", langEnglish: "Pause automatic deploys"},
	"incident-action.cd-rollback":       {langKorean: "자동 배포 직후 되돌리기", langEnglish: "Roll back right after an automatic deploy"},
	"incident-action.rollback-previous": {langKorean: "직전 버전으로 되돌리기", langEnglish: "Roll back to the previous version"},
	"incident-action.move-service":      {langKorean: "다른 서버로 재배치", langEnglish: "Move to another server"},
	"incident-action.cordon-node":       {langKorean: "문제 서버를 새 배치 대상에서 잠시 제외", langEnglish: "Keep new placements off the server for now"},
	"incident-action.reconnect-tunnel":  {langKorean: "서버 간 망(터널) 다시 연결", langEnglish: "Reconnect the link (tunnel) between servers"},
	"incident-action.restart-registry":  {langKorean: "이미지 저장소 다시 시작", langEnglish: "Restart the image registry"},
	"incident-action.prune-images":      {langKorean: "서버 이미지 캐시 정리", langEnglish: "Clean the server's image cache"},
	"incident-action.drain-node":        {langKorean: "서버 비우기", langEnglish: "Drain the server"},
	"incident-note.rollback-pause":      {langKorean: "{versions}, 자동 배포 멈춤", langEnglish: "{versions}, automatic deploys paused"},
	"incident-note.prune":               {langKorean: "{node}: 안 쓰는 이미지 {count}개, {mb} MB", langEnglish: "{node}: {count} unused images, {mb} MB"},

	"impact.low":    {langKorean: "낮음", langEnglish: "low"},
	"impact.medium": {langKorean: "보통", langEnglish: "medium"},
	"impact.high":   {langKorean: "높음", langEnglish: "high"},

	"incident-by.rule":       {langKorean: "규칙", langEnglish: "Rules"},
	"incident-by.assessment": {langKorean: "영향 평가", langEnglish: "Impact assessment"},

	"incident-step.diagnosis":  {langKorean: "진단", langEnglish: "Diagnosis"},
	"incident-step.assessment": {langKorean: "영향 평가", langEnglish: "Impact assessment"},

	"incident-input.rules":      {langKorean: "규칙", langEnglish: "Rules"},
	"incident-input.signals":    {langKorean: "최근 신호", langEnglish: "Recent signals"},
	"incident-input.candidates": {langKorean: "임시 조치 후보", langEnglish: "Temporary action candidates"},
	"incident-input.guides":     {langKorean: "행동 지침", langEnglish: "Guidelines"},
	"incident-input.action":     {langKorean: "조치 정의", langEnglish: "Action definition"},
	"incident-input.facts":      {langKorean: "수집한 사실", langEnglish: "Collected facts"},

	"incident-field.action": {langKorean: "조치", langEnglish: "Action"},
	"incident-field.target": {langKorean: "대상", langEnglish: "Target"},
	"incident-field.impact": {langKorean: "영향", langEnglish: "Impact"},
	"incident-field.rule":   {langKorean: "감지", langEnglish: "Detected by"},
	"incident-field.note":   {langKorean: "내용", langEnglish: "Details"},

	"guide-scope.app":     {langKorean: "앱", langEnglish: "app"},
	"guide-scope.tenant":  {langKorean: "작업 공간", langEnglish: "workspace"},
	"guide-scope.cluster": {langKorean: "클러스터", langEnglish: "cluster"},

	// incidents: why a candidate was left out
	"incident-skip":                     {langKorean: "{action}: {why}", langEnglish: "{action}: {why}"},
	"incident-skip.not-buildable":       {langKorean: "아직 자동으로 만들 수 없음", langEnglish: "cannot be built automatically yet"},
	"incident-skip.no-task":             {langKorean: "대상 컨테이너를 알 수 없음", langEnglish: "the target container is unknown"},
	"incident-skip.not-cd":              {langKorean: "지금 버전이 자동 배포로 올라온 것이 아님", langEnglish: "the current version was not deployed automatically"},
	"incident-skip.no-node":             {langKorean: "대상 서버를 알 수 없음", langEnglish: "the target server is unknown"},
	"incident-skip.images-unread":       {langKorean: "지울 이미지 목록을 읽지 못함", langEnglish: "could not read the images to remove"},
	"incident-skip.no-unused-images":    {langKorean: "안 쓰는 이미지가 없음", langEnglish: "there are no unused images"},
	"incident-skip.link-unknown":        {langKorean: "끊긴 링크의 작업 공간·망을 알 수 없음", langEnglish: "the workspace or network of the broken link is unknown"},
	"incident-skip.link-not-ends":       {langKorean: "끊김을 본 서버가 링크의 양 끝이 아님", langEnglish: "the server that saw it is not an end of the link"},
	"incident-skip.versions-unread":     {langKorean: "버전을 읽지 못함", langEnglish: "could not read the versions"},
	"incident-skip.no-previous":         {langKorean: "직전 버전이 없음", langEnglish: "there is no previous version"},
	"incident-skip.policy-off":          {langKorean: "앱 정책에서 꺼짐", langEnglish: "off in the app policy"},
	"incident-skip.always-approve":      {langKorean: "이 앱은 항상 승인", langEnglish: "this app always asks for approval"},
	"incident-skip.window-passed":       {langKorean: "배포 뒤 허용 시간이 지남", langEnglish: "the time allowed after the deploy has passed"},
	"incident-skip.migration":           {langKorean: "데이터 이전 있음 표시", langEnglish: "marked as having a data migration"},
	"incident-skip.yaml-diff":           {langKorean: "app.yaml을 비교하지 못함", langEnglish: "could not compare app.yaml"},
	"incident-skip.heavy-change":        {langKorean: "가벼운 변경이 아님: {path}", langEnglish: "not a light change: {path}"},
	"incident-skip.heavy-change.secret": {langKorean: "가벼운 변경이 아님: {path} (비밀값 참조)", langEnglish: "not a light change: {path} (secret reference)"},
	"incident-skip.unwatched":           {langKorean: "배포 전 신호를 다 보지 못함", langEnglish: "not every signal before the deploy was seen"},
	"incident-skip.before-deploy":       {langKorean: "배포 전부터 있던 신호", langEnglish: "the signal was there before the deploy"},
	"incident-skip.rolled-back":         {langKorean: "24시간 안에 이미 자동으로 되돌림", langEnglish: "already rolled back automatically in the last 24 hours"},
	"incident-skip.mcp-args":            {langKorean: "도구 입력을 사건에서 채울 수 없음", langEnglish: "the tool input cannot be filled from the incident"},
	"incident-skip.mcp-limit":           {langKorean: "MCP 후보는 {max}개까지", langEnglish: "at most {max} MCP candidates"},
	"incident-skip.guide-avoid":         {langKorean: "{scope} 지침이 막음", langEnglish: "blocked by the {scope} guidelines"},
	"incident-skip.guide-service":       {langKorean: "지침이 서비스 {service}를 막음", langEnglish: "the guidelines block service {service}"},

	// incidents: timeline and decisions
	"incident.detected":           {langKorean: "{signal} ({rule})", langEnglish: "{signal} ({rule})"},
	"incident.candidates":         {langKorean: "규칙으로 임시 조치 후보를 골랐어요.", langEnglish: "Picked temporary action candidates by the rules."},
	"incident.candidates-skipped": {langKorean: "규칙으로 임시 조치 후보를 골랐어요. 뺀 것: {parts}", langEnglish: "Picked temporary action candidates by the rules. Left out: {parts}"},
	"incident.no-candidates":      {langKorean: "쓸 수 있는 임시 조치가 없어 사람에게 넘깁니다.", langEnglish: "No temporary action fits, so a person takes it from here."},
	"incident.rule-floor":         {langKorean: "규칙 하한: {impact}", langEnglish: "Rule floor: {impact}"},
	"incident.high-impact":        {langKorean: "영향이 높아 자동 대응이 하지 않습니다. 사람이 직접 처리하세요.", langEnglish: "The impact is high, so automatic response will not act. Handle it yourself."},
	"incident.why.ai-failed":      {langKorean: "AI {step} 실패로 자동 실행하지 않아요.", langEnglish: "AI {step} failed, so it does not run on its own."},
	"incident.why.impact":         {langKorean: "영향이 {impact}이라 승인이 필요해요.", langEnglish: "The impact is {impact}, so it needs approval."},
	"incident.why.approval":       {langKorean: "승인이 필요한 조치예요.", langEnglish: "This action needs approval."},
	"incident.why.stopped":        {langKorean: "자동 대응이 멈춰 있어요.", langEnglish: "Automatic response is stopped."},
	"incident.why.suggest-only":   {langKorean: "정책이 '제안만'이에요.", langEnglish: "The policy is 'suggest only'."},
	"incident.why.quiet":          {langKorean: "자동 실행을 막는 시간이에요.", langEnglish: "Automatic runs are blocked at this time."},
	"incident.why.rate":           {langKorean: "시간당 자동 실행 한도에 닿았어요.", langEnglish: "The hourly limit of automatic runs was reached."},
	"incident.why.refused":        {langKorean: "자동 실행이 거절됐어요({code}).", langEnglish: "The automatic run was refused ({code})."},
	"incident.why.mcp-gone":       {langKorean: "MCP 서버가 없어졌어요.", langEnglish: "The MCP server is gone."},
	"incident.why.mcp-approval":   {langKorean: "승인이 필요한 MCP 조치예요.", langEnglish: "This MCP action needs approval."},
	"incident.why.mcp-incident":   {langKorean: "이 사건에서 MCP 도구 한도({max}번)에 닿았어요.", langEnglish: "The MCP tool limit for this incident ({max}) was reached."},
	"incident.why.mcp-uncounted":  {langKorean: "MCP 도구 하루 한도를 셀 수 없어요.", langEnglish: "The MCP tool's daily limit cannot be counted."},
	"incident.why.mcp-day":        {langKorean: "MCP 도구 하루 한도({max}번)에 닿았어요.", langEnglish: "The MCP tool's daily limit ({max}) was reached."},
	"incident.why.mcp-failed":     {langKorean: "MCP 도구가 실패했어요({error}).", langEnglish: "The MCP tool failed ({error})."},
	"incident.waiting":            {langKorean: "승인을 기다려요. {why}", langEnglish: "Waiting for approval. {why}"},
	"incident.notified":           {langKorean: "승인할 수 있는 {count}명에게 알렸어요.", langEnglish: "Told {count} people who can approve."},
	"incident.auto-ran":           {langKorean: "{action} 자동 실행", langEnglish: "{action} ran automatically"},
	"incident.auto-failed":        {langKorean: "자동 실행 실패: {code}", langEnglish: "Automatic run failed: {code}"},
	"incident.expired":            {langKorean: "승인 요청이 응답 없이 지났어요.", langEnglish: "The approval request passed without an answer."},
	"incident.signals-continue":   {langKorean: "조치 뒤에도 신호가 이어져 사람에게 넘겨요. 같은 조치는 다시 하지 않아요.", langEnglish: "Signals continued after the action, so a person takes it from here. The same action is not repeated."},
	"incident.recovered":          {langKorean: "조치 뒤 {minutes}분 동안 신호가 없어 회복으로 봐요.", langEnglish: "No signals for {minutes} minutes after the action, so it counts as recovered."},
	"incident.mcp-auto-ran":       {langKorean: "{action} 자동 실행 (MCP {id})", langEnglish: "{action} ran automatically (MCP {id})"},
	"incident.mcp-auto-failed":    {langKorean: "MCP 자동 실행 실패: {error}", langEnglish: "MCP automatic run failed: {error}"},
	"incident.mcp-approved":       {langKorean: "{action} 승인 (MCP {id})", langEnglish: "{action} approved (MCP {id})"},
	"incident.mcp-run-failed":     {langKorean: "MCP 도구 실행 실패: {error}. 사람이 확인해 주세요.", langEnglish: "MCP tool run failed: {error}. Please check it."},
	"incident.approved":           {langKorean: "{action} 승인", langEnglish: "{action} approved"},
	"incident.also-failed":        {langKorean: "{action}을(를) 보내지 못했어요. 사람이 확인해 주세요.", langEnglish: "Could not send {action}. Please check it."},
	"incident.rejected":           {langKorean: "거절: {reason}", langEnglish: "Rejected: {reason}"},
	"incident.ai-excluded":        {langKorean: "이 작업 공간은 외부 AI로 보내지 않게 설정되어 규칙으로만 판단해요.", langEnglish: "This workspace is set not to go to external AI, so only the rules decide."},
	"incident.ai-failed":          {langKorean: "{step}에 실패해 자동 실행하지 않고 승인을 요청해요 ({code}).", langEnglish: "{step} failed, so it asks for approval instead of running on its own ({code})."},
	"incident.assessed":           {langKorean: "평가 {level}, 규칙 하한 {floor} → 최종 {final}", langEnglish: "Assessed {level}, rule floor {floor} → final {final}"},

	// webhooks: one-line summaries sent to slack/teams/pagerduty, in the
	// webhook creator's language (webhookLang)
	"webhook.summary.incident":           {langKorean: "[{event}] {title}", langEnglish: "[{event}] {title}"},
	"webhook.summary.cd":                 {langKorean: "[자동 배포] {app} {name}", langEnglish: "[Automatic deploy] {app} {name}"},
	"webhook.summary.ingress":            {langKorean: "[외부 접속] {where}: {word}", langEnglish: "[External access] {where}: {word}"},
	"webhook.summary.test":               {langKorean: "Seafield Cluster 웹훅 시험: {name}", langEnglish: "Seafield Cluster webhook test: {name}"},
	"incident-event.opened":              {langKorean: "장애", langEnglish: "Incident"},
	"incident-event.approval-required":   {langKorean: "승인 요청", langEnglish: "Approval requested"},
	"incident-event.auto-run":            {langKorean: "자동 조치", langEnglish: "Automatic action"},
	"incident-event.approved":            {langKorean: "승인됨", langEnglish: "Approved"},
	"incident-event.rejected":            {langKorean: "거절됨", langEnglish: "Rejected"},
	"incident-event.expired":             {langKorean: "승인 만료", langEnglish: "Approval expired"},
	"incident-event.recovered":           {langKorean: "회복", langEnglish: "Recovered"},
	"incident-event.closed":              {langKorean: "닫힘", langEnglish: "Closed"},
	"ingress-event.down":                 {langKorean: "수신 주소 닫힘", langEnglish: "Listener closed"},
	"ingress-event.tls-rejects":          {langKorean: "TLS 거부", langEnglish: "TLS rejections"},
	"ingress-event.source-rejects":       {langKorean: "허용 밖 출발지 거부 급증", langEnglish: "Surge of rejected sources"},
	"ingress-event.error-rate":           {langKorean: "5xx 비율 높음", langEnglish: "High 5xx rate"},
	"ingress-event.latency":              {langKorean: "지연 높음", langEnglish: "High latency"},
	"ingress-event.no-backends":          {langKorean: "받을 컨테이너 없음", langEnglish: "No containers to serve"},
	"ingress-event.probe-failed":         {langKorean: "상태 검사 실패", langEnglish: "Health check failed"},
	"ingress-event.cert":                 {langKorean: "인증서 없음", langEnglish: "No certificate"},
	"ingress-event.blocked":              {langKorean: "긴급 차단", langEnglish: "Emergency block"},
	"ingress-event.balance-fallback":     {langKorean: "분배 방식 대체", langEnglish: "Balancing fallback"},
	"ingress-event.certificate-expiring": {langKorean: "인증서 만료 임박", langEnglish: "Certificate expiring soon"},
	"ingress-event.limit-90":             {langKorean: "연결 한도 90% 넘음", langEnglish: "Over 90% of the connection limit"},
	"ingress-event.recovered":            {langKorean: "{word} 회복", langEnglish: "{word} recovered"},

	// webhooks: an ingress link's condition
	"ingress-cond.5xx":       {langKorean: "5xx", langEnglish: "5xx"},
	"ingress-cond.latency":   {langKorean: "지연 p95", langEnglish: "p95 latency"},
	"ingress-cond.value":     {langKorean: "{what} {value}{unit} 넘게", langEnglish: "{what} over {value}{unit}"},
	"ingress-cond.threshold": {langKorean: "{what} 기준 넘게", langEnglish: "{what} over the threshold"},
	"ingress-cond.minutes":   {langKorean: "{cond} {minutes}분", langEnglish: "{cond} for {minutes} min"},

	// webhooks: answers and checks (a reason code is kept in a Reason field
	// next to values a webhook sent; text leaves a value as it is)
	"webhook-reason.bad-format":    {langKorean: "응답 형식이 맞지 않음", langEnglish: "the answer is not in the expected format"},
	"webhook-reason.not-allowed":   {langKorean: "고른 조치가 allowed_actions에 없음", langEnglish: "the chosen action is not in allowed_actions"},
	"with-reason":                  {langKorean: "{text} ({reason})", langEnglish: "{text} ({reason})"},
	"incident.webhook.no-answer":   {langKorean: "판단 웹훅이 답하지 않아 규칙으로 판단해요 ({error}).", langEnglish: "The decide webhook did not answer, so the rules decide ({error})."},
	"incident.webhook.dropped":     {langKorean: "판단 응답을 버렸습니다 · {reason}", langEnglish: "The decide answer was dropped · {reason}"},
	"incident.webhook.not-allowed": {langKorean: "판단 응답을 버렸습니다 · {action}은(는) allowed_actions에 없습니다", langEnglish: "The decide answer was dropped · {action} is not in allowed_actions"},
	"incident.webhook.none":        {langKorean: "판단 웹훅: 맞는 조치가 없어요. 사람에게 넘겨요.", langEnglish: "Decide webhook: no action fits. A person takes it from here."},
	"incident.webhook.chose":       {langKorean: "판단 웹훅이 골랐어요: {action}", langEnglish: "The decide webhook chose: {action}"},
	"cd-check.no-approver":         {langKorean: "배포 확인 계정에 승인 권한이 없어({state}) 웹훅을 부르지 않았어요. 사람이 승인해요", langEnglish: "The deploy check account cannot approve ({state}), so the webhook was not called. A person approves."},
	"cd-check.off-approve":         {langKorean: "웹훅이 꺼져 있어 사람이 승인해요", langEnglish: "The webhook is off, so a person approves"},
	"cd-check.off":                 {langKorean: "웹훅이 꺼져 있음", langEnglish: "The webhook is off"},
	"cd-check.approve-failed":      {langKorean: "승인을 보내지 못함: {code}", langEnglish: "Could not send the approval: {code}"},
	"cd-check.reject-failed":       {langKorean: "반려를 보내지 못함: {code}", langEnglish: "Could not send the rejection: {code}"},
	"cd-check.not-healthy":         {langKorean: "{seconds}초 안에 정상이 되지 않음 ({health})", langEnglish: "Not healthy within {seconds} seconds ({health})"},
	"cd-link.needs-cd":             {langKorean: "자동 배포가 켜진 앱이어야 합니다", langEnglish: "The app must have automatic deploys on"},
	"cd-link.needs-manual":         {langKorean: "자동 배포를 '승인 후 배포'로 바꿔야 합니다", langEnglish: "Set automatic deploys to 'deploy after approval'"},

	// webhooks: the test's steps
	"webhook-test.address":       {langKorean: "주소 확인", langEnglish: "Address"},
	"webhook-test.sent":          {langKorean: "보냄", langEnglish: "Sent"},
	"webhook-test.send-failed":   {langKorean: "실패 · {error}", langEnglish: "Failed · {error}"},
	"webhook-test.signed":        {langKorean: "POST · 서명 {sign}", langEnglish: "POST · signed {sign}"},
	"webhook-test.answer":        {langKorean: "응답", langEnglish: "Answer"},
	"webhook-test.answer-detail": {langKorean: "{status} · {seconds}초", langEnglish: "{status} · {seconds} s"},
	"webhook-test.format":        {langKorean: "판단 응답 형식", langEnglish: "Decide answer format"},
	"webhook-test.format-ok":     {langKorean: "JSON 객체에 action·decision·result 중 하나가 있음", langEnglish: "A JSON object with action, decision or result"},
	"webhook-test.format-bad":    {langKorean: "형식이 맞지 않음: JSON 객체에 action·decision·result 중 하나가 있어야 합니다", langEnglish: "Wrong format: a JSON object needs action, decision or result"},

	// MCP servers (mcp.go)
	"mcp-missing":                    {langKorean: "빠진 것: {list}", langEnglish: "Missing: {list}"},
	"mcp-missing.floor":              {langKorean: "영향 등급 하한", langEnglish: "impact floor"},
	"mcp-missing.inputs":             {langKorean: "입력 제한", langEnglish: "input limits"},
	"mcp-missing.limits":             {langKorean: "한도", langEnglish: "run limits"},
	"mcp-missing.revert":             {langKorean: "되돌리기", langEnglish: "revert"},
	"mcp-missing.irreversible-floor": {langKorean: "되돌릴 수 없으면 하한 보통 이상", langEnglish: "a floor of medium or more when it cannot be reverted"},
	"mcp-choice.summary":             {langKorean: "도구 {count}개 (읽기 {read} · 바꾸기 {change})", langEnglish: "{count} tools ({read} read · {change} change)"},
	"mcp-test.max":                   {langKorean: "최대 {value}", langEnglish: "at most {value}"},
	"mcp-test.loaded":                {langKorean: "{id} 불러옴", langEnglish: "Loaded {id}"},
	"mcp-test.off":                   {langKorean: "이 도구는 장애 대응에 쓰지 않았을 것", langEnglish: "Incident response would not have used this tool"},
	"mcp-test.scope":                 {langKorean: "쓸 범위", langEnglish: "Scope"},
	"mcp-test.scope-no":              {langKorean: "이 사건의 작업 공간에는 쓸 수 없음", langEnglish: "Not usable in this incident's workspace"},
	"mcp-test.unused":                {langKorean: "이 도구는 쓰지 않았을 것", langEnglish: "This tool would not have been used"},
	"mcp-test.diagnosis":             {langKorean: "진단 A", langEnglish: "Diagnosis A"},
	"mcp-test.diagnose":              {langKorean: "{tool}을(를) 읽어 진단에 씀", langEnglish: "Reads {tool} for the diagnosis"},
	"mcp-test.diagnose-result":       {langKorean: "진단에서 읽었을 것 · 실제 호출 안 함", langEnglish: "Would have been read in the diagnosis · not called"},
	"mcp-test.notify":                {langKorean: "알림", langEnglish: "Notice"},
	"mcp-test.notify-detail":         {langKorean: "{tool}(으)로 사건 요약을 보냄", langEnglish: "Sends the incident summary with {tool}"},
	"mcp-test.notify-result":         {langKorean: "알림을 보냈을 것 · 실제 호출 안 함", langEnglish: "Would have sent the notice · not called"},
	"mcp-test.propose":               {langKorean: "{tool} 제안 {args}", langEnglish: "Proposes {tool} {args}"},
	"mcp-test.assessment":            {langKorean: "영향 평가 B", langEnglish: "Impact assessment B"},
	"mcp-test.floor":                 {langKorean: "하한 {impact} (규칙·영향 평가가 더 높게 볼 수 있음)", langEnglish: "Floor {impact} (the rules or the assessment may rate it higher)"},
	"mcp-test.policy":                {langKorean: "정책", langEnglish: "Policy"},
	"mcp-test.policy-no-auto":        {langKorean: "자동 실행 수준이 아님", langEnglish: "Not at the automatic run level"},
	"mcp-test.auto-result":           {langKorean: "자동 실행했을 것 · 실제 호출 안 함", langEnglish: "Would have run automatically · not called"},
	"mcp-test.approval-result":       {langKorean: "승인 요청을 만들었을 것 · 실제 호출 안 함", langEnglish: "Would have asked for approval · not called"},
	"mcp-oauth.no-request":           {langKorean: "로그인 요청을 찾지 못했습니다. Seafield Cluster 화면에서 다시 로그인해 주세요.", langEnglish: "The login request was not found. Log in again from the Seafield Cluster screen."},
	"mcp-oauth.failed":               {langKorean: "로그인하지 못했습니다. Seafield Cluster 화면에서 이유를 볼 수 있습니다. 이 창은 닫아도 됩니다.", langEnglish: "The login failed. See why on the Seafield Cluster screen. You can close this window."},
	"mcp-oauth.done":                 {langKorean: "로그인을 마쳤습니다. 이 창을 닫고 Seafield Cluster 화면으로 돌아가 주세요.", langEnglish: "Logged in. Close this window and go back to the Seafield Cluster screen."},

	// guidelines (guides.go)
	"guide.summary-more":    {langKorean: "{first} 외 {more}줄", langEnglish: "{first} and {more} more lines"},
	"guide-warn.not-listed": {langKorean: "{line}은(는) 임시 조치 목록에 없어 AI가 고를 수 없습니다. 지침에서 빼거나 사람이 할 일로 적으세요.", langEnglish: "{line} is not in the temporary action list, so AI cannot choose it. Take it out or write it as a task for people."},
	"guide-warn.delete":     {langKorean: "{line}처럼 지우는 일은 장애 대응이 하지 않습니다. 사람이 할 일로 적으세요.", langEnglish: "Incident response does not delete things like {line}. Write it as a task for people."},
	"guide-warn.secret":     {langKorean: "{line}처럼 비밀값을 요구하는 문장은 따르지 않습니다.", langEnglish: "Sentences that ask for secrets, like {line}, are not followed."},
	"guide-warn.policy":     {langKorean: "{line}처럼 영향 등급·자동 실행 조건을 바꾸는 문장은 따르지 않습니다. 정책에서 정하세요.", langEnglish: "Sentences that change impact levels or automatic run conditions, like {line}, are not followed. Set them in the policy."},

	// incident policy and assessment
	"approvers.admins":              {langKorean: "시스템 관리자", langEnglish: "System administrators"},
	"approvers.admins-count":        {langKorean: "시스템 관리자 {count}명", langEnglish: "{count} system administrators"},
	"approvers.and-tenant":          {langKorean: "{who} + 그 앱의 작업 공간 관리자", langEnglish: "{who} + the app's workspace managers"},
	"incident-assess.floor":         {langKorean: "임시 조치 목록의 규칙 하한", langEnglish: "The rule floor of the temporary action list"},
	"incident-assess.policy":        {langKorean: "최종 등급 = 규칙 하한과 평가 중 높은 쪽", langEnglish: "Final level = the higher of the rule floor and the assessment"},
	"incident-assess.unsure":        {langKorean: "신뢰도 {confidence} < {threshold}라 한 단계 올림", langEnglish: "raised one level because confidence {confidence} < {threshold}"},
	"incident-assess.same-provider": {langKorean: "진단과 같은 공급자로 평가", langEnglish: "assessed by the same provider as the diagnosis"},
	"incident-fact.scope":           {langKorean: "범위", langEnglish: "Scope"},
	"incident-fact.signals":         {langKorean: "신호 수", langEnglish: "Signals"},
	"incident-fact.reversible":      {langKorean: "되돌릴 수 있음", langEnglish: "Reversible"},
	"incident-fact.critical":        {langKorean: "지침의 중요 사항", langEnglish: "Critical guideline points"},
	"incident-fact.auto-runs":       {langKorean: "최근 1시간 자동 실행", langEnglish: "Automatic runs in the last hour"},
	"incident-fact.yes":             {langKorean: "예", langEnglish: "yes"},
	"incident-fact.no":              {langKorean: "아니오", langEnglish: "no"},

	// external access and DNS servers
	"ingress-action.set-node-gateways":       {langKorean: "게이트웨이 설정", langEnglish: "Gateway settings"},
	"ingress-action.set-ingress-balance":     {langKorean: "분배 방식 변경", langEnglish: "Balancing change"},
	"ingress-action.drain-ingress":           {langKorean: "비우기", langEnglish: "Drain"},
	"ingress-action.undrain-ingress":         {langKorean: "비우기 해제", langEnglish: "Undrain"},
	"ingress-action.ingress-block":           {langKorean: "긴급 차단", langEnglish: "Emergency block"},
	"ingress-action.ingress-unblock":         {langKorean: "차단 해제", langEnglish: "Unblock"},
	"ingress-action.ingress-block-extend":    {langKorean: "차단 연장", langEnglish: "Block extended"},
	"ingress-action.set-ingress-host-policy": {langKorean: "호스트 정책 변경", langEnglish: "Host policy change"},
	"ingress-history.app-declared":           {langKorean: "앱 선언", langEnglish: "App declaration"},
	"ingress-metrics.codes":                  {langKorean: "2xx {2xx} · 3xx {3xx} · 4xx {4xx} · 5xx {5xx} · 차단 {blocked}", langEnglish: "2xx {2xx} · 3xx {3xx} · 4xx {4xx} · 5xx {5xx} · blocked {blocked}"},
	"ingress-metrics.none":                   {langKorean: "없음", langEnglish: "none"},
	"dns-reach.no-address":                   {langKorean: "주소 없음", langEnglish: "No address"},
	"dns-reach.not-public":                   {langKorean: "{addr}: 공개 주소가 아님", langEnglish: "{addr}: not a public address"},
	"dns-reach.no-connect":                   {langKorean: "{addr}: 연결 안 됨 (:{port})", langEnglish: "{addr}: no connection (:{port})"},
}

// text renders code in lang with args; Korean when lang lacks it, the code
// itself when no language has it.
func text(lang, code string, args map[string]string) string {
	t, ok := texts[code][lang]
	if !ok {
		if t, ok = texts[code][langKorean]; !ok {
			return code
		}
	}
	if !strings.Contains(t, "{") {
		return t
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(t, '{')
		if i < 0 {
			b.WriteString(t)
			return b.String()
		}
		j := strings.IndexByte(t[i:], '}')
		if j < 0 {
			b.WriteString(t)
			return b.String()
		}
		b.WriteString(t[:i])
		b.WriteString(args[t[i+1:i+j]])
		t = t[i+j+1:]
	}
}

// ph is the phrase code with args given as name, value pairs.
func ph(code string, kv ...string) store.Phrase {
	p := store.Phrase{Code: code}
	if len(kv) > 1 {
		p.Args = make(map[string]string, len(kv)/2)
		for i := 0; i+1 < len(kv); i += 2 {
			p.Args[kv[i]] = kv[i+1]
		}
	}
	return p
}

// with sets the phrase argument name to q (rendered in the same language).
func with(p store.Phrase, name string, q store.Phrase) store.Phrase {
	m := maps.Clone(p.Phrases)
	if m == nil {
		m = map[string]store.Phrase{}
	}
	m[name] = q
	p.Phrases = m
	return p
}

// reasonText is a stored reason in lang: the web's own reason codes
// (webhook-reason.*) are rendered; anything else (what a webhook said, an
// error) is shown as it is, even when it looks like a code.
func reasonText(lang, r string) string {
	if strings.HasPrefix(r, "webhook-reason.") {
		return text(lang, r, nil)
	}
	return r
}

func ptr(p store.Phrase) *store.Phrase { return &p }

// lit is a value shown as it is.
func lit(v string) store.Phrase { return ph("text", "text", v) }

// render makes p into text in lang ("" for the zero phrase).
func render(lang string, p store.Phrase) string {
	if p.Code == "" {
		return ""
	}
	return text(lang, p.Code, phraseArgs(lang, p.Args, p.Phrases, p.Parts))
}

// renderPtr is render of p, or legacy when p is nil (a row stored before
// the phrase).
func renderPtr(lang string, p *store.Phrase, legacy string) string {
	if p == nil {
		return legacy
	}
	return render(lang, *p)
}

func phraseArgs(lang string, args map[string]string, phrases map[string]store.Phrase, parts []store.Phrase) map[string]string {
	if len(phrases) == 0 && len(parts) == 0 {
		return args
	}
	out := maps.Clone(args)
	if out == nil {
		out = map[string]string{}
	}
	for k, q := range phrases {
		out[k] = render(lang, q)
	}
	if len(parts) > 0 {
		r := make([]string, 0, len(parts))
		for _, q := range parts {
			r = append(r, render(lang, q))
		}
		out["parts"] = strings.Join(r, "; ")
	}
	return out
}

// requestLang is the language of the text the web makes for this request:
// the signed-in account's default language (prefs.language), else the
// page order (sfc_lang cookie, Accept-Language, English).
func (s *Server) requestLang(r *http.Request, ws *webSession) string {
	if ws != nil {
		if l := s.userLang(ws.user.ID); l != "" {
			return l
		}
	}
	return pageLang(r)
}

// userLang is the account's default language (prefs.language), "" when it
// has none.
func (s *Server) userLang(id string) string {
	if id == "" {
		return ""
	}
	if raw, err := s.opt.Store.GetPrefs(id); err == nil && raw != nil {
		var p struct {
			Language string `json:"language"`
		}
		if json.Unmarshal(raw, &p) == nil && knownLang(p.Language) {
			return p.Language
		}
	}
	return ""
}

// webhookLang is the language of the human text a webhook sends: its
// creator's default language, else English (no reader to ask).
func (s *Server) webhookLang(h *store.Webhook) string {
	if l := s.userLang(h.CreatedByID); l != "" {
		return l
	}
	return langEnglish
}
