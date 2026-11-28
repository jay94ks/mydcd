// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"net/http"
	"strings"
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

// requestLang is the language of the text the web makes for this request:
// the signed-in account's default language (prefs.language), else the
// page order (sfc_lang cookie, Accept-Language, English).
func (s *Server) requestLang(r *http.Request, ws *webSession) string {
	if ws != nil && ws.user.ID != "" {
		if raw, err := s.opt.Store.GetPrefs(ws.user.ID); err == nil && raw != nil {
			var p struct {
				Language string `json:"language"`
			}
			if json.Unmarshal(raw, &p) == nil && knownLang(p.Language) {
				return p.Language
			}
		}
	}
	return pageLang(r)
}
