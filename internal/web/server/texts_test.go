// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jay94ks/seafield/internal/web/store"
)

// Every web-made text has Korean and English, with the same {names}.
func TestTextsHaveEveryLanguage(t *testing.T) {
	names := func(s string) []string {
		var out []string
		for {
			i := strings.IndexByte(s, '{')
			if i < 0 {
				return out
			}
			j := strings.IndexByte(s[i:], '}')
			out = append(out, s[i+1:i+j])
			s = s[i+j+1:]
		}
	}
	for code, m := range texts {
		ko, en := m[langKorean], m[langEnglish]
		if ko == "" || en == "" {
			t.Errorf("%s: missing a language", code)
			continue
		}
		a, b := names(ko), names(en)
		for _, n := range a {
			if !strings.Contains(en, "{"+n+"}") {
				t.Errorf("%s: en lacks {%s}", code, n)
			}
		}
		if len(a) != len(b) {
			t.Errorf("%s: %v vs %v", code, a, b)
		}
	}
	if got := text("en", "webhook-off", map[string]string{"name": "ops"}); got != "Webhook ops was turned off" {
		t.Fatal(got)
	}
	if got := text("fr", "deploy-done", map[string]string{"target": "web"}); got != "배포 완료: web" {
		t.Fatal(got)
	}
	if got := text("en", "no-such-code", nil); got != "no-such-code" {
		t.Fatal(got)
	}
}

// A notification stored as codes is read in the reader's language: the
// account's prefs.language wins over Accept-Language. A row stored with
// its own Title and Body keeps them.
func TestNotificationsInReadersLanguage(t *testing.T) {
	f := newFixture(t)
	f.login()
	user := "u-alice"
	f.srv.notify(&store.Notification{User: user, Kind: NotifyDeployDone, Text: notice("deploy-done", map[string]string{"target": "web"})})
	f.srv.notify(&store.Notification{User: user, Kind: NotifyDeployDone, Title: "배포 완료: old"})
	titles := func() string {
		_, out := f.do("GET", "/api/v1/notifications", nil)
		var ts []string
		for _, it := range out["items"].([]any) {
			ts = append(ts, it.(map[string]any)["title"].(string))
		}
		return strings.Join(ts, "|")
	}
	if got := titles(); !strings.Contains(got, "Deployed: web") || !strings.Contains(got, "배포 완료: old") {
		t.Fatalf("english: %s", got)
	}
	if code, _ := f.do("PUT", "/api/v1/prefs", map[string]any{"prefs": map[string]any{"language": "ko"}}); code != 204 {
		t.Fatal("prefs")
	}
	if got := titles(); !strings.Contains(got, "배포 완료: web") {
		t.Fatalf("korean: %s", got)
	}
}

// The incident tables keep the Korean text the AI reads; it is the same as
// the texts table's.
func TestIncidentTablesMatchTexts(t *testing.T) {
	for k, r := range incidentRules {
		if got := text(langKorean, "incident-rule."+k+".title", nil); got != r.Title {
			t.Errorf("%s title: %q vs %q", k, got, r.Title)
		}
		if got := text(langKorean, "incident-rule."+k+".words", nil); got != r.Words {
			t.Errorf("%s words: %q vs %q", k, got, r.Words)
		}
	}
	for _, a := range incidentActions {
		if got := text(langKorean, "incident-action."+a.ID, nil); got != a.Label {
			t.Errorf("%s: %q vs %q", a.ID, got, a.Label)
		}
	}
}

// An incident's title, rule, timeline and decision are read in the
// reader's language; lines stored as Korean text stay as they are.
func TestIncidentTextInReadersLanguage(t *testing.T) {
	f, fake, clock := incidentFixture(t)
	cdRollbackSetup(t, f, fake, clock, true, 0)
	row := findIncident(t, f, "task-restarted")
	if row == nil {
		t.Fatal("no incident")
	}
	id := row["id"].(string)
	if _, err := f.srv.opt.Store.UpdateIncident(id, func(x *store.Incident) error {
		x.Timeline = append(x.Timeline, store.IncidentEntry{At: x.At, Kind: "notify", Text: "옛 줄"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	get := func() string {
		_, det := f.do("GET", "/api/v1/incidents/"+id, nil)
		return fmt.Sprint(det)
	}
	if got := get(); !strings.Contains(got, "title:Container keeps restarting: shop/php-shop") || !strings.Contains(got, "Roll back right after an automatic deploy ran automatically") ||
		!strings.Contains(got, "note:v2 → v1, automatic deploys paused") || !strings.Contains(got, "옛 줄") {
		t.Fatalf("english: %s", got)
	}
	if code, _ := f.do("PUT", "/api/v1/prefs", map[string]any{"prefs": map[string]any{"language": "ko"}}); code != 204 {
		t.Fatal("prefs")
	}
	if got := get(); !strings.Contains(got, "title:컨테이너 재시작 반복: shop/php-shop") || !strings.Contains(got, "자동 배포 직후 되돌리기 자동 실행") ||
		!strings.Contains(got, "rule:10분 안에 3번 재시작") || !strings.Contains(got, "note:v2 → v1, 자동 배포 멈춤") {
		t.Fatalf("korean: %s", got)
	}
}
