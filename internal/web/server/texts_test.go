// SPDX-License-Identifier: Apache-2.0

package server

import (
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
