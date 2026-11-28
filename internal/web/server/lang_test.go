// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
)

func TestAcceptLang(t *testing.T) {
	for h, want := range map[string]string{
		"":                            "",
		"ko-KR,ko;q=0.9,en-US;q=0.8":  "ko",
		"en-US,en;q=0.9,ko;q=0.8":     "en",
		"fr-FR,fr;q=0.9,ko;q=0.5":     "ko",
		"fr, en;q=0.2, ko;q=0.7":      "ko",
		"ja, *":                       "",
		"ko;q=0, en":                  "en",
		"ko;q=abc, en;q=0.1":          "en",
		"KO":                          "ko",
		"en;q=0.5, ko;q=0.5":          "en",
		"zh-Hant-TW, en-GB;q=0.3, de": "en",
	} {
		if got := acceptLang(h); got != want {
			t.Errorf("%q: %q, want %q", h, got, want)
		}
	}
}

func TestWithPageLang(t *testing.T) {
	for in, want := range map[string]string{
		`<!doctype html><html lang="ko"><head>`: `<!doctype html><html lang="en"><head>`,
		`<html><body>`:                          `<html lang="en"><body>`,
		`<html class="x" lang="ko-KR">`:         `<html class="x" lang="en">`,
		`no html tag`:                           `no html tag`,
	} {
		if got := string(withPageLang([]byte(in), "en")); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// The index is served in the page's language: sfc_lang_user, sfc_lang,
// Accept-Language, then English, with Content-Language and Vary.
func TestIndexLanguage(t *testing.T) {
	hs := newFixture(t).http
	for _, c := range []struct {
		path, accept, cookie, want string
	}{
		{"/", "", "", "en"},
		{"/", "ko-KR,ko;q=0.9", "", "ko"},
		{"/apps/x", "ko", "sfc_lang=en", "en"},
		{"/", "en", "sfc_lang=en; sfc_lang_user=ko", "ko"},
		{"/", "ko", "sfc_lang=fr", "ko"},
		{"/system/domains/example.com", "", "sfc_lang_user=ko", "ko"},
	} {
		req, _ := http.NewRequest("GET", hs.URL+c.path, nil)
		if c.accept != "" {
			req.Header.Set("Accept-Language", c.accept)
		}
		if c.cookie != "" {
			req.Header.Set("Cookie", c.cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), `<html lang="`+c.want+`">`) || resp.Header.Get("Content-Language") != c.want || !strings.Contains(resp.Header.Get("Vary"), "Accept-Language") || !strings.Contains(resp.Header.Get("Vary"), "Cookie") || resp.Header.Get("Cache-Control") != "no-cache" {
			t.Errorf("%+v: %d %s %v", c, resp.StatusCode, body, resp.Header)
		}
	}
}

func TestWithLangPreload(t *testing.T) {
	index := []byte(`<html lang="en"><head></head></html>`)
	one := fstest.MapFS{"assets/lang-en-1a2b.js": {}, "assets/app-9.js": {}}
	if got := string(withLangPreload(index, one, "en")); got != `<html lang="en"><head><link rel="modulepreload" href="/assets/lang-en-1a2b.js"></head></html>` {
		t.Fatal(got)
	}
	two := fstest.MapFS{"assets/lang-en-1.js": {}, "assets/lang-en-2.js": {}}
	for _, c := range []struct {
		files fstest.MapFS
		lang  string
	}{{one, "ko"}, {two, "en"}, {fstest.MapFS{}, "en"}} {
		if got := string(withLangPreload(index, c.files, c.lang)); got != string(index) {
			t.Errorf("%s: %s", c.lang, got)
		}
	}
}
