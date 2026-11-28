// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"io/fs"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// Screen languages (devel/design/web-i18n.md). Korean is the source text;
// a request that names neither gets English.
const (
	langKorean  = "ko"
	langEnglish = "en"
)

// Cookies the browser keeps: sfc_lang_user is the signed-in account's
// default language (the frontend writes it after login and clears it on
// logout; absent when the account has none), sfc_lang this browser's own
// choice. Neither grants anything; they only pick the first screen's text.
const (
	langUserCookie    = "sfc_lang_user"
	langBrowserCookie = "sfc_lang"
)

func knownLang(v string) bool { return v == langKorean || v == langEnglish }

// pageLang picks the language of a page load: sfc_lang_user, then sfc_lang,
// then Accept-Language (the first ko* or en* by preference), then English.
func pageLang(r *http.Request) string {
	for _, name := range []string{langUserCookie, langBrowserCookie} {
		if c, err := r.Cookie(name); err == nil && knownLang(c.Value) {
			return c.Value
		}
	}
	if l := acceptLang(r.Header.Get("Accept-Language")); l != "" {
		return l
	}
	return langEnglish
}

// acceptLang is the first ko or en range in Accept-Language by quality
// (ties keep their order); "" when there is none. "*" matches nothing.
func acceptLang(h string) string {
	type item struct {
		lang string
		q    float64
	}
	var items []item
	for part := range strings.SplitSeq(h, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		for p := range strings.SplitSeq(params, ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "q") {
				if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 1 {
					q = f
				} else {
					q = 0
				}
			}
		}
		primary, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(tag)), "-")
		if q > 0 && knownLang(primary) {
			items = append(items, item{primary, q})
		}
		if len(items) >= 32 {
			break
		}
	}
	slices.SortStableFunc(items, func(a, b item) int { return cmp.Compare(b.q, a.q) })
	if len(items) == 0 {
		return ""
	}
	return items[0].lang
}

// withPageLang sets the page's <html lang> to lang. The frontend reads
// document.documentElement.lang as the first language: the page's CSP
// (script-src 'self') allows no inline script for a global value.
func withPageLang(index []byte, lang string) []byte {
	s := string(index)
	i := strings.Index(s, "<html")
	if i < 0 {
		return index
	}
	end := strings.IndexByte(s[i:], '>')
	if end < 0 {
		return index
	}
	tag := s[i : i+end]
	if j := strings.Index(tag, ` lang="`); j >= 0 {
		k := strings.IndexByte(tag[j+7:], '"')
		if k < 0 {
			return index
		}
		tag = tag[:j] + ` lang="` + lang + `"` + tag[j+7+k+1:]
	} else {
		tag += ` lang="` + lang + `"`
	}
	return []byte(s[:i] + tag + s[i+end:])
}

// withLangPreload links the page language's text bundle for preloading:
// Korean is in the main bundle; another language is the one build file
// assets/lang-<code>-<hash>.js. None, or more than one, adds nothing (the
// screen loads it at run time).
func withLangPreload(index []byte, files fs.FS, lang string) []byte {
	if lang == langKorean || files == nil {
		return index
	}
	m, err := fs.Glob(files, "assets/lang-"+lang+"-*.js")
	if err != nil || len(m) != 1 {
		return index
	}
	s := string(index)
	i := strings.Index(s, "</head>")
	if i < 0 {
		return index
	}
	return []byte(s[:i] + `<link rel="modulepreload" href="/` + m[0] + `">` + s[i:])
}
