// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
)

const notBuilt = `<!doctype html><meta charset="utf-8"><title>Seafield Cluster</title><p>The web UI is not built into this binary. Build apps/sfc-web/web and copy dist to apps/sfc-web/ui/dist, or run with -static-dir.</p>`

// static serves the UI build with SPA fallback: unknown paths get
// index.html so client-side routes survive reload. Hashed assets are cached
// for a year; index.html is never cached and carries the page's language
// (pageLang) in <html lang>.
func (s *Server) static() http.Handler {
	files := s.opt.Static
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if files == nil {
			serveNotBuilt(w)
			return
		}
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if st, err := fs.Stat(files, name); err != nil || st.IsDir() {
			// Only a missing build asset is a real 404. Any other path is a
			// client route, even with a dot in it (/system/domains/example.com).
			if strings.HasPrefix(name, "assets/") {
				http.NotFound(w, r)
				return
			}
			name = "index.html"
		}
		if name == "index.html" {
			index, err := fs.ReadFile(files, name)
			if err != nil {
				serveNotBuilt(w)
				return
			}
			serveIndex(w, r, files, index)
			return
		} else if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, files, name)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, files fs.FS, index []byte) {
	lang := pageLang(r)
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("Content-Language", lang)
	h.Add("Vary", "Accept-Language, Cookie")
	body := withLangPreload(withPageLang(index, lang), files, lang)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func serveNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(notBuilt))
}
