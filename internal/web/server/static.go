// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

const notBuilt = `<!doctype html><meta charset="utf-8"><title>MyDC</title><p>The web UI is not built into this binary. Build apps/mydc-web/web and copy dist to apps/mydc-web/ui/dist, or run with -static-dir.</p>`

// static serves the UI build with SPA fallback: unknown paths get
// index.html so client-side routes survive reload. Hashed assets are cached
// for a year; index.html is never cached.
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
			if _, err := fs.Stat(files, name); err != nil {
				serveNotBuilt(w)
				return
			}
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		http.ServeFileFS(w, r, files, name)
	})
}

func serveNotBuilt(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(notBuilt))
}
