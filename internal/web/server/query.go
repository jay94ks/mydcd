// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strconv"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// listPage is the common list response:
// {"items":[...],"next":"cursor","revision":N,"asOf":"RFC3339"}.
type listPage struct {
	Items    any    `json:"items"`
	Next     string `json:"next,omitempty"`
	Revision uint64 `json:"revision"`
	AsOf     string `json:"asOf"`
}

// read runs fn on the session's connection and writes its value with
// camelJSON, or the mapped error.
func read[T any](s *Server, w http.ResponseWriter, r *http.Request, ws *webSession, fn func(context.Context, sfc.Conn) (T, error)) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var v T
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		v, err = fn(ctx, c)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, camel{v})
}

// readPage is read for paged sfcd methods.
func readPage[T any](s *Server, w http.ResponseWriter, r *http.Request, ws *webSession, fn func(context.Context, sfc.Conn, string) (sfc.Page[T], error)) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := fn(ctx, c, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		return s.page(p.Items, p.Next, p.Revision), nil
	})
}

// readList is read for unpaged list methods.
func readList[T any](s *Server, w http.ResponseWriter, r *http.Request, ws *webSession, fn func(context.Context, sfc.Conn) ([]T, error)) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		items, err := fn(ctx, c)
		if err != nil {
			return listPage{}, err
		}
		return s.page(items, "", 0), nil
	})
}

func (s *Server) page(items any, next string, rev uint64) listPage {
	return listPage{Items: items, Next: next, Revision: rev, AsOf: rfc3339(s.now())}
}

func queryUint(r *http.Request, name string) uint64 {
	v, _ := strconv.ParseUint(r.URL.Query().Get(name), 10, 64)
	return v
}
