// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Log clearing (UI-3C '로그 정리…', devel/proposals/seafield-log-clear.md):
// each server keeps container logs in its own sfcd log store. A clear asks
// every member server to clear its store for the selection; containers are
// not touched. It is a direct request, not a signed change: no opId, no op
// in bbolt, and sending it again is the same request (a server that was
// down clears then). Each server checks the tenant's Deploy permission
// itself.

type logsSelection struct {
	App        string `json:"app,omitempty"`
	Standalone string `json:"standalone,omitempty"`
	Service    string `json:"service,omitempty"`
	Key        string `json:"key,omitempty"` // one task key (workload/task/...)
}

func (q logsSelection) sfc() (sfc.LogsClear, bool) {
	ok := (q.App == "") != (q.Standalone == "") && (q.Standalone == "" || q.Service == "" && q.Key == "")
	return sfc.LogsClear{App: q.App, Standalone: q.Standalone, Service: q.Service, Key: q.Key}, ok
}

type logsClearNodeView struct {
	Node       string `json:"node"`
	Code       string `json:"code"` // ok, denied, unreachable, unavailable
	Containers int    `json:"containers"`
	Removed    int    `json:"removed"`
}

type logsClearView struct {
	Nodes   []logsClearNodeView `json:"nodes"`
	Cleared int                 `json:"cleared"` // servers that answered ok
	Total   int                 `json:"total"`
}

func viewLogsClear(r control.LogsClearReply) logsClearView {
	v := logsClearView{Nodes: []logsClearNodeView{}, Total: len(r.Nodes)}
	for _, n := range r.Nodes {
		v.Nodes = append(v.Nodes, logsClearNodeView{Node: n.Node, Code: n.Code, Containers: n.Containers, Removed: n.Removed})
		if n.Code == "ok" {
			v.Cleared++
		}
	}
	return v
}

// POST /t/{t}/logs/clear {app|standalone, service?, key?} → {nodes:[{node,
// code, containers, removed}], cleared, total}. A server that is not "ok"
// kept its logs; the screen offers the same request again.
func (s *Server) handleClearLogs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req logsSelection
	if !readJSON(w, r, &req) {
		return
	}
	q, ok := req.sfc()
	if !ok {
		writeError(w, http.StatusBadRequest, "bad-request", "one of app or standalone is required (service and key only with app)")
		return
	}
	tenant := r.PathValue("t")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var out control.LogsClearReply
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		out, err = c.ClearLogs(ctx, tenant, q)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	v := viewLogsClear(out)
	s.log.Info("logs cleared", "user", ws.user.Username, "tenant", tenant, "app", q.App, "standalone", q.Standalone, "service", q.Service, "cleared", v.Cleared, "total", v.Total)
	writeJSON(w, http.StatusOK, v)
}

type storedLogView struct {
	Container string `json:"container"`
	Name      string `json:"name"`
	Service   string `json:"service,omitempty"`
	Key       string `json:"key,omitempty"`
	Lines     uint64 `json:"lines"`
	Size      int64  `json:"size"`
}

type storedLogsNodeView struct {
	Node string          `json:"node"`
	Code string          `json:"code"`
	Logs []storedLogView `json:"logs"`
}

// GET /t/{t}/logs/stored?app=|standalone=&service=&key=&node= →
// {nodes:[{node, code, logs:[{container, name, service, key, lines,
// size}]}]}: what each server's log store keeps for the selection,
// including containers that are gone. Lines of a gone container are not
// served (secret values are hidden when read, from the live container).
func (s *Server) handleStoredLogs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	qv := r.URL.Query()
	q, ok := logsSelection{App: qv.Get("app"), Standalone: qv.Get("standalone"), Service: qv.Get("service"), Key: qv.Get("key")}.sfc()
	if !ok {
		writeError(w, http.StatusBadRequest, "bad-request", "one of app or standalone is required (service and key only with app)")
		return
	}
	tenant, node := r.PathValue("t"), qv.Get("node")
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (map[string]any, error) {
		out, err := c.StoredLogs(ctx, tenant, q, node)
		if err != nil {
			return nil, err
		}
		nodes := []storedLogsNodeView{}
		for _, n := range out.Nodes {
			v := storedLogsNodeView{Node: n.Node, Code: n.Code, Logs: []storedLogView{}}
			for _, l := range n.Logs {
				v.Logs = append(v.Logs, storedLogView{Container: l.Container, Name: l.Name, Service: l.Service, Key: l.Key, Lines: l.Lines, Size: l.Size})
			}
			nodes = append(nodes, v)
		}
		return map[string]any{"nodes": nodes}, nil
	})
}
