// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/mydcd/internal/servicecall"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// POST /t/{t}/apps/{app}/call {service, port, path, headers?, body?(base64)
// | text?, timeoutMs?} → {code?, status?, contentType?, body?(base64), task?,
// node?, elapsedMs}: one POST from inside the tenant network to a service
// port (REQ-24/55 `service-call`, CallService; scheme https with
// insecureSkipVerify? for a TLS port). The target is a tenant/app/service/port
// only; mydcd picks a ready task and refuses anything else. A failed call
// is code (SERVICE_NO_READY_TASK, SERVICE_CALL_TIMEOUT, ...), not an error.
// Calls are not journaled and the web keeps neither request nor answer.
func (s *Server) handleServiceCall(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Service   string            `json:"service"`
		Port      int               `json:"port"`
		Path      string            `json:"path"`
		Headers   map[string]string `json:"headers,omitempty"`
		Body      []byte            `json:"body,omitempty"`
		Text      *string           `json:"text,omitempty"`
		TimeoutMS int               `json:"timeoutMs,omitempty"`
		Scheme    string            `json:"scheme,omitempty"`
		Insecure  bool              `json:"insecureSkipVerify,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Text != nil {
		if req.Body != nil {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "send body or text, not both")
			return
		}
		req.Body = []byte(*req.Text)
	}
	switch {
	case req.Service == "" || req.Port < 1 || req.Port > 65535:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "service and port (1..65535) are required")
		return
	case req.Path == "" || req.Path[0] != '/':
		writeError(w, http.StatusUnprocessableEntity, "invalid", "path: starts with /")
		return
	case req.Scheme != "" && req.Scheme != "http" && req.Scheme != "https" || req.Insecure && req.Scheme != "https":
		writeError(w, http.StatusUnprocessableEntity, "invalid", "scheme: http or https (insecureSkipVerify only with https)")
		return
	case req.TimeoutMS < 0 || req.TimeoutMS > servicecall.MaxTimeout:
		writeError(w, http.StatusUnprocessableEntity, "invalid", "timeoutMs: 0..30000 (0 = 10 s)")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (serviceCallView, error) {
		res, err := c.CallService(ctx, r.PathValue("t"), servicecall.Request{App: r.PathValue("app"), Service: req.Service, Port: req.Port,
			Path: req.Path, Method: http.MethodPost, Headers: req.Headers, Body: req.Body, TimeoutMS: req.TimeoutMS,
			Scheme: req.Scheme, InsecureSkipVerify: req.Insecure})
		if err != nil {
			return serviceCallView{}, err
		}
		return serviceCallView{Code: res.Code, Status: res.Status, ContentType: res.Headers["Content-Type"], Body: res.Body,
			Task: res.Task, Node: res.Node, ElapsedMS: res.ElapsedMS}, nil
	})
}

// serviceCallView: the screen's flat answer (contentType from Headers).
type serviceCallView struct {
	Code        string `json:",omitempty"`
	Status      int    `json:",omitempty"`
	ContentType string `json:",omitempty"`
	Body        []byte `json:",omitempty"`
	Task        string `json:",omitempty"`
	Node        string `json:",omitempty"`
	ElapsedMS   int64
}
