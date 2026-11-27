// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// POST /t/{t}/apps/{app}/cd/probe {repository, branch, path, credential?}
// → {commit, size, node?} (REQ-56 `cd-probe` as the caller).
// A failed read answers 422 with its code (auth-failed, no-repository,
// no-branch, no-file, no-credential, timeout, too-large, source-error) or 429 rate-limited.
func (s *Server) handleCDProbe(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Repository string `json:"repository"`
		Branch     string `json:"branch"`
		Path       string `json:"path"`
		Credential string `json:"credential,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var res deployment.GitProbeResult
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		res, err = c.ProbeCD(ctx, r.PathValue("t"), deployment.GitProbeRequest{App: r.PathValue("app"),
			Repository: req.Repository, Branch: strings.TrimPrefix(req.Branch, "refs/heads/"), Path: req.Path, Credential: req.Credential})
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	switch res.Code {
	case "":
		out := map[string]any{"commit": res.Commit, "size": res.Size}
		if res.Node != "" {
			out["node"] = res.Node
		}
		writeJSON(w, http.StatusOK, out)
	case "rate-limited":
		writeError(w, http.StatusTooManyRequests, res.Code, "too many read checks; try again shortly")
	default:
		writeError(w, http.StatusUnprocessableEntity, res.Code, "the repository could not be read")
	}
}
