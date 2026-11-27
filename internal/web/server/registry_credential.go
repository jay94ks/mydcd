// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/registry"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// POST /t/{t}/registries/{id}/credential {repository, access} → {registry,
// authority, username, token, repository, access, expiresAt}: a short-lived
// `docker login` for a built-in registry (UI-81, `sfcli registry
// credential`). access: pull / push / pull,push. Not an op: sfcd issues it
// to the session and decides who may have it (403 otherwise, also when the
// registry is stopped). The token goes only into this response body
// (no-store); the daemon does not store, log or journal it and clears its
// copy after writing.
func (s *Server) handleRegistryCredential(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Repository string `json:"repository"`
		Access     string `json:"access"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Access == "" {
		req.Access = "pull"
	}
	repo, actions, err := registry.RequestedScope("repository:" + req.Repository + ":" + req.Access)
	if err != nil || repo != req.Repository || strings.Join(actions, ",") != strings.Join(slices.Sorted(slices.Values(strings.Split(req.Access, ","))), ",") {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "repository: an image path such as shop/web; access: pull, push or pull,push")
		return
	}
	tenant, id := r.PathValue("t"), r.PathValue("id")
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var cred sfc.RegistryCredential
	err = ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		cred, err = c.RegistryCredential(ctx, tenant, sfc.RegistryCredentialRequest{ID: id, Repository: repo, Actions: actions})
		return err
	})
	defer clear(cred.Token)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	// Known limit: the string conversion for json.Marshal cannot be wiped;
	// the token bytes and the encoded body are.
	body, _ := json.Marshal(struct {
		Registry   string   `json:"registry"`
		Authority  string   `json:"authority"`
		Username   string   `json:"username"`
		Token      string   `json:"token"`
		Repository string   `json:"repository"`
		Access     []string `json:"access"`
		ExpiresAt  string   `json:"expiresAt"`
	}{id, cred.Authority, ws.user.Username, string(cred.Token), repo, actions, rfc3339(time.Unix(cred.ExpiresAt, 0))})
	defer clear(body)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}
