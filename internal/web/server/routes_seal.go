// SPDX-License-Identifier: Apache-2.0

package server

import (
	"net/http"

	"github.com/jay94ks/mydcd/internal/web/seal"
)

// handleSealStatus tells the UI whether sealed storage works. Features that
// keep keys (AI, external DNS, ACME, notifications) are off unless it is
// ready, and the screen shows the reason. Secret names and values are
// never listed here. A broken box's reason is an OS error with paths, so
// only system administrators see it; others get a plain sentence.
func (s *Server) handleSealStatus(w http.ResponseWriter, r *http.Request, ws *webSession) {
	st, reason := s.opt.Seal.Status()
	if st == seal.StateBroken && !ws.user.SystemAdmin {
		reason = "sealed storage cannot be read; ask a system administrator"
	}
	writeJSON(w, http.StatusOK, map[string]any{"state": st, "ready": st == seal.StateReady, "reason": reason})
}
