// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// POST /nodes/{node}/isolate | /restore | /remove {opId, operation?,
// epoch?, expected?} → isolate-node / restore-node / remove-node
// (control.NodeLifecycleChange, as `mydc node isolate|restore|remove`).
// System admin, judged by mydcd. operation is the node lifecycle operation
// ID (lowercase letters, digits, -; default "<verb>-<opId>"); epoch defaults
// to the members page's node operation epoch and expected to the server's
// revision. Whether the change is allowed (last voter, quorum, pending node
// work, storage) is mydcd's answer: a refusal comes back as the op's result.
// Only a request that would not change anything is answered early (409
// unchanged): isolating an isolated server, restoring one that is not
// isolated, or any change to a removed server.
func (s *Server) handleNodeLifecycle(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	verb := strings.TrimSuffix(action, "-node")
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID      string `json:"opId"`
			Operation string `json:"operation,omitempty"`
			Epoch     uint64 `json:"epoch,omitempty"`
			Expected  uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		node := r.PathValue("node")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{action, req}, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
			op, err := nodeOperation(req.Operation, verb, req.OpID)
			if err != nil {
				return "", nil, 0, "", err
			}
			m, epoch, err := findMemberEpoch(ctx, c, node)
			if err != nil {
				return "", nil, 0, "", err
			}
			if m == nil {
				return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such server"}
			}
			switch {
			case m.Phase == mydc.NodePhaseRemoved:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server is removed"}
			case action == mydc.ActionIsolateNode && m.Phase == mydc.NodePhaseIsolated:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server is already isolated"}
			case action == mydc.ActionRestoreNode && m.Phase != mydc.NodePhaseIsolated:
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server is not isolated"}
			}
			if req.Epoch != 0 {
				epoch = req.Epoch
			}
			return action, control.NodeLifecycleChange{ID: node, Operation: op, Epoch: max(1, epoch)}, expectedOr(req.Expected, m.Revision), "node/" + node, nil
		})
	}
}
