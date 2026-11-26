// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/config"
	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/web/mydc"
)

// Adding a server (UI-13 '서버 추가', system administrator), as `mydc node
// add`, `mydc node invitation` and `mydc node promote`. mydcd keeps the
// membership directory, signs the invitation and decides; the web keeps
// nothing (the invitation is fetched again on every download).

// POST /nodes {opId, id, endpoint, publicKey, joinId} → invite-node
// (Expected 0). id and joinId: lowercase letters, digits and -, starting
// with a letter (joinId not "genesis"); endpoint: canonical host:port;
// publicKey: the 64-hex Ed25519 key `mydc identity create` printed on the
// new server. 409 exists when the ID, key, endpoint or join ID is taken.
func (s *Server) handleInviteNode(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		ID        string `json:"id"`
		Endpoint  string `json:"endpoint"`
		PublicKey string `json:"publicKey"`
		JoinID    string `json:"joinId"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		key, err := identity.ParseKey(req.PublicKey)
		switch {
		case !lifecycle.ValidID(req.ID):
			return "", nil, 0, "", invalid("id: lowercase letters, digits and -, starting with a letter")
		case config.ValidateCanonicalEndpoint(req.Endpoint) != nil:
			return "", nil, 0, "", invalid("endpoint: canonical host:port")
		case err != nil || hex.EncodeToString(key[:]) != req.PublicKey:
			return "", nil, 0, "", invalid("publicKey: the full lowercase Ed25519 public key in hex (64 characters)")
		case !lifecycle.ValidID(req.JoinID) || req.JoinID == "genesis":
			return "", nil, 0, "", invalid("joinId: lowercase letters, digits and -, starting with a letter, not genesis")
		}
		taken := false
		if err := eachMember(ctx, c, func(m memberView, _ mydc.MembersPage) bool {
			taken = m.ID == req.ID || m.Key == req.PublicKey || m.Endpoint == req.Endpoint || m.JoinID == req.JoinID
			return !taken
		}); err != nil {
			return "", nil, 0, "", err
		}
		if taken {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "exists", "a server with this ID, key, endpoint or join ID is already in the cluster"}
		}
		return mydc.ActionInviteNode, mydc.NodeInvite{Peer: config.Peer{ID: req.ID, Key: req.PublicKey, Endpoint: req.Endpoint}, JoinID: req.JoinID}, 0, "node/" + req.ID, nil
	})
}

// GET /nodes/{node}/invitation → the signed invitation file for `mydcd
// join` (application/json attachment mydc-invitation-{node}.json). Only an
// invited, learner or ready server has one (403 otherwise, from mydcd).
func (s *Server) handleNodeInvitation(w http.ResponseWriter, r *http.Request, ws *webSession) {
	node := r.PathValue("node")
	if !lifecycle.ValidID(node) {
		writeError(w, http.StatusBadRequest, "bad-request", "node")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var raw []byte
	err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
		inv, err := c.NodeInvitation(ctx, node)
		if err != nil {
			return err
		}
		if inv.Target.ID != node {
			return &httpErr{http.StatusBadGateway, "invitation-invalid", "the invitation is for another server"}
		}
		raw, err = inv.Encode()
		if err != nil {
			return &httpErr{http.StatusBadGateway, "invitation-invalid", "the invitation signature does not verify"}
		}
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="mydc-invitation-`+node+`.json"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// GET /nodes/{node}/invitation/summary → {node, cluster, joinId,
// approvalRevision, source:{id, key, endpoint}, target:{id, key,
// endpoint}}: the values the wizard shows next to the file and puts in the
// `mydcd join --cluster … --source-public-key …` command. The source key
// is to be checked against a separately trusted node key.
func (s *Server) handleNodeInvitationSummary(w http.ResponseWriter, r *http.Request, ws *webSession) {
	node := r.PathValue("node")
	type peer struct {
		ID       string `json:"id"`
		Key      string `json:"key"`
		Endpoint string `json:"endpoint"`
	}
	read(s, w, r, ws, func(ctx context.Context, c mydc.Conn) (map[string]any, error) {
		inv, err := c.NodeInvitation(ctx, node)
		if err != nil {
			return nil, err
		}
		if inv.Target.ID != node {
			return nil, &httpErr{http.StatusBadGateway, "invitation-invalid", "the invitation is for another server"}
		}
		if _, err := inv.Encode(); err != nil {
			return nil, &httpErr{http.StatusBadGateway, "invitation-invalid", "the invitation signature does not verify"}
		}
		return map[string]any{"node": node, "cluster": hex.EncodeToString(inv.Cluster[:]), "joinId": inv.JoinID, "approvalRevision": inv.ApprovalRevision,
			"source": peer{inv.Source.ID, inv.Source.Key, inv.Source.Endpoint}, "target": peer{inv.Target.ID, inv.Target.Key, inv.Target.Endpoint}}, nil
	})
}

// POST /nodes/{node}/promote {opId, expected?} → promote-node with Expected
// = the member's revision. 409 not-ready unless the server is in join
// phase ready (installed and acknowledged).
func (s *Server) handlePromoteNode(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	node := r.PathValue("node")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c mydc.Conn, _ mydc.Session) (string, any, uint64, string, error) {
		m, err := findMember(ctx, c, node)
		if err != nil {
			return "", nil, 0, "", err
		}
		if m == nil {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such server"}
		}
		if req.Expected == 0 && m.Join != mydc.JoinReady {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "not-ready", "the server has not finished joining (join: " + m.Join + ")"}
		}
		return mydc.ActionPromoteNode, control.NodeSelection{ID: node}, expectedOr(req.Expected, m.JoinRevision), "node/" + node, nil
	})
}
