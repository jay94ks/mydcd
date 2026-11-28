// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/secrets"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Vault object policy (UI-70): vault-acl, vault-move, vault-approval-age,
// vault-revoke, vault-retire. The daemon finds the object in the `vault`
// rows for its revision (Expected); sfcd decides permission and state.

// findVaultObject reads a tenant vault object by ID.
func findVaultObject(ctx context.Context, c sfc.Conn, tenant, id string) (sfc.VaultView, error) {
	after := ""
	for {
		p, err := screenVault(ctx, c, tenant, after)
		if err != nil {
			return sfc.VaultView{}, err
		}
		for _, v := range p.Items {
			if v.Realm == tenant && v.ID == id {
				return v, nil
			}
		}
		if p.Next == "" {
			return sfc.VaultView{}, &httpErr{http.StatusNotFound, "not-found", "no such vault object"}
		}
		after = p.Next
	}
}

// vaultStep is a vault object endpoint: build gets the object row and
// returns the action and payload; Expected is the object revision unless
// the body gives one.
func (s *Server) vaultStep(w http.ResponseWriter, r *http.Request, ws *webSession, opID, id string, expected uint64, body any,
	build func(v sfc.VaultView) (string, any, error)) {
	tenant := r.PathValue("t")
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !storageIDRE.MatchString(id) {
			return "", nil, 0, "", invalid("id: a vault object ID")
		}
		v, err := findVaultObject(ctx, c, tenant, id)
		if err != nil {
			return "", nil, 0, "", err
		}
		action, payload, err := build(v)
		if expected == 0 {
			expected = v.Revision
		}
		return action, payload, expected, "vault/" + v.Path, err
	})
}

func activeObject(v sfc.VaultView) error {
	if v.Status != string(secrets.Active) {
		return &httpErr{http.StatusConflict, "not-active", "the object is " + v.Status}
	}
	return nil
}

// aclDelta is one side of an ACL change: names to add to, or remove from,
// each list. A list left out does not change.
type aclDelta struct {
	Users        []string `json:"users"`
	Services     []string `json:"services"`
	DenyUsers    []string `json:"denyUsers"`
	DenyServices []string `json:"denyServices"`
}

func (d aclDelta) acl() (secrets.ACL, int, error) {
	n := 0
	for _, l := range [][]string{d.Users, d.Services, d.DenyUsers, d.DenyServices} {
		if len(l) > 256 {
			return secrets.ACL{}, 0, invalid("acl: at most 256 names per list")
		}
		for _, name := range l {
			if name == "" || len(name) > 200 {
				return secrets.ACL{}, 0, invalid("acl: names of 1..200 characters")
			}
		}
		n += len(l)
	}
	return secrets.ACL{Users: d.Users, Services: d.Services, DenyUsers: d.DenyUsers, DenyServices: d.DenyServices}, n, nil
}

// PATCH /t/{t}/vault/acl {opId, id, add?, remove?, expected?} → vault-acl.
// add and remove each hold {users, services, denyUsers, denyServices}; only
// the changed names are sent.
func (s *Server) handleVaultACL(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string   `json:"opId"`
		ID       string   `json:"id"`
		Add      aclDelta `json:"add"`
		Remove   aclDelta `json:"remove"`
		Expected uint64   `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.vaultStep(w, r, ws, req.OpID, req.ID, req.Expected, req, func(v sfc.VaultView) (string, any, error) {
		if err := activeObject(v); err != nil {
			return "", nil, err
		}
		add, n, err := req.Add.acl()
		if err != nil {
			return "", nil, err
		}
		remove, m, err := req.Remove.acl()
		if err != nil {
			return "", nil, err
		}
		if n+m == 0 {
			return "", nil, invalid("acl: nothing to change")
		}
		return sfc.ActionVaultACL, control.VaultACL{Realm: v.Realm, ID: v.ID, Add: add, Remove: remove}, nil
	})
}

// POST /t/{t}/vault/move {opId, id, parent, expected?} → vault-move (parent:
// a group ID, or the tenant for the root)
func (s *Server) handleVaultMove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		ID       string `json:"id"`
		Parent   string `json:"parent"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.vaultStep(w, r, ws, req.OpID, req.ID, req.Expected, req, func(v sfc.VaultView) (string, any, error) {
		if err := activeObject(v); err != nil {
			return "", nil, err
		}
		if req.Parent == "" || req.Parent == v.Parent {
			return "", nil, invalid("parent: another group")
		}
		return sfc.ActionVaultMove, control.VaultMove{Realm: v.Realm, ID: v.ID, Parent: req.Parent}, nil
	})
}

// PUT /t/{t}/vault/approval-age {opId, id, seconds, expected?} → vault-approval-age (groups)
func (s *Server) handleVaultApprovalAge(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		ID       string `json:"id"`
		Seconds  int64  `json:"seconds"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.vaultStep(w, r, ws, req.OpID, req.ID, req.Expected, req, func(v sfc.VaultView) (string, any, error) {
		if v.Kind != "group" {
			return "", nil, &httpErr{http.StatusConflict, "not-group", "only a group has an approval age"}
		}
		if req.Seconds < 0 || req.Seconds > 366*86400 {
			return "", nil, invalid("seconds: 0 (no limit) .. 366 days")
		}
		return sfc.ActionVaultApprovalAge, control.VaultAge{Realm: v.Realm, ID: v.ID, Seconds: req.Seconds}, nil
	})
}

// POST /t/{t}/vault/revoke | retire {opId, id, expected?} → vault-revoke /
// vault-retire (retire: a revoking object with nothing under it and no
// live use; sfcd checks).
func (s *Server) handleVaultSelection(action string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req struct {
			OpID     string `json:"opId"`
			ID       string `json:"id"`
			Expected uint64 `json:"expected,omitempty"`
		}
		if !readJSON(w, r, &req) {
			return
		}
		body := struct {
			Action string
			Req    any
		}{action, req}
		s.vaultStep(w, r, ws, req.OpID, req.ID, req.Expected, body, func(v sfc.VaultView) (string, any, error) {
			if action == sfc.ActionVaultRetire && v.Status != string(secrets.Revoking) {
				return "", nil, &httpErr{http.StatusConflict, "not-revoking", "revoke the object first"}
			}
			return action, control.VaultSelection{Realm: v.Realm, ID: v.ID}, nil
		})
	}
}
