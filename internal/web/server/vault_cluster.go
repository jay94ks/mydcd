// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Cluster Vault (UI-70 '클러스터 보관함', CLI `sfcli secret --cluster`): the
// same tree, create, write, access, revoke and retire endpoints as a
// workspace Vault, under /api/v1/vault with realm "" (sfcd's
// cluster realm). sfcd admits only system administrators; the daemon does
// not judge that itself.

// clusterRealm runs a workspace Vault handler with realm "".
func clusterRealm(h func(http.ResponseWriter, *http.Request, *webSession)) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		r.SetPathValue("t", "")
		h(w, r, ws)
	}
}

type clusterVaultPage struct {
	listPage
	// Initialized: the cluster Vault tree exists (vault-init was applied).
	Initialized bool `json:"initialized"`
	// Root: the root group's ID (the parent of top-level objects).
	Root string `json:"root,omitempty"`
}

// GET /vault?after= → {items, next, revision, asOf, initialized, root?}
func (s *Server) handleClusterVault(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (clusterVaultPage, error) {
		p, err := screenVault(ctx, c, "", r.URL.Query().Get("after"))
		if err != nil {
			return clusterVaultPage{}, err
		}
		out := clusterVaultPage{listPage: s.page(p.Items, p.Next, p.Revision), Initialized: p.Collection > 0}
		for _, v := range p.Items {
			if v.Parent == "" && v.Kind == "group" {
				out.Root, out.Initialized = v.ID, true
			}
		}
		if out.Items == nil || len(p.Items) == 0 {
			out.Items = []sfc.VaultView{}
		}
		return out, nil
	})
}

// POST /vault/init {opId, root?} → vault-init {Realm:"", Root}
// (Expected 0). root defaults to "cluster".
func (s *Server) handleClusterVaultInit(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID string `json:"opId"`
		Root string `json:"root,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Root == "" {
		req.Root = "cluster"
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !storageIDRE.MatchString(req.Root) {
			return "", nil, 0, "", invalid("root: lowercase letters, digits and -, starting with a letter")
		}
		p, err := c.Vault(ctx, "", "")
		if err != nil {
			return "", nil, 0, "", err
		}
		if p.Collection > 0 || len(p.Items) > 0 {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "exists", "the cluster Vault already exists"}
		}
		return sfc.ActionVaultInit, control.VaultRealm{Realm: "", Root: req.Root}, 0, "cluster-vault", nil
	})
}

// vaultUsageView is one PublicRead vault-usages row (a release of secrets
// to an app service or standalone container; live = still held, which
// blocks vault-retire).
type vaultUsageView struct {
	ID         string   `json:"id"`
	Tenant     string   `json:"tenant"`
	User       string   `json:"user,omitempty"`
	App        string   `json:"app,omitempty"`
	Standalone string   `json:"standalone,omitempty"`
	Deployment string   `json:"deployment,omitempty"`
	Service    string   `json:"service,omitempty"`
	Node       string   `json:"node"`
	Purpose    string   `json:"purpose,omitempty"`
	Generation uint64   `json:"generation"`
	Secrets    []string `json:"secrets"`
	Live       bool     `json:"live"`
}

// GET /t/{t}/vault/usages?id=&after= (and /vault/usages for the cluster
// Vault) → {items:[{app, deployment, service, standalone?, node, selector,
// secrets, live}], next, revision, asOf}: the app services that take
// secrets from object id (REQ-44 `vault-usages`). id defaults to the realm
// itself, which sfcd reads as the whole realm. sfcd decides who may read.
func (s *Server) handleVaultUsages(w http.ResponseWriter, r *http.Request, ws *webSession) {
	realm := r.PathValue("t")
	id := r.URL.Query().Get("id")
	if id == "" {
		id = realm
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "bad-request", "id is required for the cluster Vault")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.PublicRead(ctx, "vault-usages", realm, control.PublicReadQuery{Name: id}, r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		items := []vaultUsageView{}
		for _, row := range p.Rows {
			if u := row.SecretUsage; u != nil {
				items = append(items, vaultUsageView{ID: u.ID, Tenant: u.Tenant, User: u.User, App: u.App, Standalone: u.Standalone, Deployment: u.Deployment,
					Service: u.Service, Node: u.Node, Purpose: u.Purpose, Generation: u.Generation, Secrets: append([]string{}, u.Secrets...), Live: u.Live})
			}
		}
		return s.page(items, p.Next, p.RootRevision), nil
	})
}
