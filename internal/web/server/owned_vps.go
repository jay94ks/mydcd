// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Owned VPS (devel/design/vps-hostinger.md): VPS servers the operator owns
// at a provider (Hostinger) and attaches. A screen of its own, never mixed
// with the managed VPS screen (Jay 2026-11-28 14:04 KST). Server changes
// send `revision` of GET /system/owned-vps as Expected; account changes
// send `accountRevision` (the accounts stay in the VPS catalog).

// GET /system/owned-vps → {revision, accountRevision, accounts, servers,
// status, statusError?}: status is the leader's vendor readings (this
// month's bandwidth, remaining subscription), null when it cannot be read.
func (s *Server) handleOwnedVPS(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var reply userauth.OwnedVPSReply
	statusErr := ""
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		if reply, err = c.QueryOwnedVPS(ctx, true); err == nil {
			return nil
		}
		// The leader's readings are optional: show the records without them.
		var me *sfc.Error
		if !errors.As(err, &me) || me.Code == sfc.CodeClosed || me.Code == sfc.CodeSessionExpired || me.Code == sfc.CodeNotLoggedIn || me.Code == sfc.CodeForbidden {
			return err
		}
		statusErr = string(me.Code)
		reply, err = c.QueryOwnedVPS(ctx, false)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	p := reply.Page
	if p.Accounts == nil {
		p.Accounts = []control.VPSPublicAccount{}
	}
	if p.Servers == nil {
		p.Servers = []control.OwnedVPS{}
	}
	steps := map[string]int{}
	for _, v := range p.Servers {
		steps[v.Name] = ownedInstallStep(v)
	}
	out := map[string]any{"revision": reply.RootRevision, "accountRevision": reply.AccountRootRevision, "accounts": camel{p.Accounts}, "servers": camel{p.Servers}, "installSteps": steps, "status": nil}
	if reply.Status != nil {
		out["status"] = camel{*reply.Status}
	}
	if statusErr != "" {
		out["statusError"] = statusErr
	}
	writeJSON(w, http.StatusOK, out)
}

// ownedInstallStep is how far the install got, 1–4: 1 reading the VPS, 2
// VPS checked (public IP and build recorded), 3 invitation issued (the
// server may join), 4 joined (running). 0 = failed; the record's failure
// says why.
func ownedInstallStep(v control.OwnedVPS) int {
	switch {
	case v.Phase == control.OwnedFailed:
		return 0
	case v.Phase == control.OwnedRunning:
		return 4
	case v.Invitation != nil:
		return 3
	case v.PublicIP != "":
		return 2
	}
	return 1
}

func ownedToken(token string) error {
	if token == "" || len(token) > 256 {
		return invalid("token: 1..256 characters")
	}
	return nil
}

func ownedAccountOf(p control.OwnedVPSPage, name string) (control.VPSPublicAccount, bool) {
	i := slices.IndexFunc(p.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == name })
	if i < 0 {
		return control.VPSPublicAccount{}, false
	}
	return p.Accounts[i], true
}

// POST /system/owned-vps/accounts {opId, name, vendor, token} → the voter
// seals the API token, then put-vps-account. The token is not stored by the
// web daemon (the op digest leaves it out).
func (s *Server) handleOwnedVPSAccountAdd(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID   string `json:"opId"`
		Name   string `json:"name"`
		Vendor string `json:"vendor"`
		Token  string `json:"token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	body := struct{ Name, Vendor string }{req.Name, req.Vendor}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !vps.ValidAccountName(req.Name) {
			return "", nil, 0, "", invalid("name: 1-32 lower-case letters, digits and hyphens")
		}
		if _, ok := vps.LookupOwned(req.Vendor); !ok {
			return "", nil, 0, "", invalid("vendor: hostinger")
		}
		if err := ownedToken(req.Token); err != nil {
			return "", nil, 0, "", err
		}
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := ownedAccountOf(reply.Page, req.Name); ok {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "exists", "the account already exists; replace its token instead"}
		}
		sealed, err := c.SealVPSCredential(ctx, userauth.VPSCredentialInput{Request: req.OpID, Account: req.Name, AccessKey: []byte(req.Token)})
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionPutVPSAccount, control.VPSAccountPut{Name: req.Name, Vendor: req.Vendor, Credential: &sealed}, reply.AccountRootRevision, "vps-account/" + req.Name, nil
	})
}

// GET /system/owned-vps/accounts/{account}/instances → {instances}: the
// account's VMs as the leader reads them from the vendor now, for the attach
// picker. Reading changes nothing at the vendor.
func (s *Server) handleOwnedVPSInstances(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	name := r.PathValue("account")
	var list []control.OwnedVPSInstance
	found := true
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return err
		}
		if _, found = ownedAccountOf(reply.Page, name); !found {
			return nil
		}
		list, err = c.QueryOwnedVPSInstances(ctx, name)
		return err
	})
	switch {
	case err != nil:
		s.writeBackendError(w, ws, err)
	case !found:
		writeError(w, http.StatusNotFound, "not-found", "no such account")
	default:
		if list == nil {
			list = []control.OwnedVPSInstance{}
		}
		writeJSON(w, http.StatusOK, map[string]any{"instances": camel{list}})
	}
}

// POST /system/owned-vps/accounts/{account}/rotate-key {opId, token,
// expected?} → a new sealed token (and a new SSH key for later installs).
func (s *Server) handleOwnedVPSAccountRotate(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Token    string `json:"token"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("account")
	body := struct{ Expected uint64 }{req.Expected}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if err := ownedToken(req.Token); err != nil {
			return "", nil, 0, "", err
		}
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		old, ok := ownedAccountOf(reply.Page, name)
		if !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such account"}
		}
		sealed, err := c.SealVPSCredential(ctx, userauth.VPSCredentialInput{Request: req.OpID, Account: name, AccessKey: []byte(req.Token)})
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionPutVPSAccount, control.VPSAccountPut{Name: name, Vendor: old.Vendor, Credential: &sealed}, expectedOr(req.Expected, reply.AccountRootRevision), "vps-account/" + name, nil
	})
}

// DELETE /system/owned-vps/accounts/{account} {opId, expected?} → refused
// (409 in-use) while servers of the account are attached.
func (s *Server) handleOwnedVPSAccountRemove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("account")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := ownedAccountOf(reply.Page, name); !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such account"}
		}
		if slices.ContainsFunc(reply.Page.Servers, func(v control.OwnedVPS) bool { return v.Account == name }) {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "in-use", "servers of this account are attached; detach them first"}
		}
		return sfc.ActionRemoveVPSAccount, control.VPSAccountSelection{Name: name}, expectedOr(req.Expected, reply.AccountRootRevision), "vps-account/" + name, nil
	})
}

// POST /system/owned-vps/servers {opId, name, account, instanceId, install
// (ssh|manual|existing), port (not with existing), voter?,
// protect?(exclude|low-weight), expected?} →
// attach-owned-vps.
func (s *Server) handleOwnedVPSAttach(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID       string `json:"opId"`
		Name       string `json:"name"`
		Account    string `json:"account"`
		InstanceID string `json:"instanceId"`
		Install    string `json:"install"`
		Voter      bool   `json:"voter,omitempty"`
		Port       uint16 `json:"port,omitempty"`
		Protect    string `json:"protect,omitempty"`
		Expected   uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !lifecycle.ValidID(req.Name) {
			return "", nil, 0, "", invalid("name: a server name")
		}
		switch req.Install {
		case control.OwnedInstallSSH, control.OwnedInstallManual, control.OwnedInstallExisting:
		default:
			return "", nil, 0, "", invalid("install: ssh, manual or existing")
		}
		if (req.Port == 0) != (req.Install == control.OwnedInstallExisting) {
			return "", nil, 0, "", invalid("port: the SFCP port of a new server; none with existing")
		}
		if req.Voter && req.Install != control.OwnedInstallManual {
			return "", nil, 0, "", invalid("voter: only with the manual install")
		}
		if req.Protect != "" && req.Protect != control.OwnedProtectExclude && req.Protect != control.OwnedProtectLowWeight {
			return "", nil, 0, "", invalid("protect: exclude or low-weight")
		}
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := ownedAccountOf(reply.Page, req.Account); !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such owned-VPS account"}
		}
		return sfc.ActionAttachOwnedVPS, control.OwnedVPSAttach{Name: req.Name, Account: req.Account, InstanceID: req.InstanceID, Install: req.Install, Voter: req.Voter, Port: req.Port, Protect: req.Protect},
			expectedOr(req.Expected, reply.RootRevision), "owned-vps/" + req.Name, nil
	})
}

// PATCH /system/owned-vps/servers/{name} {opId, protect?, restore?,
// expected?} → set-owned-vps (restore ends a traffic hold now; the leader
// leaves the server be until next month).
func (s *Server) handleOwnedVPSSet(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Protect  string `json:"protect,omitempty"`
		Restore  bool   `json:"restore,omitempty"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.Protect == "" && !req.Restore || req.Protect != "" && req.Protect != control.OwnedProtectExclude && req.Protect != control.OwnedProtectLowWeight {
			return "", nil, 0, "", invalid("protect: exclude or low-weight; or restore: true")
		}
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		i := slices.IndexFunc(reply.Page.Servers, func(v control.OwnedVPS) bool { return v.Name == name })
		if i < 0 {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such owned VPS"}
		}
		if req.Restore && reply.Page.Servers[i].Limit == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "not-limited", "the server's traffic is not held"}
		}
		return sfc.ActionSetOwnedVPS, control.OwnedVPSSet{Name: name, Protect: req.Protect, Restore: req.Restore}, expectedOr(req.Expected, reply.RootRevision), "owned-vps/" + name, nil
	})
}

// DELETE /system/owned-vps/servers/{name} {opId, expected?} →
// detach-owned-vps: the record only; the VPS stays at the provider.
func (s *Server) handleOwnedVPSDetach(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("name")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		reply, err := c.QueryOwnedVPS(ctx, false)
		if err != nil {
			return "", nil, 0, "", err
		}
		if !slices.ContainsFunc(reply.Page.Servers, func(v control.OwnedVPS) bool { return v.Name == name }) {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such owned VPS"}
		}
		return sfc.ActionDetachOwnedVPS, control.OwnedVPSSelection{Name: name}, expectedOr(req.Expected, reply.RootRevision), "owned-vps/" + name, nil
	})
}
