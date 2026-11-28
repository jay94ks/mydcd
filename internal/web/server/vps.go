// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/userauth"
	"github.com/jay94ks/seafield/internal/vps"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// VPS management (UI-12B, docs/reference/web-api/54-vps.md). Every change
// is a system-administrator action of sfcd; the daemon builds the payload
// and sfcd decides. Expected is the VPS catalog revision (`revision` of
// GET /system/vps), the same for accounts and servers.

// vpsServerView is one VPS server row. Build and the leader's bookkeeping
// (CreateSentAt) stay out.
type vpsServerView struct {
	Name, Account, Zone, Image, Flavor string
	Script                             string   `json:",omitempty"`
	SSHKeys                            []string `json:",omitempty"`
	CapKRW                             int64
	CapAction                          string // "stop" or "notify"
	Voter                              bool
	Port                               uint16
	CreatedBy                          string
	CreatedAt                          int64
	Phase                              string
	PhaseAt                            int64
	StopAfter                          int64               `json:",omitempty"`
	CapStop                            *control.VPSCapStop `json:",omitempty"`
	InstanceID                         string              `json:",omitempty"`
	PublicIP                           string              `json:",omitempty"`
	Failure                            string              `json:",omitempty"`
	// Joining: installing with the invitation issued (the enrolled key may
	// join now), shown as "가입 중".
	Joining bool `json:"joining,omitempty"`
	// DNSHolds: records taken out of DNS while it is stopped, or not put
	// back (vps_dns.go).
	DNSHolds []vpsDNSHoldView `json:"dnsHolds,omitempty"`
}

func vpsCapActionName(a string) string {
	if a == control.VPSCapNotify {
		return "notify"
	}
	return "stop"
}

func vpsCapActionOf(name string) (string, error) {
	switch name {
	case "", "stop":
		return control.VPSCapStopAction, nil
	case "notify":
		return control.VPSCapNotify, nil
	}
	return "", invalid("capAction: stop or notify")
}

func vpsServerViewOf(v control.VPSServer) vpsServerView {
	return vpsServerView{Name: v.Name, Account: v.Account, Zone: v.Zone, Image: v.Image, Flavor: v.Flavor, Script: v.Script, SSHKeys: v.SSHKeys,
		CapKRW: v.CapKRW, CapAction: vpsCapActionName(v.CapAction), Voter: v.Voter, Port: v.Port, CreatedBy: v.CreatedBy, CreatedAt: v.CreatedAt,
		Phase: v.Phase, PhaseAt: v.PhaseAt, StopAfter: v.StopAfter, CapStop: v.CapStop, InstanceID: v.InstanceID, PublicIP: v.PublicIP, Failure: v.Failure,
		Joining: v.Phase == control.VPSInstalling && v.Invitation != nil}
}

// GET /system/vps → {revision, accounts[], servers[], status|null,
// statusError?}. The cost watch lives in the leader's memory; when it cannot
// be read the page still comes with statusError.
func (s *Server) handleVPS(w http.ResponseWriter, r *http.Request, ws *webSession) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var page control.VPSPage
	var status *control.VPSStatus
	statusErr := ""
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		if page, err = c.QueryVPS(ctx); err != nil {
			return err
		}
		st, err := c.QueryVPSStatus(ctx)
		var me *sfc.Error
		switch {
		case err == nil:
			status = &st
		case errors.As(err, &me) && me.Code != sfc.CodeClosed && me.Code != sfc.CodeSessionExpired && me.Code != sfc.CodeNotLoggedIn:
			statusErr = string(me.Code)
		default:
			return err
		}
		return nil
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	holds := s.vpsDNSHoldViews()
	servers := []vpsServerView{}
	for _, v := range page.Servers {
		row := vpsServerViewOf(v)
		row.DNSHolds = holds[v.Name]
		servers = append(servers, row)
	}
	accounts := page.Accounts
	if accounts == nil {
		accounts = []control.VPSPublicAccount{}
	}
	out := map[string]any{"revision": page.Revision, "accounts": camel{accounts}, "servers": camel{servers}, "status": nil, "dnsAuto": s.vpsDNSAuto()}
	if status != nil {
		out["status"] = camel{*status}
	}
	if statusErr != "" {
		out["statusError"] = statusErr
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /system/vps/accounts/{account}/offer?zone= → what the account's
// vendor sells now (the "new VPS server" form and "지금 연결 확인").
// unavailable: the vendor refused or could not be read, or this server is
// not a voter.
func (s *Server) handleVPSOffer(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := control.VPSOfferQuery{Account: r.PathValue("account"), Zone: r.URL.Query().Get("zone")}
	if !vps.ValidAccountName(q.Account) || !q.Valid() || len(q.Zone) > 64 {
		writeError(w, http.StatusBadRequest, "bad-request", "account or zone")
		return
	}
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var offer control.VPSOffer
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		offer, err = c.QueryVPSOffer(ctx, q)
		return err
	})
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	writeJSON(w, http.StatusOK, camel{offer})
}

func vpsAccountOf(page control.VPSPage, name string) (control.VPSPublicAccount, bool) {
	i := slices.IndexFunc(page.Accounts, func(a control.VPSPublicAccount) bool { return a.Name == name })
	if i < 0 {
		return control.VPSPublicAccount{}, false
	}
	return page.Accounts[i], true
}

func vpsServerOf(page control.VPSPage, name string) (control.VPSServer, error) {
	i := slices.IndexFunc(page.Servers, func(v control.VPSServer) bool { return v.Name == name })
	if i < 0 {
		return control.VPSServer{}, &httpErr{http.StatusNotFound, "not-found", "no such VPS server"}
	}
	return page.Servers[i], nil
}

func vpsKeys(accessKey, secretKey string) error {
	if accessKey == "" || len(accessKey) > 256 || secretKey == "" || len(secretKey) > 256 {
		return invalid("accessKey and secretKey: 1..256 characters each")
	}
	return nil
}

// POST /system/vps/accounts {opId, name, vendor, accessKey, secretKey,
// trafficPrice} → the voter seals the key pair, then put-vps-account. The
// keys are not stored by the web daemon (the op digest leaves them out).
func (s *Server) handleVPSAccountAdd(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID         string `json:"opId"`
		Name         string `json:"name"`
		Vendor       string `json:"vendor"`
		AccessKey    string `json:"accessKey"`
		SecretKey    string `json:"secretKey"`
		TrafficPrice int64  `json:"trafficPrice"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	body := struct {
		Name, Vendor string
		TrafficPrice int64
	}{req.Name, req.Vendor, req.TrafficPrice}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if !vps.ValidAccountName(req.Name) {
			return "", nil, 0, "", invalid("name: 1-32 lower-case letters, digits and hyphens")
		}
		// Owned-vendor accounts are added from the owned VPS screen.
		if _, ok := vps.LookupManaged(req.Vendor); !ok {
			return "", nil, 0, "", invalid("vendor: iwinv")
		}
		if req.TrafficPrice < 0 || req.TrafficPrice > control.MaxOverageKRWPerGB {
			return "", nil, 0, "", invalid("trafficPrice: KRW per GB above the free allowance")
		}
		if err := vpsKeys(req.AccessKey, req.SecretKey); err != nil {
			return "", nil, 0, "", err
		}
		page, err := c.QueryVPS(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := vpsAccountOf(page, req.Name); ok {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "exists", "the account already exists; replace its key instead"}
		}
		sealed, err := c.SealVPSCredential(ctx, userauth.VPSCredentialInput{Request: req.OpID, Account: req.Name, AccessKey: []byte(req.AccessKey), SecretKey: []byte(req.SecretKey)})
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionPutVPSAccount, control.VPSAccountPut{Name: req.Name, Vendor: req.Vendor, OverageKRWPerGB: req.TrafficPrice, Credential: &sealed}, page.Revision, "vps-account/" + req.Name, nil
	})
}

// POST /system/vps/accounts/{account}/rotate-key {opId, accessKey,
// secretKey, expected?} → a new sealed key pair (the account gets a new SSH
// key to register again).
func (s *Server) handleVPSAccountRotate(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string `json:"opId"`
		AccessKey string `json:"accessKey"`
		SecretKey string `json:"secretKey"`
		Expected  uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("account")
	body := struct{ Expected uint64 }{req.Expected}
	s.sharedCreate(w, r, ws, req.OpID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if err := vpsKeys(req.AccessKey, req.SecretKey); err != nil {
			return "", nil, 0, "", err
		}
		page, err := c.QueryVPS(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		old, ok := vpsAccountOf(page, name)
		if !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such account"}
		}
		sealed, err := c.SealVPSCredential(ctx, userauth.VPSCredentialInput{Request: req.OpID, Account: name, AccessKey: []byte(req.AccessKey), SecretKey: []byte(req.SecretKey)})
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionPutVPSAccount, control.VPSAccountPut{Name: name, Vendor: old.Vendor, OverageKRWPerGB: old.OverageKRWPerGB, Credential: &sealed, Guard: old.Guard},
			expectedOr(req.Expected, page.Revision), "vps-account/" + name, nil
	})
}

// PATCH /system/vps/accounts/{account} {opId, trafficPrice?, sshKeyId?,
// guardWindowMin?, guardAverageMin?, guardPattern?, expected?} →
// put-vps-account without a credential (a missing field keeps its value;
// sshKeyId "" forgets it; guard minutes 0 = default).
func (s *Server) handleVPSAccountSet(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID         string  `json:"opId"`
		TrafficPrice *int64  `json:"trafficPrice,omitempty"`
		SSHKeyID     *string `json:"sshKeyId,omitempty"`
		GuardWindow  *int    `json:"guardWindowMin,omitempty"`
		GuardAverage *int    `json:"guardAverageMin,omitempty"`
		GuardPattern *bool   `json:"guardPattern,omitempty"`
		Expected     uint64  `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("account")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		if req.TrafficPrice == nil && req.SSHKeyID == nil && req.GuardWindow == nil && req.GuardAverage == nil && req.GuardPattern == nil {
			return "", nil, 0, "", invalid("nothing to change")
		}
		if req.TrafficPrice != nil && (*req.TrafficPrice < 0 || *req.TrafficPrice > control.MaxOverageKRWPerGB) {
			return "", nil, 0, "", invalid("trafficPrice: KRW per GB above the free allowance")
		}
		if req.SSHKeyID != nil && len(*req.SSHKeyID) > 128 {
			return "", nil, 0, "", invalid("sshKeyId: the vendor's key ID")
		}
		page, err := c.QueryVPS(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		old, ok := vpsAccountOf(page, name)
		if !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such account"}
		}
		q := control.VPSAccountPut{Name: name, Vendor: old.Vendor, OverageKRWPerGB: old.OverageKRWPerGB, SSHKeyID: old.SSHKeyID, Guard: old.Guard}
		if req.GuardWindow != nil {
			q.Guard.WindowMin = *req.GuardWindow
		}
		if req.GuardAverage != nil {
			q.Guard.AverageMin = *req.GuardAverage
		}
		if req.GuardPattern != nil {
			q.Guard.PatternOff = !*req.GuardPattern
		}
		if !vps.ValidGuard(q.Guard.WindowMin, q.Guard.AverageMin) {
			return "", nil, 0, "", invalid("guardWindowMin: 0 (5) to 60; guardAverageMin: 0 (60) or at least twice the window, up to 1440")
		}
		if req.TrafficPrice != nil {
			q.OverageKRWPerGB = *req.TrafficPrice
		}
		if req.SSHKeyID != nil {
			q.SSHKeyID = *req.SSHKeyID
		}
		if q.OverageKRWPerGB == old.OverageKRWPerGB && q.SSHKeyID == old.SSHKeyID && q.Guard == old.Guard {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the account already has these values"}
		}
		return sfc.ActionPutVPSAccount, q, expectedOr(req.Expected, page.Revision), "vps-account/" + name, nil
	})
}

// DELETE /system/vps/accounts/{account} {opId, expected?} →
// remove-vps-account (refused while a VPS server uses the account).
func (s *Server) handleVPSAccountRemove(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string `json:"opId"`
		Expected uint64 `json:"expected,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	name := r.PathValue("account")
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		page, err := c.QueryVPS(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := vpsAccountOf(page, name); !ok {
			return "", nil, 0, "", &httpErr{http.StatusNotFound, "not-found", "no such account"}
		}
		if n := countVPS(page, name); n > 0 {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "in-use", "VPS servers of this account remain; delete them first"}
		}
		return sfc.ActionRemoveVPSAccount, control.VPSAccountSelection{Name: name}, expectedOr(req.Expected, page.Revision), "vps-account/" + name, nil
	})
}

func countVPS(page control.VPSPage, account string) int {
	n := 0
	for _, v := range page.Servers {
		if v.Account == account {
			n++
		}
	}
	return n
}

// POST /system/vps/servers {opId, name, account, zone, image, flavor,
// script?, sshKeys?, capKRW, capAction?, voter?, port?} → create-vps-node.
// The instance starts costing money once sfcd accepts it.
func (s *Server) handleVPSCreate(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID      string   `json:"opId"`
		Name      string   `json:"name"`
		Account   string   `json:"account"`
		Zone      string   `json:"zone"`
		Image     string   `json:"image"`
		Flavor    string   `json:"flavor"`
		Script    string   `json:"script,omitempty"`
		SSHKeys   []string `json:"sshKeys,omitempty"`
		CapKRW    int64    `json:"capKRW"`
		CapAction string   `json:"capAction,omitempty"`
		Voter     bool     `json:"voter,omitempty"`
		Port      uint16   `json:"port,omitempty"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		action, err := vpsCapActionOf(req.CapAction)
		if err != nil {
			return "", nil, 0, "", err
		}
		keys := slices.Clone(req.SSHKeys)
		slices.Sort(keys)
		port := req.Port
		if port == 0 {
			port = 7443
		}
		q := control.VPSServerCreate{Name: req.Name, Account: req.Account, Zone: req.Zone, Image: req.Image, Flavor: req.Flavor, Script: req.Script, SSHKeys: slices.Compact(keys),
			CapKRW: req.CapKRW, CapAction: action, Voter: req.Voter, Port: port}
		if !q.Valid() {
			return "", nil, 0, "", invalid("the values do not make a valid VPS server (name, account, zone, image, flavor, capKRW > 0; voter needs a script)")
		}
		page, err := c.QueryVPS(ctx)
		if err != nil {
			return "", nil, 0, "", err
		}
		if _, ok := vpsAccountOf(page, req.Account); !ok {
			return "", nil, 0, "", invalid("account: no such account")
		}
		if _, err := vpsServerOf(page, req.Name); err == nil {
			return "", nil, 0, "", &httpErr{http.StatusConflict, "exists", "a VPS server with this name exists"}
		}
		return sfc.ActionCreateVPSNode, q, page.Revision, "vps/" + req.Name, nil
	})
}

// vpsServerChange is the body of the per-server verbs below.
type vpsServerChange struct {
	OpID     string `json:"opId"`
	Expected uint64 `json:"expected,omitempty"`
	// stop only: how long the leader waits after DNS is taken off (the
	// record TTL), default 300 seconds.
	DNSWaitSeconds *int64 `json:"dnsWaitSeconds,omitempty"`
	// cap only.
	CapKRW    int64   `json:"capKRW,omitempty"`
	CapAction *string `json:"capAction,omitempty"`
}

// POST /system/vps/servers/{name}/stop|start|cap and DELETE
// /system/vps/servers/{name}. stop needs the server cordoned with a recent
// drain that succeeded (POST /nodes/{node}/cordon and /drain first); a
// voter only while one more can be lost. start of a server stopped for the
// cap needs a new month or a cap above the recorded projection.
func (s *Server) handleVPSServer(verb string) func(http.ResponseWriter, *http.Request, *webSession) {
	return func(w http.ResponseWriter, r *http.Request, ws *webSession) {
		var req vpsServerChange
		if !readJSON(w, r, &req) {
			return
		}
		name := r.PathValue("name")
		s.sharedCreate(w, r, ws, req.OpID, actionBody{verb, req}, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
			page, err := c.QueryVPS(ctx)
			if err != nil {
				return "", nil, 0, "", err
			}
			v, err := vpsServerOf(page, name)
			if err != nil {
				return "", nil, 0, "", err
			}
			expected := expectedOr(req.Expected, page.Revision)
			target := "vps/" + name
			switch verb {
			case "stop":
				wait := int64(control.VPSCapDNSWait)
				if req.DNSWaitSeconds != nil {
					wait = *req.DNSWaitSeconds
				}
				if wait < 0 || wait > control.MaxVPSDNSWait {
					return "", nil, 0, "", invalid("dnsWaitSeconds: 0..3600")
				}
				if req.Expected == 0 && v.Phase != control.VPSRunning {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "phase", "only a running VPS server can be stopped"}
				}
				return sfc.ActionStopVPSNode, control.VPSServerStop{Name: name, DNSWaitSeconds: wait}, expected, target, nil
			case "start":
				if req.Expected == 0 && v.Phase != control.VPSStopped && v.Phase != control.VPSCapped {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "phase", "only a stopped VPS server can be started"}
				}
				return sfc.ActionStartVPSNode, control.VPSServerSelection{Name: name}, expected, target, nil
			case "delete":
				if req.Expected == 0 && v.Phase == control.VPSDeleting {
					return "", nil, 0, "", &httpErr{http.StatusConflict, "phase", "the VPS server is already being deleted"}
				}
				return sfc.ActionDeleteVPSNode, control.VPSServerSelection{Name: name}, expected, target, nil
			}
			q := control.VPSServerCap{Name: name, CapKRW: v.CapKRW, CapAction: v.CapAction}
			if req.CapKRW != 0 {
				q.CapKRW = req.CapKRW
			}
			if req.CapAction != nil {
				if q.CapAction, err = vpsCapActionOf(*req.CapAction); err != nil {
					return "", nil, 0, "", err
				}
			}
			if q.CapKRW <= 0 {
				return "", nil, 0, "", invalid("capKRW: the monthly cap in KRW")
			}
			if q == (control.VPSServerCap{Name: name, CapKRW: v.CapKRW, CapAction: v.CapAction}) {
				return "", nil, 0, "", &httpErr{http.StatusConflict, "unchanged", "the server already has this cap"}
			}
			return sfc.ActionSetVPSNodeCap, q, expected, target, nil
		})
	}
}
