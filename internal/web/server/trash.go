// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/network/services"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// "Bring back what was deleted" (UI-A5). Deleting a webhook, an MCP server
// connection or guidelines (web-own), or a network DNS record added by hand
// or a cluster app's routes (kept by sfcd) leaves the definition in web
// bbolt for the retention period (web settings, default 7 days). A restore
// makes the same definition again: web-own ones in bbolt, sfcd's as a new
// change checked against the revision read now. Secret values are never
// kept, so a restored webhook gets a new signing secret and a restored MCP
// server needs its token or login again. Apps taken down keep their own
// archive (archived apps); the list links to it.

const defaultTrashDays = 7

func (s *Server) trashDays() int {
	if d := s.settings().TrashRetentionDays; d > 0 {
		return d
	}
	return defaultTrashDays
}

// putTrash keeps a deleted definition. A failure is logged: the delete
// itself already happened.
func (s *Server) putTrash(user, username, kind, tenant, name, op, id string, data any) *store.TrashItem {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	now := s.now()
	if id == "" {
		id = randomID(12)
	}
	it := &store.TrashItem{ID: id, Kind: kind, Tenant: tenant, Name: name, DeletedBy: username, DeletedByID: user,
		DeletedAt: now, ExpiresAt: now.Add(days(s.trashDays())), Op: op, Data: raw}
	if err := s.opt.Store.PutTrash(it); err != nil {
		s.log.Error("keep deleted", "kind", kind, "name", name, "err", err)
		return nil
	}
	return it
}

// trashRef is what a delete answers so the screen can offer undo.
type trashRef struct {
	ID        string `json:"id"`
	ExpiresAt string `json:"expiresAt"`
}

func refOf(it *store.TrashItem) *trashRef {
	if it == nil {
		return nil
	}
	return &trashRef{it.ID, rfc3339(it.ExpiresAt)}
}

// writeDeleted answers a web-own delete: 200 with the trash reference.
func writeDeleted(w http.ResponseWriter, it *store.TrashItem) {
	writeJSON(w, http.StatusOK, map[string]any{"trash": refOf(it)})
}

// trashFromOp keeps what an applied change of sfcd's definitions took
// away: network DNS records added by hand, and a cluster app's routes. It
// reads the op's revert record (the target before). A restore op drops
// its item.
func (s *Server) trashFromOp(o *store.Op) {
	if o.State != store.OpApplied {
		return
	}
	if o.Restores != "" {
		if _, err := s.opt.Store.TakeTrash(o.Restores); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.log.Error("drop restored", "op", o.ID, "err", err)
		}
	}
	if o.Change == nil {
		return
	}
	before, sent := decodeState(o.Change.Before), decodeState(o.Change.Sent)
	if before == nil || sent == nil {
		return
	}
	switch o.Action {
	case sfc.ActionConfigureNetworkDNS:
		gone := minus(rows(getPath(before, "Policy.Records")), rows(getPath(sent, "Policy.Records")))
		added := rows(getPath(sent, "Policy.Records"))
		for i, x := range gone {
			rec, _ := x.(map[string]any)
			// a record changed in place (same name and type added) is
			// an edit, which the change's revert undoes
			if slices.ContainsFunc(added, func(y any) bool {
				m, _ := y.(map[string]any)
				return m["Name"] == rec["Name"] && m["Type"] == rec["Type"]
			}) {
				continue
			}
			network := strOf(sent["Network"])
			s.putTrash(o.User, o.Username, store.TrashDNSRecord, strOf(sent["Tenant"]), strOf(rec["Name"])+" "+strOf(rec["Type"]), o.ID,
				o.ID+"-"+strconv.Itoa(i), store.TrashDNSRecordData{Network: network, Record: mustJSON(rec)})
		}
	case sfc.ActionRemoveClusterAppRoute:
		if ing := before["Ingress"]; ing != nil {
			app := strOf(before["App"])
			s.putTrash(o.User, o.Username, store.TrashClusterAppRoute, "", deployment.ClusterAppPrefix+app, o.ID, o.ID,
				store.TrashClusterAppRouteData{App: app, Ingress: mustJSON(ing)})
		}
	}
}

// trashView is one row of GET /trash.
type trashView struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Tenant    string `json:"tenant,omitempty"`
	Name      string `json:"name"`
	DeletedBy string `json:"deletedBy"`
	DeletedAt string `json:"deletedAt"`
	ExpiresAt string `json:"expiresAt,omitempty"`
	// Op: the web op whose change removed it (sfcd's definitions)
	Op string `json:"op,omitempty"`
	// Restore: here (POST …/restore) or link (another screen keeps it)
	Restore string      `json:"restore"`
	Link    *revertLink `json:"link,omitempty"`
	// Lost: what a restore cannot bring back (secret, token, login)
	Lost   []string `json:"lost,omitempty"`
	Detail any      `json:"detail,omitempty"`
}

func trashViewOf(it *store.TrashItem) trashView {
	v := trashView{ID: it.ID, Kind: it.Kind, Tenant: it.Tenant, Name: it.Name, DeletedBy: it.DeletedBy, DeletedAt: rfc3339(it.DeletedAt), ExpiresAt: rfc3339(it.ExpiresAt), Op: it.Op, Restore: "here"}
	switch it.Kind {
	case store.TrashWebhook:
		var d store.TrashWebhookData
		_ = json.Unmarshal(it.Data, &d)
		h := d.Webhook
		v.Detail = map[string]any{"kind": h.Kind, "role": h.Role, "format": h.Format, "sign": h.Sign, "url": h.URL, "target": h.Target, "links": len(d.Links)}
		switch h.Sign {
		case "hmac":
			v.Lost = []string{"secret"}
		case "token":
			v.Lost = []string{"token"}
		}
	case store.TrashMCPServer:
		var d store.TrashMCPData
		_ = json.Unmarshal(it.Data, &d)
		v.Detail = map[string]any{"url": d.Server.URL, "auth": d.Server.Auth, "tools": len(d.Server.Tools), "guides": d.Guides}
		switch d.Server.Auth {
		case "bearer":
			v.Lost = []string{"token"}
		case "oauth":
			v.Lost = []string{"login"}
		}
	case store.TrashGuide:
		var d store.TrashGuideData
		_ = json.Unmarshal(it.Data, &d)
		v.Detail = map[string]any{"scope": d.Current.Scope, "app": d.Current.App, "version": d.Current.Version, "versions": len(d.Versions)}
	case store.TrashDNSRecord:
		var d store.TrashDNSRecordData
		_ = json.Unmarshal(it.Data, &d)
		var rec services.DNSRecord
		_ = json.Unmarshal(d.Record, &rec)
		v.Detail = map[string]any{"network": d.Network, "name": rec.Name, "type": rec.Type, "value": rec.Value, "ttl": rec.TTL}
	case store.TrashClusterAppRoute:
		var d store.TrashClusterAppRouteData
		_ = json.Unmarshal(it.Data, &d)
		var ing deployment.IngressDeclaration
		_ = json.Unmarshal(d.Ingress, &ing)
		v.Detail = map[string]any{"app": d.App, "file": clusterAppRouteFile(d.App, ing)}
	}
	return v
}

// trashSees: who may see (and restore or empty) an item. sfcd still
// decides a restore of its own definitions.
func trashSees(acc incidentAccess, it *store.TrashItem) bool {
	switch it.Kind {
	case store.TrashWebhook:
		return acc.webhook(it.Tenant, true)
	case store.TrashGuide:
		var d store.TrashGuideData
		_ = json.Unmarshal(it.Data, &d)
		return acc.canGuide(guideScope{d.Current.Scope, d.Current.Tenant, d.Current.App}, true)
	case store.TrashDNSRecord:
		return acc.admin || acc.roles[it.Tenant] != ""
	}
	return acc.admin // MCP servers, cluster app routes
}

// GET /trash → {items, retentionDays}
func (s *Server) handleListTrash(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	all, err := s.opt.Store.ListTrash(s.now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	items := []trashView{}
	for _, it := range all {
		if trashSees(acc, it) {
			items = append(items, trashViewOf(it))
		}
	}
	// apps taken down: their own archive
	tenants := make([]string, 0, len(acc.roles))
	for t := range acc.roles {
		tenants = append(tenants, t)
	}
	slices.Sort(tenants)
	for _, t := range tenants {
		apps, err := s.opt.Store.ListArchived(t)
		if err != nil {
			continue
		}
		for _, a := range apps {
			items = append(items, trashView{ID: "app:" + a.Key, Kind: "app", Tenant: a.Tenant, Name: a.App, DeletedBy: a.DownBy, DeletedAt: rfc3339(a.DownAt),
				Restore: "link", Link: &revertLink{Kind: "archived-apps", Tenant: a.Tenant, App: a.App}})
		}
	}
	slices.SortStableFunc(items, func(a, b trashView) int { return strings.Compare(b.DeletedAt, a.DeletedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "retentionDays": s.trashDays()})
}

func (s *Server) loadTrash(w http.ResponseWriter, r *http.Request, ws *webSession) (*store.TrashItem, incidentAccess, bool) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return nil, acc, false
	}
	it, err := s.opt.Store.GetTrash(r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || err == nil && (!trashSees(acc, it) || !it.ExpiresAt.After(s.now())) {
		writeError(w, http.StatusNotFound, "not-found", "no such deleted item")
		return nil, acc, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, acc, false
	}
	return it, acc, true
}

// GET /trash/{id}
func (s *Server) handleGetTrash(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if it, _, ok := s.loadTrash(w, r, ws); ok {
		writeJSON(w, http.StatusOK, map[string]any{"item": trashViewOf(it)})
	}
}

// DELETE /trash/{id}: empty it now.
func (s *Server) handleEmptyTrash(w http.ResponseWriter, r *http.Request, ws *webSession) {
	it, _, ok := s.loadTrash(w, r, ws)
	if !ok {
		return
	}
	if _, err := s.opt.Store.TakeTrash(it.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, it.Tenant, "trash", "empty", it.Kind+"/"+it.Name, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /trash/{id}/restore {opId?, name?, replace?}
func (s *Server) handleRestoreTrash(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID    string `json:"opId"`
		Name    string `json:"name"`
		Replace bool   `json:"replace"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	it, _, ok := s.loadTrash(w, r, ws)
	if !ok {
		return
	}
	switch it.Kind {
	case store.TrashWebhook:
		s.restoreWebhook(w, ws, it, req.Name)
	case store.TrashMCPServer:
		s.restoreMCP(w, ws, it, req.Name)
	case store.TrashGuide:
		s.restoreGuide(w, ws, it, req.Replace)
	case store.TrashDNSRecord:
		s.restoreDNSRecord(w, r, ws, it, req.OpID, req.Name, req.Replace)
	case store.TrashClusterAppRoute:
		s.restoreClusterAppRoute(w, r, ws, it, req.OpID, req.Replace)
	default:
		writeError(w, http.StatusUnprocessableEntity, "unsupported", "this kind is not restored here")
	}
}

func exists(what string, current any) error {
	return &existsErr{what, current}
}

type existsErr struct {
	what    string
	current any
}

func (e *existsErr) Error() string { return e.what + " exists" }

// writeExists: 409 exists with what is there now, so the screen offers
// "replace" or "another name".
func writeExists(w http.ResponseWriter, msg string, current any) {
	writeJSON(w, http.StatusConflict, map[string]any{"error": apiError{Code: "exists", Message: msg}, "current": current})
}

func (s *Server) restoreWebhook(w http.ResponseWriter, ws *webSession, it *store.TrashItem, name string) {
	var d store.TrashWebhookData
	if err := json.Unmarshal(it.Data, &d); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	h := d.Webhook
	if name != "" {
		if !validName(name) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "name: lowercase letters, digits and -")
			return
		}
		h.Name = name
	}
	if cur, err := s.opt.Store.GetWebhook(h.Name); err == nil {
		writeExists(w, "a webhook with this name exists", map[string]any{"name": cur.Name, "url": cur.URL, "kind": cur.Kind})
		return
	}
	out := map[string]any{}
	h.Failures, h.RotatingUntil, h.TokenLast4 = 0, time.Time{}, ""
	switch h.Sign {
	case "hmac":
		sec := newSecret()
		if err := s.opt.Seal.Put(webhookSecretKey(h.Name), []byte(sec)); err != nil {
			writeError(w, http.StatusInternalServerError, "internal", "could not seal the secret")
			return
		}
		out["secret"] = map[string]any{"set": true, "value": sec}
	case "token":
		// the token is gone: off until a new one is set
		h.Enabled, h.DisabledReason = false, "restored"
	}
	if err := s.opt.Store.RestoreWebhook(&h, d.Links); errors.Is(err, store.ErrConflict) {
		writeExists(w, "a webhook with this name exists", map[string]any{"name": h.Name})
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_, _ = s.opt.Store.TakeTrash(it.ID)
	s.audit(ws, h.Tenant, "webhooks", "restore", h.Name, nil, map[string]any{"from": d.Webhook.Name, "links": len(d.Links)})
	out["restored"] = map[string]any{"kind": it.Kind, "name": h.Name, "enabled": h.Enabled}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) restoreMCP(w http.ResponseWriter, ws *webSession, it *store.TrashItem, name string) {
	var d store.TrashMCPData
	if err := json.Unmarshal(it.Data, &d); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	m := d.Server
	if name != "" {
		if !validName(name) {
			writeError(w, http.StatusUnprocessableEntity, "invalid", "name: lowercase letters, digits and -")
			return
		}
		m.Name = name
	}
	m.TokenLast4, m.TokenExpiresAt = "", time.Time{}
	switch m.Auth {
	case "bearer":
		m.Enabled, m.State, m.Error = false, "error", "token needed"
	case "oauth":
		m.NeedsLogin = true
	}
	if err := s.opt.Store.CreateMCPServer(&m); errors.Is(err, store.ErrConflict) {
		writeExists(w, "an MCP server with this name exists", map[string]any{"name": m.Name})
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if err := s.opt.Store.AddGuideMCP(m.Name, d.Guides); err != nil {
		s.log.Error("restore mcp guides", "name", m.Name, "err", err)
	}
	_, _ = s.opt.Store.TakeTrash(it.ID)
	s.audit(ws, "", "mcp", "restore", m.Name, nil, map[string]any{"from": d.Server.Name})
	writeJSON(w, http.StatusOK, map[string]any{"restored": map[string]any{"kind": it.Kind, "name": m.Name, "enabled": m.Enabled}})
}

func (s *Server) restoreGuide(w http.ResponseWriter, ws *webSession, it *store.TrashItem, replace bool) {
	var d store.TrashGuideData
	if err := json.Unmarshal(it.Data, &d); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	g := d.Current
	err := s.opt.Store.RestoreGuide(&g, d.Versions)
	if errors.Is(err, store.ErrConflict) {
		cur, gerr := s.opt.Store.GetGuide(g.Scope)
		if gerr != nil {
			writeError(w, http.StatusInternalServerError, "internal", gerr.Error())
			return
		}
		if !replace {
			writeExists(w, "this scope has guidelines now", map[string]any{"scope": cur.Scope, "version": cur.Version, "updatedBy": cur.UpdatedBy})
			return
		}
		// as a new version on top of the current one
		n := d.Current
		n.UpdatedBy, n.UpdatedAt = ws.user.Username, s.now()
		err = s.opt.Store.SaveGuide(&n, cur.Version)
		g = n
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	_, _ = s.opt.Store.TakeTrash(it.ID)
	s.audit(ws, g.Tenant, "guides", "restore", g.Scope, nil, map[string]any{"version": g.Version})
	writeJSON(w, http.StatusOK, map[string]any{"restored": map[string]any{"kind": it.Kind, "name": g.Scope, "version": g.Version}})
}

func (s *Server) restoreDNSRecord(w http.ResponseWriter, r *http.Request, ws *webSession, it *store.TrashItem, opID, name string, replace bool) {
	var d store.TrashDNSRecordData
	var rec services.DNSRecord
	if json.Unmarshal(it.Data, &d) != nil || json.Unmarshal(d.Record, &rec) != nil {
		writeError(w, http.StatusInternalServerError, "internal", "bad deleted record")
		return
	}
	body := struct {
		ID, Name string
		Replace  bool
	}{it.ID, name, replace}
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		n, _, err := revNetwork(ctx, c, it.Tenant, d.Network)
		if err != nil {
			return "", nil, 0, "", err
		}
		if n == nil || n.DNS == nil || n.DNS.Policy.Transports == nil {
			return "", nil, 0, "", invalidCode("target-gone", "the network or its managed DNS is gone")
		}
		p := n.DNS.Policy
		zone, err := services.Domain(p.Zone)
		if err != nil {
			return "", nil, 0, "", err
		}
		clientZone := ""
		if p.ClientZone != "" {
			clientZone, _ = services.Domain(p.ClientZone)
		}
		want := rec
		if name != "" {
			if want, err = dnsRecordOf(dnsRecordInput{Name: name, Type: rec.Type, Value: rec.Value, TTL: rec.TTL}, zone); err != nil {
				return "", nil, 0, "", err
			}
		} else if !strings.HasSuffix(want.Name, "."+zone) && want.Name != zone {
			return "", nil, 0, "", invalidCode("zone-changed", "the network's zone changed; restore it under another name")
		}
		records := slices.Clone(p.Records)
		if slices.ContainsFunc(records, func(o services.DNSRecord) bool { return sameDNSRecord(o, want) }) {
			return "", nil, 0, "", invalidCode("exists", "the list has this record now")
		}
		same := func(o services.DNSRecord) bool { return o.Name == want.Name && o.Type == want.Type }
		if slices.ContainsFunc(records, same) {
			if !replace {
				var now []services.DNSRecord
				for _, o := range records {
					if same(o) {
						now = append(now, o)
					}
				}
				return "", nil, 0, "", exists("record", now)
			}
			records = slices.DeleteFunc(records, same)
		}
		records = append(records, want)
		if records, err = services.ValidDNSRecords(zone, clientZone, records); err != nil {
			return "", nil, 0, "", invalid("records: the restored record does not fit the list (a CNAME alone at its name, up to 8 of one type per name, at most 64)")
		}
		p.Records = records
		def := services.ManagedDNSDefinition{Schema: 1, Tenant: it.Tenant, Network: d.Network, Policy: p}
		return sfc.ActionConfigureNetworkDNS, opPayload{payload: def, tenant: it.Tenant, restores: it.ID}, n.DNS.Revision, d.Network, nil
	})
}

func (s *Server) restoreClusterAppRoute(w http.ResponseWriter, r *http.Request, ws *webSession, it *store.TrashItem, opID string, replace bool) {
	var d store.TrashClusterAppRouteData
	var ing deployment.IngressDeclaration
	if json.Unmarshal(it.Data, &d) != nil || json.Unmarshal(d.Ingress, &ing) != nil {
		writeError(w, http.StatusInternalServerError, "internal", "bad deleted routes")
		return
	}
	body := struct {
		ID      string
		Replace bool
	}{it.ID, replace}
	s.sharedCreate(w, r, ws, opID, body, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		v, err := clusterAppRoute(ctx, c, d.App)
		if err != nil {
			return "", nil, 0, "", err
		}
		if !v.Removed && v.Revision != 0 && !replace {
			return "", nil, 0, "", exists("routes", clusterAppRouteOf(v))
		}
		return sfc.ActionPutClusterAppRoute, opPayload{payload: control.ClusterAppRouteChange{App: d.App, Ingress: ing}, restores: it.ID}, v.Revision, deployment.ClusterAppPrefix + d.App, nil
	})
}
