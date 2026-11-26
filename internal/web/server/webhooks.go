// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jay94ks/mydcd/internal/servicecall"
	"github.com/jay94ks/mydcd/internal/web/mydc"
	"github.com/jay94ks/mydcd/internal/web/store"
)

// Webhooks (W2.3b, UI-BB). External webhooks are sent by mydc-web to a
// public https address; internal ones go to an app service inside a
// workspace network through mydcd's service-call. Secrets and
// header tokens are sealed; the store keeps only their last 4 characters.

const (
	webhookBodyMax       = 256 << 10
	webhookRespMax       = 64 << 10
	webhookDecideTimeout = 10 * time.Second
	webhookNotifyTimeout = 30 * time.Second
	webhookDisableAfter  = 3 // failed deliveries in a row
	webhookRotateFor     = 24 * time.Hour
)

var (
	webhookNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)
	// Retries of a notify webhook after the first try.
	webhookBackoff = []time.Duration{time.Second, 10 * time.Second, time.Minute}
)

// webhookState is the background sends (tests wait on it).
type webhookState struct {
	wg      sync.WaitGroup
	backoff []time.Duration // nil: webhookBackoff
	ingress ingressHookState
	// mcpAuto holds the limit check and the record of an automatic MCP
	// incident call together (two incidents cannot both take the last run).
	mcpAuto sync.Mutex
	// reachPort overrides :443 of the DNS server reach check (tests).
	reachPort string
}

// Sealed entry names. The prefixes never extend each other, so one
// webhook's entry cannot be another's (names start with a letter).
func webhookSecretKey(name string) string    { return "webhook-hmac-" + name }
func webhookOldSecretKey(name string) string { return "webhook-oldhmac-" + name }
func webhookTokenKey(name string) string     { return "webhook-token-" + name }

// Special ranges that are not "private" to netip but still not the public
// internet (NAT64, 6to4, Teredo, documentation, benchmarking, ORCHID).
var webhookBlocked = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:2::/48"), netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("2001:20::/28"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// webhookAddrOK: an address a webhook may reach (public unicast only).
func (s *Server) webhookAddrOK(a netip.Addr) bool {
	if s.opt.WebhookAllowAddr != nil {
		return s.opt.WebhookAllowAddr(a)
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range webhookBlocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// checkWebhookURL: https, no user info, not a private host ("" = fine).
func (s *Server) checkWebhookURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(raw) > 2048 {
		return "url: an https address without user info"
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") {
		return "url: private addresses are not allowed"
	}
	if a, err := netip.ParseAddr(host); err == nil && !s.webhookAddrOK(a) {
		return "url: private addresses are not allowed"
	}
	return ""
}

// webhookClient dials public addresses only and never follows redirects.
func (s *Server) webhookClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !s.webhookAddrOK(ap.Addr()) {
			return errors.New("webhook: address not allowed")
		}
		return nil
	}}
	tr := &http.Transport{DialContext: d.DialContext, TLSClientConfig: s.opt.WebhookTLS.Clone(), TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: timeout, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, ForceAttemptHTTP2: true}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// webhookAccess: system administrators all; a workspace's managers its
// webhooks and links; its members read its links.
func (a incidentAccess) webhook(tenant string, manage bool) bool {
	if a.admin {
		return true
	}
	if tenant == "" {
		return false
	}
	role := a.roles[tenant]
	return role != "" && (!manage || role == mydc.RoleManager)
}

func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "whsec_" + hex.EncodeToString(b)
}

func last4(s string) string {
	r := []rune(s)
	if len(r) <= 4 {
		return ""
	}
	return string(r[len(r)-4:])
}

type webhookReq struct {
	Revision uint64               `json:"revision"`
	Name     string               `json:"name"`
	Tenant   string               `json:"tenant"`
	Kind     string               `json:"kind"`
	URL      *string              `json:"url,omitempty"`
	Target   *store.WebhookTarget `json:"target,omitempty"`
	Role     string               `json:"role"`
	Format   string               `json:"format"`
	Sign     string               `json:"sign"`
	Token    *string              `json:"token,omitempty"`
	Enabled  *bool                `json:"enabled,omitempty"`
}

// checkWebhook validates w as it would be stored ("" = fine).
func (s *Server) checkWebhook(w *store.Webhook) string {
	switch {
	case !webhookNameRE.MatchString(w.Name):
		return "name: lowercase letters, digits and -, starting with a letter, up to 31"
	case w.Tenant != "" && !safeParamRE.MatchString(w.Tenant):
		return "tenant: not a workspace name"
	case w.Role != "notify" && w.Role != "decide":
		return "role: notify or decide"
	case w.Format != "mydc" && w.Format != "slack" && w.Format != "teams" && w.Format != "pagerduty":
		return "format: mydc, slack, teams or pagerduty"
	case w.Role == "decide" && w.Format != "mydc":
		return "format: decide webhooks answer in the mydc format"
	case w.Sign != "hmac" && w.Sign != "token" && w.Sign != "none":
		return "sign: hmac, token or none"
	}
	switch w.Kind {
	case "external":
		w.Target = nil
		return s.checkWebhookURL(w.URL)
	case "internal":
		w.URL = ""
		t := w.Target
		switch {
		case w.Tenant == "":
			return "tenant: an internal webhook belongs to the workspace of its app"
		case t == nil || !safeParamRE.MatchString(t.App) || !safeParamRE.MatchString(t.Service):
			return "target: app and service of the workspace"
		case t.Port < 1 || t.Port > 65535:
			return "target.port: 1..65535"
		case t.Path == "" || t.Path[0] != '/' || len(t.Path) > 512 || strings.ContainsAny(t.Path, " \r\n#"):
			return "target.path: starts with /"
		}
		if t.Scheme == "" {
			t.Scheme = "http"
		}
		if t.Scheme != "http" && t.Scheme != "https" {
			return "target.scheme: http or https"
		}
		if t.Scheme == "http" {
			t.InsecureSkipVerify = false
		}
		return ""
	}
	return "kind: external or internal"
}

func validToken(t string) bool {
	if t == "" || len(t) > 512 || !utf8.ValidString(t) {
		return false
	}
	for _, r := range t {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func (s *Server) loadWebhook(w http.ResponseWriter, r *http.Request, ws *webSession, manage bool) (*store.Webhook, incidentAccess, bool) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return nil, acc, false
	}
	h, err := s.opt.Store.GetWebhook(r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) || err == nil && !acc.webhook(h.Tenant, true) {
		writeError(w, http.StatusNotFound, "not-found", "no such webhook")
		return nil, acc, false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil, acc, false
	}
	return h, acc, true
}

// GET /webhooks?tenant=
func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request, ws *webSession) {
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	all, err := s.opt.Store.ListWebhooks()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	links, _ := s.opt.Store.ListWebhookLinks()
	t := r.URL.Query().Get("tenant")
	items := []map[string]any{}
	for _, h := range all {
		if !acc.webhook(h.Tenant, true) || t != "" && h.Tenant != t {
			continue
		}
		items = append(items, s.webhookView(h, links))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// GET /webhooks/{name}
func (s *Server) handleGetWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	h, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	links, _ := s.opt.Store.ListWebhookLinks()
	writeJSON(w, http.StatusOK, s.webhookView(h, links))
}

func (s *Server) webhookView(h *store.Webhook, links []*store.WebhookLink) map[string]any {
	v := map[string]any{"name": h.Name, "kind": h.Kind, "role": h.Role, "format": h.Format, "sign": h.Sign, "enabled": h.Enabled,
		"revision": h.Revision, "createdBy": h.CreatedBy, "createdAt": rfc3339(h.CreatedAt)}
	if h.Tenant != "" {
		v["tenant"] = h.Tenant
	}
	if h.URL != "" {
		v["url"] = h.URL
	}
	if h.Target != nil {
		v["target"] = h.Target
	}
	sec := map[string]any{"set": h.Sign == "hmac"}
	if h.Sign == "hmac" && s.now().Before(h.RotatingUntil) {
		sec["rotatingUntil"] = rfc3339(h.RotatingUntil)
	}
	v["secret"] = sec
	if h.Sign == "token" {
		v["token"] = map[string]any{"set": true, "last4": h.TokenLast4}
	}
	if h.DisabledReason != "" && !h.Enabled {
		v["disabledReason"] = h.DisabledReason
	}
	ds, _ := s.opt.Store.ListWebhookDeliveries(h.Name)
	state := "ok"
	var last *store.WebhookDelivery
	for _, d := range ds {
		if d.Point != "test" {
			last = d
			break
		}
	}
	if last == nil && len(ds) > 0 {
		last = ds[0]
	}
	if last != nil {
		ld := map[string]any{"at": rfc3339(last.At), "ms": last.MS}
		if last.Status != 0 {
			ld["status"] = last.Status
		}
		if last.Error != "" {
			ld["error"] = last.Error
		}
		if !last.Done && last.Of > 1 {
			ld["retry"] = map[string]int{"attempt": last.Attempt, "of": last.Of}
		}
		v["lastDelivery"] = ld
		if last.Done && !last.OK() || !last.Done && last.Attempt > 1 {
			state = "failing"
		}
	}
	if !h.Enabled {
		state = "disabled"
	}
	v["state"] = state
	day := s.now().Truncate(24 * time.Hour)
	today, failed, ms := 0, 0, 0
	for _, d := range ds {
		if d.At.Before(day) {
			break
		}
		if d.Point == "test" || !d.Done {
			continue
		}
		today++
		ms += d.MS
		if !d.OK() {
			failed++
		}
	}
	avg := 0
	if today > 0 {
		avg = ms / today
	}
	v["stats"] = map[string]int{"today": today, "failed": failed, "avgMs": avg}
	n := 0
	for _, l := range links {
		if l.Webhook == h.Name {
			n++
		}
	}
	v["links"] = n
	return v
}

// POST /webhooks {name, tenant?, kind, url|target, role, format, sign?,
// token?} → the webhook, with its secret once (sign hmac).
func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req webhookReq
	if !readJSON(w, r, &req) {
		return
	}
	h := &store.Webhook{Name: req.Name, Tenant: req.Tenant, Kind: req.Kind, Target: req.Target, Role: req.Role, Format: req.Format, Sign: req.Sign,
		Enabled: true, CreatedBy: ws.user.Username, CreatedByID: ws.user.ID, CreatedAt: s.now()}
	if req.URL != nil {
		h.URL = *req.URL
	}
	if h.Format == "" {
		h.Format = "mydc"
	}
	if h.Sign == "" {
		h.Sign = "hmac"
	}
	if msg := s.checkWebhook(h); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	acc, err := s.incidentAccessOf(r, ws)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	if !acc.webhook(h.Tenant, true) {
		writeError(w, http.StatusForbidden, "denied", "cluster webhooks need a system administrator; workspace webhooks its managers")
		return
	}
	if h.Sign == "token" && (req.Token == nil || !validToken(*req.Token)) {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "token: the header value, 1..512 visible ASCII characters")
		return
	}
	if _, err := s.opt.Store.GetWebhook(h.Name); err == nil {
		writeError(w, http.StatusConflict, "exists", "a webhook with this name exists")
		return
	}
	out := map[string]any{}
	if err := s.sealWebhookSecrets(h, req.Token, out, true); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the secret")
		return
	}
	if err := s.opt.Store.CreateWebhook(h); errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "exists", "a webhook with this name exists")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, h.Tenant, "webhooks", "create", h.Name, nil, map[string]any{"kind": h.Kind, "role": h.Role, "sign": h.Sign})
	v := s.webhookView(h, nil)
	for k, x := range out {
		v[k] = x
	}
	writeJSON(w, http.StatusCreated, v)
}

// sealWebhookSecrets stores the secret (hmac) or token of h and drops the
// other; a new secret goes into out once. fresh (a new webhook) always
// makes a new secret and drops anything left under its names.
func (s *Server) sealWebhookSecrets(h *store.Webhook, token *string, out map[string]any, fresh bool) error {
	if fresh {
		for _, k := range []string{webhookSecretKey(h.Name), webhookOldSecretKey(h.Name), webhookTokenKey(h.Name)} {
			_ = s.opt.Seal.Delete(k)
		}
	}
	switch h.Sign {
	case "hmac":
		if _, err := s.opt.Seal.Get(webhookSecretKey(h.Name)); fresh || err != nil {
			sec := newSecret()
			if err := s.opt.Seal.Put(webhookSecretKey(h.Name), []byte(sec)); err != nil {
				return err
			}
			out["secret"] = map[string]any{"set": true, "value": sec}
		}
		_ = s.opt.Seal.Delete(webhookTokenKey(h.Name))
		h.TokenLast4 = ""
	case "token":
		if token != nil {
			if err := s.opt.Seal.Put(webhookTokenKey(h.Name), []byte(*token)); err != nil {
				return err
			}
			h.TokenLast4 = last4(*token)
		}
		_ = s.opt.Seal.Delete(webhookSecretKey(h.Name))
		_ = s.opt.Seal.Delete(webhookOldSecretKey(h.Name))
	default:
		_ = s.opt.Seal.Delete(webhookSecretKey(h.Name))
		_ = s.opt.Seal.Delete(webhookOldSecretKey(h.Name))
		_ = s.opt.Seal.Delete(webhookTokenKey(h.Name))
		h.TokenLast4 = ""
	}
	return nil
}

// PUT /webhooks/{name} {revision, url?, target?, format?, sign?, token?,
// enabled?}. Kind, role and workspace stay.
func (s *Server) handlePutWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req webhookReq
	if !readJSON(w, r, &req) {
		return
	}
	cur, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	if req.Kind != "" && req.Kind != cur.Kind || req.Role != "" && req.Role != cur.Role || req.Tenant != "" && req.Tenant != cur.Tenant ||
		req.Name != "" && req.Name != cur.Name {
		writeError(w, http.StatusUnprocessableEntity, "immutable", "name, workspace, kind and role cannot change; make a new webhook")
		return
	}
	next := *cur
	if req.URL != nil {
		next.URL = *req.URL
	}
	if req.Target != nil {
		next.Target = req.Target
	}
	if req.Format != "" {
		next.Format = req.Format
	}
	if req.Sign != "" {
		next.Sign = req.Sign
	}
	if msg := s.checkWebhook(&next); msg != "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid", msg)
		return
	}
	if next.Sign == "token" && (req.Token != nil && !validToken(*req.Token) || req.Token == nil && cur.Sign != "token") {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "token: the header value, 1..512 visible ASCII characters")
		return
	}
	if req.Revision != cur.Revision {
		writeError(w, http.StatusConflict, "stale", "the webhook changed; read it again")
		return
	}
	out := map[string]any{}
	if err := s.sealWebhookSecrets(&next, req.Token, out, false); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the secret")
		return
	}
	h, err := s.opt.Store.UpdateWebhook(cur.Name, req.Revision, func(x *store.Webhook) error {
		x.URL, x.Target, x.Format, x.Sign, x.TokenLast4 = next.URL, next.Target, next.Format, next.Sign, next.TokenLast4
		if next.Sign != "hmac" {
			x.RotatingUntil = time.Time{}
		}
		if req.Enabled != nil {
			if *req.Enabled && !x.Enabled {
				x.Failures, x.DisabledReason = 0, ""
			}
			if !*req.Enabled && x.Enabled {
				x.DisabledReason = "manual"
			}
			x.Enabled = *req.Enabled
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "stale", "the webhook changed; read it again")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, h.Tenant, "webhooks", "update", h.Name, nil, map[string]any{"sign": h.Sign, "enabled": h.Enabled})
	links, _ := s.opt.Store.ListWebhookLinks()
	v := s.webhookView(h, links)
	for k, x := range out {
		v[k] = x
	}
	writeJSON(w, http.StatusOK, v)
}

// DELETE /webhooks/{name} {confirmName}
func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		ConfirmName string `json:"confirmName"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	h, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	if req.ConfirmName != h.Name {
		writeError(w, http.StatusUnprocessableEntity, "confirm-name", "type the webhook's name to delete it")
		return
	}
	if err := s.opt.Store.DeleteWebhook(h.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	for _, k := range []string{webhookSecretKey(h.Name), webhookOldSecretKey(h.Name), webhookTokenKey(h.Name)} {
		_ = s.opt.Seal.Delete(k)
	}
	s.audit(ws, h.Tenant, "webhooks", "delete", h.Name, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// POST /webhooks/{name}/rotate → {secret}: both signatures go for 24 hours.
func (s *Server) handleRotateWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	h, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	if h.Sign != "hmac" {
		writeError(w, http.StatusConflict, "not-hmac", "only HMAC webhooks have a secret to rotate")
		return
	}
	old, err := s.opt.Seal.Get(webhookSecretKey(h.Name))
	sec := newSecret()
	if err == nil {
		err = s.opt.Seal.Put(webhookOldSecretKey(h.Name), old)
	}
	if err == nil {
		err = s.opt.Seal.Put(webhookSecretKey(h.Name), []byte(sec))
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not seal the secret")
		return
	}
	until := s.now().Add(webhookRotateFor)
	if _, err := s.opt.Store.UpdateWebhook(h.Name, 0, func(x *store.Webhook) error { x.RotatingUntil = until; return nil }); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(ws, h.Tenant, "webhooks", "rotate", h.Name, nil, nil)
	writeJSON(w, http.StatusOK, map[string]any{"secret": map[string]any{"set": true, "value": sec, "rotatingUntil": rfc3339(until)}})
}

// webhookSend is one prepared send.
type webhookSend struct {
	Point, Event string
	Link         string         // the link it is sent for ("" for tests)
	Payload      map[string]any // the mydc body; other formats are built from it
	Summary      string         // one line for slack/teams/pagerduty
	Decide       bool
	Timeout      time.Duration // decide only (0: 10 s)
	ws           *webSession   // internal sends: the session to call as (nil: the automation account)
}

// webhookBody renders the body in the webhook's format.
func webhookBody(h *store.Webhook, m webhookSend, id string, at time.Time) ([]byte, error) {
	p := map[string]any{}
	for k, v := range m.Payload {
		p[k] = v
	}
	p["event"], p["deliveryId"], p["at"] = m.Event, id, rfc3339(at)
	if _, ok := p["point"]; !ok {
		p["point"] = m.Point
	}
	var v any = p
	text := m.Summary
	if text == "" {
		text = "MyDC " + m.Event
	}
	switch h.Format {
	case "slack":
		v = map[string]any{"text": text}
	case "teams":
		v = map[string]any{"@type": "MessageCard", "@context": "https://schema.org/extensions", "summary": text, "text": text}
	case "pagerduty":
		action := "trigger"
		if strings.HasSuffix(m.Event, ".recovered") || strings.HasSuffix(m.Event, ".closed") {
			action = "resolve"
		}
		key, _ := p["dedupKey"].(string)
		v = map[string]any{"event_action": action, "dedup_key": key, "payload": map[string]any{"summary": text, "source": "mydc", "severity": "error", "custom_details": p}}
	}
	raw, err := json.Marshal(v)
	if err == nil && len(raw) > webhookBodyMax {
		err = errors.New("body-too-large")
	}
	return raw, err
}

func webhookSign(secret []byte, ts int64, body []byte) string {
	m := hmac.New(sha256.New, secret)
	fmt.Fprintf(m, "%d.", ts)
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// webhookHeaders: content type, event, delivery id, then the signature
// (both secrets while rotating) or the header token.
func (s *Server) webhookHeaders(h *store.Webhook, event, id string, body []byte) (map[string]string, error) {
	hd := map[string]string{"Content-Type": "application/json", "X-MyDC-Event": event, "X-MyDC-Delivery": id}
	switch h.Sign {
	case "hmac":
		sec, err := s.opt.Seal.Get(webhookSecretKey(h.Name))
		if err != nil {
			return nil, errors.New("secret-unavailable")
		}
		ts := s.now().Unix()
		sig := fmt.Sprintf("t=%d,v1=%s", ts, webhookSign(sec, ts, body))
		if s.now().Before(h.RotatingUntil) {
			if old, err := s.opt.Seal.Get(webhookOldSecretKey(h.Name)); err == nil {
				sig += ",v1=" + webhookSign(old, ts, body)
			}
		}
		hd["X-MyDC-Signature"] = sig
	case "token":
		tok, err := s.opt.Seal.Get(webhookTokenKey(h.Name))
		if err != nil {
			return nil, errors.New("token-unavailable")
		}
		hd["X-MyDC-Token"] = string(tok)
	}
	return hd, nil
}

// webhookAttempt sends once: status, answer (≤ 64 KiB), error code.
func (s *Server) webhookAttempt(ctx context.Context, h *store.Webhook, m webhookSend, hd map[string]string, body []byte, timeout time.Duration) (int, []byte, string) {
	if h.Kind == "internal" {
		ws := m.ws
		if ws == nil {
			var err error
			if ws, err = s.watchSession(ctx); err != nil {
				return 0, nil, automationErrorCode(err)
			}
		}
		// One service-call; mydcd never resends it, and a timeout, refusal
		// or lost reply may still have reached the app (retryable).
		var res servicecall.Result
		err := ws.do(ctx, func(ctx context.Context, c mydc.Conn) error {
			var err error
			res, err = c.CallService(ctx, h.Tenant, servicecall.Request{App: h.Target.App, Service: h.Target.Service, Port: h.Target.Port,
				Path: h.Target.Path, Method: http.MethodPost, Headers: hd, Body: body, TimeoutMS: int(timeout / time.Millisecond),
				Scheme: h.Target.Scheme, InsecureSkipVerify: h.Target.InsecureSkipVerify})
			return err
		})
		if err != nil {
			var me *mydc.Error
			if errors.As(err, &me) {
				return 0, nil, string(me.Code)
			}
			return 0, nil, "unavailable"
		}
		if res.Code != "" {
			return res.Status, nil, res.Code
		}
		ans := res.Body
		if len(ans) > webhookRespMax {
			ans = ans[:webhookRespMax]
		}
		return res.Status, ans, ""
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, "invalid-url"
	}
	for k, v := range hd {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "mydc-web")
	resp, err := s.webhookClient(timeout).Do(req)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "Client.Timeout"):
			return 0, nil, "timeout"
		case strings.Contains(err.Error(), "address not allowed"):
			return 0, nil, "address-not-allowed"
		case strings.Contains(err.Error(), "tls") || strings.Contains(err.Error(), "x509"):
			return 0, nil, "tls"
		}
		return 0, nil, "connect"
	}
	defer resp.Body.Close()
	ans, _ := io.ReadAll(io.LimitReader(resp.Body, webhookRespMax))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.StatusCode, nil, "redirect"
	}
	return resp.StatusCode, ans, ""
}

// retryable: whether another try may follow. An answered 429/5xx is
// retried (same X-MyDC-Delivery, the receiver can tell). For an internal
// webhook only failures that never reached the app are retried (no ready
// task, rate-limited): service-call's timeout, refusal or a lost mydcd
// reply may already have run the request, so it is not sent again.
func retryable(internal bool, status int, code string) bool {
	if code == "" {
		return status == 429 || status >= 500
	}
	if internal {
		return code == servicecall.NoReadyTask || code == servicecall.RateLimited
	}
	return code == "timeout" || code == "connect"
}

// deliverWebhook sends m to h: once for decide (10 s), up to 1 + 3 tries
// for notify. The delivery is recorded after each try; the answer of the
// last try is returned. A disabled webhook is not sent to (nil).
func (s *Server) deliverWebhook(ctx context.Context, h *store.Webhook, m webhookSend) (*store.WebhookDelivery, []byte) {
	if !h.Enabled && m.Point != "test" {
		return nil, nil
	}
	d := &store.WebhookDelivery{ID: "d-" + randomID(10), Webhook: h.Name, At: s.now(), Point: m.Point, Event: m.Event, Link: m.Link, Attempt: 1, Of: 1}
	timeout, backoff := webhookDecideTimeout, []time.Duration(nil)
	if m.Timeout > 0 {
		timeout = m.Timeout
	}
	if !m.Decide && m.Point != "test" {
		timeout, backoff = webhookNotifyTimeout, webhookBackoff
		if s.hooks.backoff != nil {
			backoff = s.hooks.backoff
		}
		d.Of = 1 + len(backoff)
	}
	body, err := webhookBody(h, m, d.ID, d.At)
	var hd map[string]string
	if err == nil {
		hd, err = s.webhookHeaders(h, m.Event, d.ID, body)
	}
	if err != nil {
		d.Error, d.Done = err.Error(), true
		s.recordDelivery(h, d)
		return d, nil
	}
	var ans []byte
	for i := 0; ; i++ {
		start := time.Now()
		status, out, code := s.webhookAttempt(ctx, h, m, hd, body, timeout)
		d.MS = int(time.Since(start) / time.Millisecond)
		if i == 0 {
			d.FirstStatus = status
		}
		d.Status, d.Error, ans = status, code, out
		if code == "" && (status < 200 || status >= 300) {
			d.Error = fmt.Sprintf("http-%d", status)
		}
		d.Retries = i
		if d.OK() || i >= len(backoff) || !retryable(h.Kind == "internal", status, code) {
			break
		}
		d.Attempt = i + 2
		s.recordDelivery(h, d)
		select {
		case <-ctx.Done():
			d.Error = "canceled"
			d.Done = true
			s.recordDelivery(h, d)
			return d, nil
		case <-time.After(backoff[i]):
		}
	}
	if d.Retries == 0 {
		d.FirstStatus = 0
	}
	d.Done = true
	s.recordDelivery(h, d)
	return d, ans
}

// recordDelivery stores d and, once done, the webhook's failure count:
// 3 failed deliveries in a row turn it off and tell its creator.
func (s *Server) recordDelivery(h *store.Webhook, d *store.WebhookDelivery) {
	if err := s.opt.Store.PutWebhookDelivery(d); err != nil {
		s.log.Error("webhook delivery", "err", err, "webhook", h.Name)
	}
	if !d.Done || d.Point == "test" {
		return
	}
	var off bool
	nh, err := s.opt.Store.UpdateWebhook(h.Name, 0, func(x *store.Webhook) error {
		if d.OK() {
			x.Failures = 0
			return nil
		}
		x.Failures++
		if x.Failures >= webhookDisableAfter && x.Enabled {
			x.Enabled, x.DisabledReason, off = false, "failures", true
		}
		return nil
	})
	if err != nil || !off {
		return
	}
	s.log.Warn("webhook turned off after failures", "webhook", h.Name)
	if u := nh.CreatedByID; u != "" {
		s.notify(&store.Notification{User: u, Kind: NotifyWebhookOff, Severity: "warning", Tenant: nh.Tenant, Title: "웹훅 " + nh.Name + "이(가) 꺼졌어요",
			Body: fmt.Sprintf("%d번 잇달아 보내지 못해 껐어요 (%s). 확인한 뒤 다시 켜 주세요.", webhookDisableAfter, d.Error), Link: "/incidents/webhooks", Action: true})
	}
}

// sendWebhookLater delivers in the background (notify webhooks).
func (s *Server) sendWebhookLater(h *store.Webhook, m webhookSend) {
	s.hooks.wg.Add(1)
	go func() {
		defer s.hooks.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		s.deliverWebhook(ctx, h, m)
	}()
}

// POST /webhooks/{name}/test → {delivery, steps}: one sample event, sent
// as the caller (internal webhooks: the caller's session).
func (s *Server) handleTestWebhook(w http.ResponseWriter, r *http.Request, ws *webSession) {
	h, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	m := webhookSend{Point: "test", Event: "test", Summary: "MyDC 웹훅 시험: " + h.Name, ws: ws,
		Payload: map[string]any{"webhook": h.Name, "test": true, "role": h.Role}}
	if h.Role == "decide" {
		m.Payload["allowed"] = []string{"none"}
	}
	ctx, cancel := context.WithTimeout(r.Context(), webhookDecideTimeout+5*time.Second)
	defer cancel()
	d, ans := s.deliverWebhook(ctx, h, m)
	where := h.URL
	if h.Target != nil {
		where = fmt.Sprintf("%s/%s/%s :%d %s (%s)", h.Tenant, h.Target.App, h.Target.Service, h.Target.Port, h.Target.Path, h.Target.Scheme)
	}
	steps := []map[string]string{{"label": "주소 확인", "detail": where}}
	if d.Error != "" && d.Status == 0 {
		steps = append(steps, map[string]string{"label": "보냄", "detail": "실패 · " + d.Error})
	} else {
		steps = append(steps, map[string]string{"label": "보냄", "detail": "POST · 서명 " + h.Sign},
			map[string]string{"label": "응답", "detail": fmt.Sprintf("%d · %.1f초", d.Status, float64(d.MS)/1000)})
		if h.Role == "decide" {
			var x map[string]any
			ok := json.Unmarshal(ans, &x) == nil && (x["action"] != nil || x["decision"] != nil || x["result"] != nil)
			detail := "JSON 객체에 action·decision·result 중 하나가 있음"
			if !ok {
				detail = "형식이 맞지 않음: JSON 객체에 action·decision·result 중 하나가 있어야 합니다"
			}
			steps = append(steps, map[string]string{"label": "판단 응답 형식", "detail": detail})
		}
	}
	s.audit(ws, h.Tenant, "webhooks", "test", h.Name, nil, map[string]any{"status": d.Status, "error": d.Error})
	writeJSON(w, http.StatusOK, map[string]any{"delivery": deliveryView(d), "steps": steps})
}

func deliveryView(d *store.WebhookDelivery) map[string]any {
	v := map[string]any{"id": d.ID, "at": rfc3339(d.At), "point": d.Point, "event": d.Event, "ms": d.MS, "done": d.Done}
	if d.Status != 0 {
		v["status"] = d.Status
	}
	if d.Error != "" {
		v["error"] = d.Error
	}
	if d.Retries > 0 {
		v["retries"] = d.Retries
		if d.FirstStatus != 0 {
			v["firstStatus"] = d.FirstStatus
		}
	}
	if !d.Done && d.Of > 1 {
		v["retry"] = map[string]int{"attempt": d.Attempt, "of": d.Of}
	}
	if d.Decision != "" {
		v["decision"] = d.Decision
	}
	if d.Accepted != nil {
		v["accepted"] = *d.Accepted
	}
	if d.Reason != "" {
		v["reason"] = d.Reason
	}
	return v
}

// GET /webhooks/{name}/deliveries?cursor= → {items, cursor?} (50 a page).
func (s *Server) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request, ws *webSession) {
	h, _, ok := s.loadWebhook(w, r, ws, true)
	if !ok {
		return
	}
	ds, err := s.opt.Store.ListWebhookDeliveries(h.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		start = len(ds)
		for i, d := range ds {
			if d.ID == c {
				start = i + 1
				break
			}
		}
	}
	items := []map[string]any{}
	out := map[string]any{}
	for i := start; i < len(ds); i++ {
		if len(items) == 50 {
			out["cursor"] = ds[i-1].ID
			break
		}
		items = append(items, deliveryView(ds[i]))
	}
	out["items"] = items
	writeJSON(w, http.StatusOK, out)
}
