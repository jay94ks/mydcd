// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// GET /api/v1/dashboard?tenant=: server cards scoped to the caller's
// permissions, plus the first apps page of the chosen workspace.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request, ws *webSession) {
	tenant := r.URL.Query().Get("tenant")
	type dashboard struct {
		Nodes    []summaryView `json:"nodes"`
		Apps     []sfc.AppView `json:"apps"`
		AppsNext string        `json:"appsNext,omitempty"`
		AsOf     string        `json:"asOf"`
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (dashboard, error) {
		var d dashboard
		var err error
		if d.Nodes, err = nodeSummaries(ctx, c, tenant); err != nil {
			return d, err
		}
		if tenant != "" {
			p, err := c.Apps(ctx, tenant, "")
			if err != nil {
				return d, err
			}
			d.Apps, d.AppsNext = p.Items, p.Next
		}
		d.AsOf = rfc3339(s.now())
		return d, nil
	})
}

// GET /api/v1/nodes: `members` with the voting configuration.
// memberRow: a members row plus its server's newest drain (system admin).
// Drain comes first so it wins over the member's own field.
type memberRow struct {
	Drain *memberDrain `json:"drain,omitempty"`
	memberView
}

type memberDrain struct {
	Operation string `json:"operation"`
	State     string `json:"state"`
}

// withNodeDrains asks sfcd for each server's in-progress (else newest)
// drain: node-drain-status without Operation, one call a server on
// the page. Missing = no drain; any other answer leaves the row without one.
func withNodeDrains(ctx context.Context, c sfc.Conn, ms []memberView) []memberRow {
	out := make([]memberRow, 0, len(ms))
	for _, m := range ms {
		row := memberRow{memberView: m}
		if m.Phase != sfc.NodePhaseRemoved {
			if st, err := c.NodeDrainStatus(ctx, control.NodeDrainQuery{Node: m.ID}); err == nil && st.Operation != "" {
				row.Drain = &memberDrain{Operation: st.Operation, State: st.State}
			}
		}
		out = append(out, row)
	}
	return out
}

func (s *Server) handleMembers(w http.ResponseWriter, r *http.Request, ws *webSession) {
	type membersView struct {
		listPage
		Voters             int    `json:"voters"`
		Quorum             int    `json:"quorum"`
		RuntimeRevision    uint64 `json:"runtimeRevision"`
		OperationEpoch     uint64 `json:"operationEpoch"`
		ConfigurationIndex uint64 `json:"configurationIndex"`
		// the ledger (rotate-ledger): ModuleEpoch and the StorageKey root
		// revision from whoami
		LedgerEpoch    uint64 `json:"ledgerEpoch"`
		LedgerRevision uint64 `json:"ledgerRevision"`
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (membersView, error) {
		p, err := c.Members(ctx, r.URL.Query().Get("after"))
		if err != nil {
			return membersView{}, err
		}
		who, err := c.Whoami(ctx)
		if err != nil {
			return membersView{}, err
		}
		rows := memberViews(p)
		var items any = rows
		if who.User.SystemAdmin {
			items = withNodeDrains(ctx, c, rows)
		}
		return membersView{listPage: s.page(items, p.Next, p.RootRevision), Voters: p.NodeVoters, Quorum: p.NodeQuorum,
			RuntimeRevision: p.NodeRuntimeRevision, OperationEpoch: p.NodeOperationEpoch, ConfigurationIndex: p.NodeConfigurationIndex,
			LedgerEpoch: max(who.LedgerEpoch, 1), LedgerRevision: who.LedgerRootRevision}, nil
	})
}

type observeReq struct {
	Service  string `json:"service"`
	Instance string `json:"instance,omitempty"`
	Kind     string `json:"kind"` // logs / top / stats
	Tail     int    `json:"tail,omitempty"`
	Stdout   *bool  `json:"stdout,omitempty"`
	Stderr   *bool  `json:"stderr,omitempty"`
	Since    int64  `json:"since,omitempty"` // Unix seconds
	Until    int64  `json:"until,omitempty"`
}

// POST /api/v1/t/{t}/apps/{app}/observe: finite container logs/top/stats.
func (s *Server) handleObserve(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req observeReq
	if !readJSON(w, r, &req) {
		return
	}
	switch req.Kind {
	case "logs", "top", "stats":
	default:
		writeError(w, http.StatusBadRequest, "bad-request", "kind must be logs, top or stats")
		return
	}
	if req.Tail < 0 || req.Tail > 10000 {
		writeError(w, http.StatusBadRequest, "bad-request", "tail must be 0..10000")
		return
	}
	if req.Since < 0 || req.Until < 0 || req.Until != 0 && req.Until < req.Since {
		writeError(w, http.StatusBadRequest, "bad-request", "since and until: Unix seconds, until not before since")
		return
	}
	sel := sfc.ContainerSelection{App: r.PathValue("app"), Service: req.Service, Instance: req.Instance}
	if name := r.PathValue("name"); name != "" {
		sel = sfc.ContainerSelection{Standalone: name}
	}
	q := sfc.ContainerQuery{Selection: sel,
		Kind: req.Kind, Tail: req.Tail, Stdout: req.Stdout == nil || *req.Stdout, Stderr: req.Stderr == nil || *req.Stderr, Since: req.Since, Until: req.Until}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.ContainerResult, error) {
		return c.ContainerObserve(ctx, r.PathValue("t"), q)
	})
}

type planReq struct {
	YAML       string `json:"yaml"`
	Project    string `json:"project,omitempty"`
	Deployment string `json:"deployment,omitempty"`
	Node       string `json:"node,omitempty"`
	Diff       bool   `json:"diff"`
}

// POST /api/v1/t/{t}/apps/plan: app.yaml check and change preview through
// the same plan core as `sfcli compose plan`. Nothing is changed.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req planReq
	if !readJSON(w, r, &req) {
		return
	}
	if req.YAML == "" || len(req.YAML) > 4<<20 {
		writeError(w, http.StatusBadRequest, "bad-request", "yaml is required and at most 4 MiB")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.AppPlan, error) {
		return c.AppPlan(ctx, sfc.AppPlanRequest{Tenant: r.PathValue("t"), Document: []byte(req.YAML), Project: req.Project, Deployment: req.Deployment, Node: req.Node, Diff: req.Diff})
	})
}

type appSourceView struct {
	Tenant     string `json:"tenant"`
	App        string `json:"app"`
	Version    uint64 `json:"version"`
	YAML       string `json:"yaml"`
	Digest     string `json:"digest"`
	Submitter  string `json:"submitter"`
	Operation  string `json:"operation"`
	AcceptedAt string `json:"acceptedAt,omitempty"`
}

func viewSource(src sfc.AppSource) appSourceView {
	v := appSourceView{Tenant: src.Tenant, App: src.App, Version: src.Version, YAML: string(src.Document), Digest: hex.EncodeToString(src.Digest[:]), Submitter: src.Submitter, Operation: src.Operation}
	if src.AcceptedAt > 0 {
		v.AcceptedAt = rfc3339(time.Unix(src.AcceptedAt, 0))
	}
	return v
}

// downReq is the down-app change plus archive details.
type downReq struct {
	opRequest
	Volumes []string `json:"volumes,omitempty"` // data stores that stay behind, shown on the archive row
}

// POST /api/v1/t/{t}/apps/{app}/down: save the running app.yaml to the
// archive first; only after that is stored does down-app go out. If the
// source cannot be read or stored the app is not taken down.
func (s *Server) handleDown(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req downReq
	if !readJSON(w, r, &req) {
		return
	}
	tenant, app := r.PathValue("t"), r.PathValue("app")
	req.Action = sfc.ActionDownApp
	req.Tenant, req.Target = tenant, app
	// The archived app and the app taken down must be the same one.
	var down control.AppDown
	dec := json.NewDecoder(bytes.NewReader(req.Payload))
	dec.DisallowUnknownFields()
	if len(req.Payload) == 0 || dec.Decode(&down) != nil || down.Tenant != tenant || down.App != app {
		writeError(w, http.StatusBadRequest, "target-mismatch", "payload must be a down-app for this workspace and app")
		return
	}
	// A repeated opId returns the stored op without archiving again.
	if old, err := s.opt.Store.GetOp(ws.user.ID, req.OpID); err == nil {
		if old.Digest != req.digest() {
			writeError(w, http.StatusConflict, "op-conflict", "this opId was already used for a different change")
			return
		}
		writeJSON(w, opStatus(old), map[string]any{"op": viewOp(old)})
		return
	}
	if !uuidRE.MatchString(req.OpID) {
		writeError(w, http.StatusBadRequest, "bad-request", "opId must be a lowercase UUID v4")
		return
	}
	ctx, cancel := s.callCtx(r)
	var src sfc.AppSource
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		src, err = c.AppSource(ctx, tenant, app, 0)
		return err
	})
	cancel()
	if err != nil {
		s.writeBackendError(w, ws, err)
		return
	}
	row := &store.ArchivedApp{Tenant: tenant, App: app, Source: src.Document, Digest: hex.EncodeToString(src.Digest[:]), Version: src.Version,
		Volumes: req.Volumes, DownBy: ws.user.Username, DownAt: s.now(), DownOp: req.OpID}
	if _, err := s.opt.Store.PutArchived(row); err != nil {
		s.log.Error("archive app before down", "tenant", tenant, "app", app, "err", err)
		writeError(w, http.StatusInternalServerError, "archive-failed", "could not save app.yaml; the app was not taken down")
		return
	}
	o, status, err := s.submitOp(r, ws, &req.opRequest)
	if err != nil || o.State == store.OpRejected || o.State == store.OpFailed {
		// Not sent, refused or not applied: the app is still running and
		// the archive row would only confuse. An unknown outcome keeps the
		// row; settling the op later removes it if the down failed.
		_ = s.opt.Store.DeleteArchived(row.Key)
	}
	s.writeOpOutcome(w, ws, o, status, err)
}

// tenantRole returns the caller's role in tenant ("" when no access), asking
// sfcd each time: web rows never grant access on their own.
func (s *Server) tenantRole(r *http.Request, ws *webSession, tenant string) (sfc.Role, error) {
	ctx, cancel := s.callCtx(r)
	defer cancel()
	var tenants []sfc.TenantView
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		tenants, err = c.Tenants(ctx)
		return err
	})
	if err != nil {
		return "", err
	}
	for _, t := range tenants {
		if t.ID == tenant {
			return t.Role, nil
		}
	}
	return "", nil
}

func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, ws *webSession, tenant string, manager bool) bool {
	role, err := s.tenantRole(r, ws, tenant)
	if err != nil {
		s.writeBackendError(w, ws, err)
		return false
	}
	if role == "" || (manager && role != sfc.RoleManager) {
		// Same answer for "no such workspace" and "no permission".
		writeError(w, http.StatusForbidden, "denied", "no access to this workspace")
		return false
	}
	return true
}

type archivedView struct {
	Key        string   `json:"key"`
	Tenant     string   `json:"tenant"`
	App        string   `json:"app"`
	Deployment string   `json:"deployment,omitempty"`
	Digest     string   `json:"digest"`
	Version    uint64   `json:"version"`
	Volumes    []string `json:"volumes"`
	DownBy     string   `json:"downBy"`
	DownAt     string   `json:"downAt"`
	DownOp     string   `json:"downOp,omitempty"`
	YAML       string   `json:"yaml,omitempty"`
}

func viewArchived(a *store.ArchivedApp, withSource bool) archivedView {
	v := archivedView{Key: archiveKeyOut(a.Key), Tenant: a.Tenant, App: a.App, Deployment: a.Deployment, Digest: a.Digest, Version: a.Version,
		Volumes: a.Volumes, DownBy: a.DownBy, DownAt: rfc3339(a.DownAt), DownOp: a.DownOp}
	if v.Volumes == nil {
		v.Volumes = []string{}
	}
	if withSource {
		v.YAML = string(a.Source)
	}
	return v
}

// Archive keys contain NUL separators; the URL form is hex.
func archiveKeyOut(k string) string { return hex.EncodeToString([]byte(k)) }

func archiveKeyIn(s string) (string, bool) {
	b, err := hex.DecodeString(s)
	return string(b), err == nil
}

func (s *Server) handleListArchived(w http.ResponseWriter, r *http.Request, ws *webSession) {
	t := r.PathValue("t")
	if !s.requireRole(w, r, ws, t, false) {
		return
	}
	rows, err := s.opt.Store.ListArchived(t)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	items := make([]archivedView, 0, len(rows))
	for _, a := range rows {
		items = append(items, viewArchived(a, false))
	}
	writeJSON(w, http.StatusOK, s.page(items, "", 0))
}

func (s *Server) loadArchived(w http.ResponseWriter, r *http.Request, ws *webSession, manager bool) *store.ArchivedApp {
	t := r.PathValue("t")
	if !s.requireRole(w, r, ws, t, manager) {
		return nil
	}
	k, ok := archiveKeyIn(r.PathValue("key"))
	var a *store.ArchivedApp
	var err error
	if ok {
		a, err = s.opt.Store.GetArchived(k)
	}
	if !ok || errors.Is(err, store.ErrNotFound) || (a != nil && a.Tenant != t) {
		writeError(w, http.StatusNotFound, "not-found", "no such archived app")
		return nil
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return nil
	}
	return a
}

func (s *Server) handleGetArchived(w http.ResponseWriter, r *http.Request, ws *webSession) {
	if a := s.loadArchived(w, r, ws, false); a != nil {
		writeJSON(w, http.StatusOK, viewArchived(a, true))
	}
}

// POST /api/v1/t/{t}/archived/{key}/purge {"confirm":"<app name>"}: the
// explicit "완전 삭제". Deleting the left-behind data stores is a separate
// cluster operation the UI submits through /ops.
func (s *Server) handlePurgeArchived(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	a := s.loadArchived(w, r, ws, true)
	if a == nil {
		return
	}
	if req.Confirm != a.App {
		writeError(w, http.StatusBadRequest, "confirm-mismatch", "type the app name to confirm")
		return
	}
	if err := s.opt.Store.DeleteArchived(a.Key); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.log.Info("purge archived app", "user", ws.user.Username, "tenant", a.Tenant, "app", a.App)
	s.audit(ws, a.Tenant, "archived", "purge", a.App, map[string]any{"app": a.App, "deployment": a.Deployment, "digest": a.Digest, "downAt": a.DownAt}, nil)
	w.WriteHeader(http.StatusNoContent)
}

func layoutKey(r *http.Request) (string, string, string) {
	return r.PathValue("t"), r.PathValue("app"), r.URL.Query().Get("deployment")
}

func (s *Server) handleGetLayout(w http.ResponseWriter, r *http.Request, ws *webSession) {
	t, app, dep := layoutKey(r)
	if !s.requireRole(w, r, ws, t, false) {
		return
	}
	raw, err := s.opt.Store.GetLayout(t, app, dep)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"layout": nil})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"layout": json.RawMessage(raw)})
}

func (s *Server) handlePutLayout(w http.ResponseWriter, r *http.Request, ws *webSession) {
	t, app, dep := layoutKey(r)
	var req struct {
		Layout json.RawMessage `json:"layout"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Layout) > 1<<20 {
		writeError(w, http.StatusRequestEntityTooLarge, "too-large", "layout is limited to 1 MiB")
		return
	}
	if !s.requireRole(w, r, ws, t, true) {
		return
	}
	if err := s.opt.Store.PutLayout(t, app, dep, req.Layout); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetPrefs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	raw, err := s.opt.Store.GetPrefs(ws.user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if raw == nil {
		raw = []byte("{}")
	}
	writeJSON(w, http.StatusOK, map[string]any{"prefs": json.RawMessage(raw)})
}

// PUT /prefs {prefs}: the account's screen settings, one JSON object the
// frontend owns. The daemon reads only language ("" = not set, "ko", "en":
// the account's default language, devel/design/web-i18n.md).
func (s *Server) handlePutPrefs(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		Prefs json.RawMessage `json:"prefs"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Prefs) > 64<<10 || len(req.Prefs) == 0 || req.Prefs[0] != '{' {
		writeError(w, http.StatusBadRequest, "bad-request", "prefs must be a JSON object up to 64 KiB")
		return
	}
	var known struct {
		Language *string `json:"language"`
	}
	if json.Unmarshal(req.Prefs, &known) != nil || known.Language != nil && *known.Language != "" && !knownLang(*known.Language) {
		writeError(w, http.StatusBadRequest, "bad-request", `prefs.language: "", "ko" or "en"`)
		return
	}
	if err := s.opt.Store.PutPrefs(ws.user.ID, req.Prefs); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
