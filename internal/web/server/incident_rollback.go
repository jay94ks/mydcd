// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// Rolling an app back for an incident (W2.3): "roll back right after CD"
// (low, may run on its own, bundled with pausing CD) when every condition
// of web-ai-plan "자동 배포 직후 되돌리기" holds, else "back to the previous
// version" (medium, always asks). Both send the previous version's
// app.yaml through the screen's deploy route.

// appVersionPair is the running version and the one before it.
type appVersionPair struct {
	cur, prev sfc.AppSource
}

// appVersions reads the running source and the newest earlier version that
// did not fail.
func appVersions(ctx context.Context, c sfc.Conn, tenant, app string) (*appVersionPair, error) {
	cur, err := c.AppSource(ctx, tenant, app, 0)
	if err != nil {
		return nil, err
	}
	var best uint64
	after := ""
	for i := 0; i < incidentMaxPages; i++ {
		p, err := c.AppRevisions(ctx, tenant, app, after)
		if err != nil {
			return nil, err
		}
		for _, v := range p.Items {
			if v.Version < cur.Version && v.Version > best && v.Status != "failed" {
				best = v.Version
			}
		}
		if p.Next == "" {
			break
		}
		after = p.Next
	}
	if best == 0 {
		return &appVersionPair{cur: cur}, nil
	}
	prev, err := c.AppSource(ctx, tenant, app, best)
	if err != nil {
		return nil, err
	}
	return &appVersionPair{cur: cur, prev: prev}, nil
}

// Keys of a service whose change counts as light for rolling back on its
// own: image, environment, replicas, resources, health checks.
var lightServiceKeys = map[string]bool{"image": true, "environment": true, "env": true, "replicas": true, "deploy": true,
	"resources": true, "healthcheck": true, "mem_limit": true, "cpus": true}

// yamlDiff lists the paths ("services.web.image") where two app.yaml
// documents differ.
func yamlDiff(a, b []byte) ([]string, error) {
	var x, y any
	if err := yaml.Unmarshal(a, &x); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &y); err != nil {
		return nil, err
	}
	var out []string
	var walk func(path string, p, q any)
	walk = func(path string, p, q any) {
		pm, ok1 := p.(map[string]any)
		qm, ok2 := q.(map[string]any)
		if !ok1 || !ok2 {
			if !reflect.DeepEqual(p, q) {
				out = append(out, path)
			}
			return
		}
		keys := map[string]bool{}
		for k := range pm {
			keys[k] = true
		}
		for k := range qm {
			keys[k] = true
		}
		for k := range keys {
			sub := k
			if path != "" {
				sub = path + "." + k
			}
			walk(sub, pm[k], qm[k])
		}
	}
	walk("", x, y)
	sort.Strings(out)
	return out, nil
}

// heavyChange says why a diff is not light ("" when it is): data stores,
// networks, domains, secret references, health scripts, added or removed
// services. secret: the path is an environment change that touches a
// secret reference.
func heavyChange(paths []string, a, b []byte) (path string, secret bool) {
	for _, p := range paths {
		parts := strings.Split(p, ".")
		if len(parts) < 3 || parts[0] != "services" {
			return p, false
		}
		if !lightServiceKeys[parts[2]] {
			return p, false
		}
	}
	// Environment changes that touch secrets.
	low := func(d []byte) bool { return bytes.Contains(bytes.ToLower(d), []byte("secret")) }
	for _, p := range paths {
		if strings.Contains(p, ".environment") || strings.Contains(p, ".env") {
			if low(a) || low(b) {
				return p, true
			}
		}
	}
	return "", false
}

// versionAuto is why a version is kept from rolling back on its own
// because of what it changed (data stores, networks, secrets…), "" if none.
func versionAuto(cur, prev []byte) string {
	if len(prev) == 0 {
		return ""
	}
	paths, err := yamlDiff(prev, cur)
	if err != nil {
		return ""
	}
	for _, p := range paths {
		for _, k := range []string{"volumes", "networks", "secrets", "domains", "ingress", "lifecycle"} {
			if strings.Contains(p, k) {
				return p
			}
		}
	}
	return ""
}

// rollbackAction builds the deploy of the previous version, with the CD
// pause when cdAuto.
func rollbackAction(def *incidentActionDef, in *store.Incident, pair *appVersionPair, cdAuto bool) *store.IncidentAction {
	sum := sha256.Sum256(pair.prev.Document)
	body, _ := json.Marshal(map[string]any{"yaml": string(pair.prev.Document), "digest": hex.EncodeToString(sum[:])})
	method, path := routePath(routeAppsDeploy, "t", in.Tenant)
	out := &store.IncidentAction{ID: def.ID, Label: def.Label, Method: method, Path: path, Body: body,
		Note: fmt.Sprintf("v%d → v%d", pair.cur.Version, pair.prev.Version)}
	if cdAuto {
		note := ph("incident-note.rollback-pause", "versions", out.Note)
		out.NoteText = &note
		pause, _ := json.Marshal(map[string]any{})
		method, path := routePath(routeAppCDPause, "t", in.Tenant, "app", in.App)
		out.Also = &store.IncidentAction{ID: "pause-cd", Label: "자동 배포 일시 정지", Method: method, Path: path, Body: pause}
	}
	return out
}

// buildRollback is the cd-rollback / rollback-previous candidate.
func (s *Server) buildRollback(ctx context.Context, ws *webSession, def *incidentActionDef, in *store.Incident, app *store.AppIncidentPolicy, recent []store.IncidentSignal) (*store.IncidentAction, store.Phrase) {
	var pair *appVersionPair
	err := ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		pair, err = appVersions(ctx, c, in.Tenant, in.App)
		return err
	})
	if err != nil {
		return nil, ph("incident-skip.versions-unread")
	}
	if len(pair.prev.Document) == 0 {
		return nil, ph("incident-skip.no-previous")
	}
	if def.ID == "rollback-previous" {
		return rollbackAction(def, in, pair, false), store.Phrase{}
	}
	// cd-rollback: every condition, checked by code.
	now := s.now()
	deployed := time.Unix(pair.cur.AcceptedAt, 0)
	switch {
	case app == nil || !app.CDRollback.Enabled:
		return nil, ph("incident-skip.policy-off")
	case app.CDRollback.AlwaysApprove:
		return nil, ph("incident-skip.always-approve")
	case pair.cur.Kind != "cd":
		return nil, ph("incident-skip.not-cd")
	case now.Sub(deployed) > time.Duration(app.CDRollback.WindowMinutes)*time.Minute:
		return nil, ph("incident-skip.window-passed")
	case app.Migrations[pair.cur.Version] || app.Migrations[pair.prev.Version]:
		return nil, ph("incident-skip.migration")
	}
	paths, err := yamlDiff(pair.prev.Document, pair.cur.Document)
	if err != nil {
		return nil, ph("incident-skip.yaml-diff")
	}
	if path, secret := heavyChange(paths, pair.prev.Document, pair.cur.Document); path != "" {
		if secret {
			return nil, ph("incident-skip.heavy-change.secret", "path", path)
		}
		return nil, ph("incident-skip.heavy-change", "path", path)
	}
	if !s.watchedSince(in.Tenant, deployed.Add(-30*time.Minute)) {
		return nil, ph("incident-skip.unwatched")
	}
	for _, x := range recent {
		if incidentKey(incidentRules[x.Kind], x) == in.Key && x.At.Before(deployed) && x.At.After(deployed.Add(-30*time.Minute)) {
			return nil, ph("incident-skip.before-deploy")
		}
	}
	if s.recentCDRollback(in, now) {
		return nil, ph("incident-skip.rolled-back")
	}
	return rollbackAction(def, in, pair, true), store.Phrase{}
}

// watchedSince: the watcher has read the tenant's events (or all of them)
// without a break since t, so recent holds every app signal after t.
func (s *Server) watchedSince(tenant string, t time.Time) bool {
	st, err := s.opt.Store.GetIncidentWatcher()
	if err != nil {
		return false
	}
	since, ok := st.Since[""]
	if !ok {
		since, ok = st.Since[tenant]
	}
	return ok && !since.After(t)
}

// recentCDRollback: this app rolled back on its own in the last 24 hours.
func (s *Server) recentCDRollback(in *store.Incident, now time.Time) bool {
	all, err := s.opt.Store.ListIncidents()
	if err != nil {
		return true
	}
	for _, x := range all {
		if x.Tenant == in.Tenant && x.App == in.App && x.Mitigation == "cd-rollback" && x.Op != "" && now.Sub(x.MitigatedAt) < 24*time.Hour {
			return true
		}
	}
	return false
}

// alsoOpID is the opId of the bundled second step, derived from the
// first so a retry sends the same pair.
func alsoOpID(opID string) string {
	h := sha256.Sum256([]byte("also\x00" + opID))
	b := h[:16]
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:]
}
