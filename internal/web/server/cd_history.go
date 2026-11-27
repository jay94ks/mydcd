// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/hex"
	"net/http"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// CD history, field values and candidate changes (UI-40 이력 표·변경점,
// UI-43 Git 값·지금 값; REQ-46 mock). Read-only views of what sfcd keeps;
// a value from a secret projection never comes back, only its selectors.

// GET /t/{t}/apps/{app}/cd/history?after= → {items:[{commit,
// candidateDigest, plannedAt, result, reason?, operation?, finishedAt?}],
// next, revision, asOf}, newest first. result: candidate / running /
// succeeded / failed / abandoned / blocked (reason = cd.blocked).
// checks?: {pre-sync?, post-sync?} — the webhook checks of that candidate.
func (s *Server) handleCDHistory(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.AppDeliveryHistory(ctx, r.PathValue("t"), r.PathValue("app"), r.URL.Query().Get("after"))
		if err != nil {
			return listPage{}, err
		}
		// Each row carries the webhook checks of its candidate (web data).
		kept, _ := s.opt.Store.CDCheckHistory(r.PathValue("t"), r.PathValue("app"))
		items := make([]cdHistoryItem, 0, len(p.Items))
		for _, row := range p.Items {
			it := cdHistoryItem{CDHistoryRow: row}
			if cs := kept[hex.EncodeToString(row.CandidateDigest[:])]; len(cs) > 0 {
				it.Checks = map[string]any{}
				for k, c := range cs {
					it.Checks[k] = checkView(c)
				}
			}
			items = append(items, it)
		}
		return s.page(items, p.Next, p.Revision), nil
	})
}

type cdHistoryItem struct {
	sfc.CDHistoryRow
	Checks map[string]any `json:",omitempty"`
}

// GET /t/{t}/apps/{app}/cd/values?path=services&path=web&path=image →
// {tenant, app, path, running?, candidate?, gitRunning?, gitCandidate?,
// current?, overridden, secrets?}: the field in Git at the running and
// candidate commits and the value in force. Same paths as cd/field.
func (s *Server) handleCDValues(w http.ResponseWriter, r *http.Request, ws *webSession) {
	path := r.URL.Query()["path"]
	if err := cdPath(path); err != nil {
		s.writeOpOutcome(w, ws, nil, 0, err)
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.CDFieldValues, error) {
		v, err := c.AppDeliveryValues(ctx, r.PathValue("t"), control.AppCDFieldRequest{App: r.PathValue("app"), Path: path})
		if v.Path == nil {
			v.Path = path
		}
		return v, err
	})
}

// GET /t/{t}/apps/{app}/cd/changes → {tenant, app, running, candidate,
// services:[{service, fields:[{path, before?, after?}]}], added, removed,
// count}: what the candidate changes against the running commit; count
// equals cd.changeCount.
func (s *Server) handleCDChanges(w http.ResponseWriter, r *http.Request, ws *webSession) {
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (sfc.CDChanges, error) {
		v, err := c.AppDeliveryChanges(ctx, r.PathValue("t"), r.PathValue("app"))
		if v.Services == nil {
			v.Services = []sfc.CDServiceChange{}
		}
		for i := range v.Services {
			if v.Services[i].Fields == nil {
				v.Services[i].Fields = []sfc.CDFieldChange{}
			}
		}
		if v.Added == nil {
			v.Added = []string{}
		}
		if v.Removed == nil {
			v.Removed = []string{}
		}
		return v, err
	})
}
