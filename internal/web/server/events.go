// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/eventlog"
	"github.com/jay94ks/seafield/internal/web/sfc"
)

// webEvent: one observation event as the screens, incident watch and
// webhooks use it (Unix seconds). It is made from sfcd's events row
// (eventOf); the daemon also makes its own samples (route metrics,
// listener limits, certificate ends) in the same shape. Target and Detail
// are display text built from the row's Target and Detail fields.
type webEvent struct {
	Cursor        string
	Time          int64
	Scope         string
	Tenant        string `json:",omitempty"`
	App           string `json:",omitempty"`
	Node          string `json:",omitempty"`
	Network       string `json:",omitempty"`
	PairID        string `json:",omitempty"`
	Kind          string
	Target        string
	Detail        string
	CD            *webCDEvent             `json:",omitempty"`
	Ingress       *webIngressEvent        `json:",omitempty"`
	ShellClosedBy *eventlog.ActorIdentity `json:",omitempty"`
}

// webCDEvent: the cd-* details (Detail.CandidateID, Commit, versions,
// Actor, Code, Reason).
type webCDEvent struct {
	CandidateID string
	Commit      string
	FromVersion string `json:",omitempty"`
	ToVersion   string `json:",omitempty"`
	Actor       string `json:",omitempty"`
	Code        string `json:",omitempty"`
	Reason      string `json:",omitempty"`
}

// webIngressEvent: the ingress-* details (Target.Gateway, RouteID, Host,
// Prefix; Detail.Value). Listener / Metric / Threshold are not from sfcd:
// the daemon's own samples set them.
type webIngressEvent struct {
	Gateway   string
	RouteID   string  `json:",omitempty"`
	Host      string  `json:",omitempty"`
	Prefix    string  `json:",omitempty"`
	Value     float64 `json:",omitempty"`
	Listener  string  `json:",omitempty"`
	Metric    string  `json:",omitempty"`
	Threshold float64 `json:",omitempty"`
}

func eventOf(it sfc.EventItem) webEvent {
	t, d := it.Target, it.Detail
	e := webEvent{Cursor: it.Cursor, Time: int64(it.At / 1000), Scope: it.Scope, Tenant: t.Tenant, App: t.App, Node: t.Node, Network: t.Network, PairID: t.PairID,
		Kind: it.Kind, Target: eventTarget(t), Detail: eventDetail(d), ShellClosedBy: d.ClosedBy}
	if e.Node == "" {
		e.Node = it.SourceNode
	}
	if strings.HasPrefix(it.Kind, "cd-") {
		e.CD = &webCDEvent{CandidateID: d.CandidateID, Commit: d.Commit, Actor: d.Actor, Code: d.Code, Reason: d.Reason}
		if d.FromVersion != 0 {
			e.CD.FromVersion = strconv.FormatUint(d.FromVersion, 10)
		}
		if d.ToVersion != 0 {
			e.CD.ToVersion = strconv.FormatUint(d.ToVersion, 10)
		}
	}
	if strings.HasPrefix(it.Kind, "ingress-") || t.Gateway != "" {
		e.Ingress = &webIngressEvent{Gateway: t.Gateway, RouteID: t.RouteID, Host: t.Host, Prefix: t.Prefix, Value: float64(d.Value)}
	}
	return e
}

// eventTarget: what the event is about, as one line.
func eventTarget(t eventlog.Target) string {
	switch {
	case t.PairID != "":
		return t.PairID
	case t.Gateway != "":
		return strings.Join(nonEmpty(t.Node, t.Gateway, t.Host+t.Prefix), "/")
	case t.Tenant != "":
		return strings.Join(nonEmpty(t.Tenant, t.App, t.Service, t.Task), "/")
	case t.FilesystemID != "":
		return t.Node + ":" + t.FilesystemID
	}
	return t.Node
}

// eventDetail: the event's detail fields as one line.
func eventDetail(d eventlog.Detail) string {
	parts := nonEmpty(d.Reason, d.OperatorReason, d.Resource, d.State, d.Code)
	if d.ExitCode != nil {
		parts = append(parts, fmt.Sprintf("exit %d", *d.ExitCode))
	}
	return strings.Join(parts, " ")
}

func nonEmpty(v ...string) []string {
	out := []string{}
	for _, s := range v {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// GET /events?tenant=&app=&node=&kind=&since=&limit= → events rows.
// since is the previous next (or last row's cursor); limit at most 100.
// next is set while more rows wait.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, ws *webSession) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	query := sfc.EventQuery{Tenant: q.Get("tenant"), App: q.Get("app"), Node: q.Get("node"), Kind: q.Get("kind"), After: q.Get("since"), Limit: min(max(limit, 0), 100)}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (listPage, error) {
		p, err := c.Events(ctx, query)
		if err != nil {
			return listPage{}, err
		}
		rows := make([]webEvent, 0, len(p.Items))
		for _, it := range p.Items {
			rows = append(rows, eventOf(it))
		}
		next := ""
		if p.More {
			next = p.Cursor
		}
		return s.page(rows, next, 0), nil
	})
}
