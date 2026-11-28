// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jay94ks/seafield/internal/web/sfc"
	"github.com/jay94ks/seafield/internal/web/store"
)

// incidentBuild is what an incident action's Build sees.
type incidentBuild struct {
	ws     *webSession
	def    *incidentActionDef
	in     *store.Incident
	sig    store.IncidentSignal
	app    *store.AppIncidentPolicy
	recent []store.IncidentSignal
}

// call is the action as one screen API call.
func (b incidentBuild) call(route string, body map[string]any, note string, kv ...string) *store.IncidentAction {
	method, path := routePath(route, kv...)
	raw, _ := json.Marshal(body)
	return &store.IncidentAction{ID: b.def.ID, Label: b.def.Label, Method: method, Path: path, Body: raw, Note: note}
}

func buildRestartTask(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	parts := strings.Split(b.sig.Target, "/")
	if len(parts) != 4 || parts[0] != b.in.Tenant || parts[1] != b.in.App {
		return nil, ph("incident-skip.no-task")
	}
	return b.call(routeTaskRestart, map[string]any{"service": parts[2], "instance": parts[3]}, parts[2]+"/"+parts[3],
		"t", b.in.Tenant, "app", b.in.App), store.Phrase{}
}

func buildPauseCD(_ *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	var src sfc.AppSource
	err := b.ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		src, err = c.AppSource(ctx, b.in.Tenant, b.in.App, 0)
		return err
	})
	if err != nil || src.Kind != "cd" {
		return nil, ph("incident-skip.not-cd")
	}
	return b.call(routeAppCDPause, map[string]any{}, fmt.Sprintf("v%d", src.Version), "t", b.in.Tenant, "app", b.in.App), store.Phrase{}
}

func buildCordonNode(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	node := b.sig.Node
	if node == "" {
		return nil, ph("incident-skip.no-node")
	}
	return b.call(routeNodeCordon, map[string]any{"reason": "장애 대응 " + b.in.ID}, node, "node", node), store.Phrase{}
}

func buildPruneImages(_ *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	node := b.sig.Node
	if node == "" {
		node, _, _ = strings.Cut(b.sig.Target, ":")
	}
	var plan imagePruneView
	err := b.ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		plan, _, err = imagePruneSelection(ctx, c, node)
		return err
	})
	if err != nil {
		return nil, ph("incident-skip.images-unread")
	}
	if len(plan.Images) == 0 {
		return nil, ph("incident-skip.no-unused-images")
	}
	act := b.call(routeNodeImagePrune, map[string]any{"plan": plan.Plan}, node, "node", node)
	note := ph("incident-note.prune", "node", node, "count", fmt.Sprint(len(plan.Images)), "mb", fmt.Sprint(plan.Bytes>>20))
	act.NoteText = &note
	return act, store.Phrase{}
}

// buildReconnectTunnel: one tenant-scoped event per TUN network and node
// pair, Target = PairID ("a/b", sorted), Node = the server that saw it
// down. That server dials; the other end is its peer.
func buildReconnectTunnel(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	sig := b.sig
	from, to, ok := strings.Cut(sig.Target, "/")
	if !ok || from == "" || to == "" || from == to || sig.Tenant == "" || sig.Network == "" {
		return nil, ph("incident-skip.link-unknown")
	}
	switch sig.Node {
	case "", from:
	case to:
		from, to = to, from
	default:
		return nil, ph("incident-skip.link-not-ends")
	}
	return b.call(routeTunnelReconnect, map[string]any{"from": from, "to": to}, sig.Tenant+"/"+sig.Network+": "+from+"–"+to,
		"t", sig.Tenant, "name", sig.Network), store.Phrase{}
}

func buildRollbackAction(s *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, store.Phrase) {
	return s.buildRollback(ctx, b.ws, b.def, b.in, b.app, b.recent)
}
