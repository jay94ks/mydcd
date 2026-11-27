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

func buildRestartTask(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, string) {
	parts := strings.Split(b.sig.Target, "/")
	if len(parts) != 4 || parts[0] != b.in.Tenant || parts[1] != b.in.App {
		return nil, "대상 컨테이너를 알 수 없음"
	}
	return b.call(routeTaskRestart, map[string]any{"service": parts[2], "instance": parts[3]}, parts[2]+"/"+parts[3],
		"t", b.in.Tenant, "app", b.in.App), ""
}

func buildPauseCD(_ *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, string) {
	var src sfc.AppSource
	err := b.ws.do(ctx, func(ctx context.Context, c sfc.Conn) error {
		var err error
		src, err = c.AppSource(ctx, b.in.Tenant, b.in.App, 0)
		return err
	})
	if err != nil || src.Kind != "cd" {
		return nil, "지금 버전이 자동 배포로 올라온 것이 아님"
	}
	return b.call(routeAppCDPause, map[string]any{}, fmt.Sprintf("v%d", src.Version), "t", b.in.Tenant, "app", b.in.App), ""
}

func buildCordonNode(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, string) {
	node := b.sig.Node
	if node == "" {
		return nil, "대상 서버를 알 수 없음"
	}
	return b.call(routeNodeCordon, map[string]any{"reason": "장애 대응 " + b.in.ID}, node, "node", node), ""
}

func buildPruneImages(_ *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, string) {
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
		return nil, "지울 이미지 목록을 읽지 못함"
	}
	if len(plan.Images) == 0 {
		return nil, "안 쓰는 이미지가 없음"
	}
	return b.call(routeNodeImagePrune, map[string]any{"plan": plan.Plan},
		fmt.Sprintf("%s: 안 쓰는 이미지 %d개, %d MB", node, len(plan.Images), plan.Bytes>>20), "node", node), ""
}

// buildReconnectTunnel: one tenant-scoped event per TUN network and node
// pair, Target = PairID ("a/b", sorted), Node = the server that saw it
// down. That server dials; the other end is its peer.
func buildReconnectTunnel(_ *Server, _ context.Context, b incidentBuild) (*store.IncidentAction, string) {
	sig := b.sig
	from, to, ok := strings.Cut(sig.Target, "/")
	if !ok || from == "" || to == "" || from == to || sig.Tenant == "" || sig.Network == "" {
		return nil, "끊긴 링크의 작업 공간·망을 알 수 없음"
	}
	switch sig.Node {
	case "", from:
	case to:
		from, to = to, from
	default:
		return nil, "끊김을 본 서버가 링크의 양 끝이 아님"
	}
	return b.call(routeTunnelReconnect, map[string]any{"from": from, "to": to}, sig.Tenant+"/"+sig.Network+": "+from+"–"+to,
		"t", sig.Tenant, "name", sig.Network), ""
}

func buildRollbackAction(s *Server, ctx context.Context, b incidentBuild) (*store.IncidentAction, string) {
	return s.buildRollback(ctx, b.ws, b.def, b.in, b.app, b.recent)
}
