// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
	"github.com/jay94ks/seafield/internal/web/sfc"
	"gopkg.in/yaml.v3"
)

// A cluster app's ingress routes (the web UI's own, sfcd's
// control.ClusterAppRouteRecord) are a cluster setting with no workspace,
// so they are not rows of /ingress. The screen reads and edits them here, as
// the same route file `sfcli app deploy -f` takes (system administrators;
// sfcd refuses everyone else).

type clusterAppRouteView struct {
	App       string                   `json:"app"`
	Revision  uint64                   `json:"revision"` // the expected of the next change; 0: never set
	Removed   bool                     `json:"removed"`
	Node      string                   `json:"node,omitempty"`
	Listeners []clusterAppListenerView `json:"listeners"`
	Routes    []clusterAppRouteRow     `json:"routes"`
	File      string                   `json:"file,omitempty"` // the route file, for editing
}

type clusterAppListenerView struct {
	Shared  string `json:"shared,omitempty"`
	Address string `json:"address,omitempty"`
	TLS     bool   `json:"tls"`
	HTTP3   bool   `json:"http3"`
}

type clusterAppRouteRow struct {
	ID      string `json:"id"`
	Host    string `json:"host"`
	Prefix  string `json:"prefix"`
	Gateway string `json:"gateway"` // local, external or both
}

// clusterAppRouteFile is the route file a record reads back as.
func clusterAppRouteFile(app string, d deployment.IngressDeclaration) string {
	type listener struct {
		Shared  string `yaml:"shared,omitempty"`
		Address string `yaml:"address,omitempty"`
		TLS     bool   `yaml:"tls,omitempty"`
		HTTP3   bool   `yaml:"http3,omitempty"`
	}
	type route struct {
		ID      string           `yaml:"id,omitempty"`
		Host    string           `yaml:"host"`
		Prefix  string           `yaml:"prefix,omitempty"`
		Gateway string           `yaml:"gateway,omitempty"`
		Balance *ingress.Balance `yaml:"balance,omitempty"`
	}
	type routes struct {
		Node      string                    `yaml:"node"`
		Runtime   deployment.IngressRuntime `yaml:"runtime"`
		Host      string                    `yaml:"host,omitempty"`
		Gateway   string                    `yaml:"gateway,omitempty"`
		Balance   *ingress.Balance          `yaml:"balance,omitempty"`
		Listeners []listener                `yaml:"listeners"`
		Routes    []route                   `yaml:"routes,omitempty"`
	}
	f := struct {
		Name string `yaml:"name"`
		Sfc  struct {
			Ingress routes `yaml:"ingress"`
		} `yaml:"x-sfc"`
	}{Name: deployment.ClusterAppPrefix + app}
	in := &f.Sfc.Ingress
	in.Node, in.Runtime, in.Host, in.Gateway, in.Balance = d.Node, d.Runtime, d.Host, d.Gateway, d.Balance
	for _, l := range d.Listeners {
		in.Listeners = append(in.Listeners, listener{l.Shared, l.Address, l.TLS, l.HTTP3})
	}
	for _, r := range d.Routes {
		in.Routes = append(in.Routes, route{r.ID, r.Host, r.Prefix, r.Gateway, r.Balance})
	}
	raw, _ := yaml.Marshal(f)
	return string(raw)
}

func clusterAppRouteOf(v control.ClusterAppRouteView) clusterAppRouteView {
	out := clusterAppRouteView{App: v.App, Revision: v.Revision, Removed: v.Removed, Listeners: []clusterAppListenerView{}, Routes: []clusterAppRouteRow{}}
	if v.Revision == 0 {
		return out
	}
	out.Node = v.Ingress.Node
	for _, l := range v.Ingress.Listeners {
		out.Listeners = append(out.Listeners, clusterAppListenerView{l.Shared, l.Address, l.TLS, l.HTTP3})
	}
	for _, r := range deployment.IngressRoutes(v.Ingress) {
		gateway := r.Gateway
		if gateway == "" {
			gateway = "local"
		}
		out.Routes = append(out.Routes, clusterAppRouteRow{r.ID, r.Host, r.Prefix, gateway})
	}
	out.File = clusterAppRouteFile(v.App, v.Ingress)
	return out
}

func clusterAppRoute(ctx context.Context, c sfc.Conn, app string) (control.ClusterAppRouteView, error) {
	p, err := ingressPaged(ctx, c, control.IngressQuery{Part: "cluster-app-routes"})
	if err != nil {
		return control.ClusterAppRouteView{}, err
	}
	for _, r := range p.ClusterAppRoutes {
		if r.App == app {
			return r, nil
		}
	}
	return control.ClusterAppRouteView{App: app}, nil
}

func clusterAppParam(r *http.Request) (string, bool) {
	return deployment.ClusterAppName(deployment.ClusterAppPrefix + r.PathValue("app"))
}

func (s *Server) handleGetClusterAppRoutes(w http.ResponseWriter, r *http.Request, ws *webSession) {
	app, ok := clusterAppParam(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not-found", "not a cluster app that takes routes")
		return
	}
	read(s, w, r, ws, func(ctx context.Context, c sfc.Conn) (clusterAppRouteView, error) {
		v, err := clusterAppRoute(ctx, c, app)
		return clusterAppRouteOf(v), err
	})
}

func (s *Server) handlePutClusterAppRoutes(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string  `json:"opId"`
		Expected *uint64 `json:"expected"`
		File     string  `json:"file"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	app, ok := clusterAppParam(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not-found", "not a cluster app that takes routes")
		return
	}
	if len(req.File) > 64<<10 {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "file: at most 64 KiB")
		return
	}
	named, d, err := deployment.ParseClusterAppRoutes([]byte(req.File))
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "file: "+strings.TrimSpace(err.Error()))
		return
	}
	if named != app {
		writeError(w, http.StatusUnprocessableEntity, "invalid", "file: name must be "+deployment.ClusterAppPrefix+app)
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		expected, err := clusterAppExpected(ctx, c, app, req.Expected)
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionPutClusterAppRoute, control.ClusterAppRouteChange{App: app, Ingress: d}, expected, deployment.ClusterAppPrefix + app, nil
	})
}

func (s *Server) handleDeleteClusterAppRoutes(w http.ResponseWriter, r *http.Request, ws *webSession) {
	var req struct {
		OpID     string  `json:"opId"`
		Expected *uint64 `json:"expected"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	app, ok := clusterAppParam(r)
	if !ok {
		writeError(w, http.StatusNotFound, "not-found", "not a cluster app that takes routes")
		return
	}
	s.sharedCreate(w, r, ws, req.OpID, req, func(ctx context.Context, c sfc.Conn, _ sfc.Session) (string, any, uint64, string, error) {
		expected, err := clusterAppExpected(ctx, c, app, req.Expected)
		if err != nil {
			return "", nil, 0, "", err
		}
		return sfc.ActionRemoveClusterAppRoute, control.ClusterAppRouteSelection{App: app}, expected, deployment.ClusterAppPrefix + app, nil
	})
}

// clusterAppExpected is the screen's expected revision, or the current one.
func clusterAppExpected(ctx context.Context, c sfc.Conn, app string, given *uint64) (uint64, error) {
	if given != nil {
		return *given, nil
	}
	v, err := clusterAppRoute(ctx, c, app)
	return v.Revision, err
}
