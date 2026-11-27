// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/seafield/internal/web/sfc"
)

// Moving a service to another server. A service without a node-pinned
// volume moves by a new app version whose x-sfc.node changed (plan →
// upload → begin-app). A service with its app's node-fixed volume moves
// with the volume move (app-plan-stream with Move → begin-volume-move, the
// new document is the move's artifact). sfcd judges whether the move can
// happen: the check is that version's plan, nothing the web decides itself.

// relocationView: GET /t/{t}/apps/{app}/relocation-check.
type relocationView struct {
	Tenant  string            `json:"tenant"`
	App     string            `json:"app"`
	Service string            `json:"service"`
	From    string            `json:"from"`
	To      string            `json:"to"`
	OK      bool              `json:"ok"`
	Checks  []relocationItem  `json:"checks"`
	Volumes []relocationMount `json:"volumes"`
	Steps   []string          `json:"steps"`
}

// relocationItem: one check. "plan" is sfcd's plan of the moved version;
// Detail is its input error code and text when it refused.
type relocationItem struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

const (
	relocateNone       = "none"
	relocateMove       = "move"
	relocateNotMovable = "not-movable"
)

// relocationMount: a named volume the service mounts. Step "none" (not
// node-pinned, or already on the target), "move" (the app's own volume:
// it moves with the service), "not-movable" (pinned there and not the
// app's own; sfcd moves only an app's own data stores).
type relocationMount struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Node string `json:"node"`
	Step string `json:"step"`
}

// relocatedService reads one service of an app document: its x-sfc.node
// (or x-sfc.nodes) and the named volumes it mounts.
func relocatedService(doc []byte, service string) (node string, replicated bool, mounts []string, err error) {
	var d struct {
		Services map[string]struct {
			Volumes []yaml.Node `yaml:"volumes"`
			XSfc    struct {
				Node  string   `yaml:"node"`
				Nodes []string `yaml:"nodes"`
			} `yaml:"x-sfc"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return "", false, nil, err
	}
	s, ok := d.Services[service]
	if !ok {
		return "", false, nil, errNoService
	}
	for _, v := range s.Volumes {
		src := ""
		switch v.Kind {
		case yaml.ScalarNode:
			src, _, _ = strings.Cut(v.Value, ":")
		case yaml.MappingNode:
			var long struct {
				Type, Source string
			}
			if v.Decode(&long) == nil && (long.Type == "" || long.Type == "volume") {
				src = long.Source
			}
		}
		// A named volume, not a host path (compose: no leading / . ~).
		if named := src != "" && !strings.ContainsAny(src[:1], "/.~") && !strings.Contains(src, "/"); named && !slices.Contains(mounts, src) {
			mounts = append(mounts, src)
		}
	}
	return s.XSfc.Node, len(s.XSfc.Nodes) > 1, mounts, nil
}

var errNoService = errors.New("no such service")

// setServiceNode sets services.{name}.x-sfc.node in an app document.
func setServiceNode(doc []byte, name, node string) ([]byte, error) {
	return setMappingPath(doc, []string{"services", name, "x-sfc"}, "node", node)
}

// relocationCheck plans the running version with the service on node (and
// its own fixed volumes moved along) and reports sfcd's answer.
func relocationCheck(ctx context.Context, c sfc.Conn, tenant, app, service, node string) (relocationView, error) {
	out := relocationView{Tenant: tenant, App: app, Service: service, To: node, Checks: []relocationItem{}, Volumes: []relocationMount{}, Steps: []string{"app"}}
	src, err := c.AppSource(ctx, tenant, app, 0)
	if err != nil {
		return out, err
	}
	from, replicated, mounts, err := relocatedService(src.Document, service)
	switch {
	case errors.Is(err, errNoService):
		return out, &httpErr{http.StatusNotFound, "not-found", "no such service in the running version"}
	case err != nil:
		return out, &httpErr{http.StatusUnprocessableEntity, "invalid", "the running app document cannot be read: " + err.Error()}
	case replicated:
		return out, invalid("replicated service: change x-sfc.nodes")
	}
	out.From = from
	doc, err := setServiceNode(src.Document, service, node)
	if err != nil {
		return out, &httpErr{http.StatusUnprocessableEntity, "invalid", "the running app document cannot be edited: " + err.Error()}
	}
	var moving []string
	for _, name := range mounts {
		v, err := findVolume(ctx, c, tenant, name, app)
		if err != nil {
			var he *httpErr
			if errors.As(err, &he) && he.status == http.StatusNotFound {
				continue // not created yet: the plan makes it
			}
			return out, err
		}
		m := relocationMount{Name: v.Name, Kind: v.Kind, Node: v.Node, Step: relocateNone}
		switch {
		case v.Node == "" || v.Node == node:
		case v.App == app:
			m.Step = relocateMove
			moving = append(moving, v.Name)
			if doc, err = setVolumeNode(doc, v.Name, node); err != nil {
				return out, &httpErr{http.StatusUnprocessableEntity, "invalid", "the running app document cannot be edited: " + err.Error()}
			}
		default:
			m.Step = relocateNotMovable
		}
		out.Volumes = append(out.Volumes, m)
	}
	plan := relocationItem{Name: "plan", OK: true}
	switch len(moving) {
	case 0:
		apps, err := allApps(ctx, c, tenant)
		if err != nil {
			return out, err
		}
		dep := ""
		if i := slices.IndexFunc(apps, func(a sfc.AppView) bool { return a.App == app }); i >= 0 {
			dep = apps[i].Deployment
		}
		_, err = c.AppPlan(ctx, sfc.AppPlanRequest{Tenant: tenant, Document: doc, Project: app, Deployment: dep})
		plan.OK, plan.Detail, err = planRefusal(err)
		if err != nil {
			return out, err
		}
	case 1:
		out.Steps = []string{"volume-move"}
		_, err := planMove(ctx, c, tenant, moving[0], "reloc-check", &moveReq{App: app, YAML: string(doc)})
		plan.OK, plan.Detail, err = planRefusal(err)
		if err != nil {
			return out, err
		}
	default:
		out.Steps = []string{"volume-move"}
		plan.OK, plan.Detail = false, "one data store moves at a time; move the others first"
	}
	out.Checks = append(out.Checks, plan)
	out.OK = plan.OK && !slices.ContainsFunc(out.Volumes, func(v relocationMount) bool { return v.Step == relocateNotMovable })
	return out, nil
}

// planRefusal turns a plan error sfcd gave about the document (an input
// code, an invalid or refused plan) into a failed check; other errors
// (transport, login, permission) stay errors.
func planRefusal(err error) (bool, string, error) {
	if err == nil {
		return true, "", nil
	}
	var e *sfc.Error
	if errors.As(err, &e) && (e.InputCode != "" || e.Code == sfc.CodeInvalid) {
		return false, e.Error(), nil
	}
	var he *httpErr
	if errors.As(err, &he) && he.status != http.StatusBadGateway {
		return false, he.msg, nil
	}
	return false, "", err
}
