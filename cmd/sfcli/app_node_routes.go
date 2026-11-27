// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/cli"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/deployment"
	"gopkg.in/yaml.v3"
)

// A file named cluster-app/NAME holds a cluster app's ingress routes, a cluster
// setting for system administrators (devel/design/cluster-apps.md 3.2). app
// diff, deploy and down take it like an app and send the setting instead.

// clusterAppRouteFile reads FILE when its name is cluster-app/...; ok false: a
// workspace app file, for the app flows.
func clusterAppRouteFile(file string) (app string, d deployment.IngressDeclaration, ok bool, err error) {
	raw, err := composeDocument(file)
	if err != nil {
		return "", d, false, err
	}
	var head struct {
		Name string `yaml:"name"`
	}
	if yaml.Unmarshal(raw, &head) != nil || !strings.HasPrefix(head.Name, deployment.ClusterAppPrefix) {
		return "", d, false, nil
	}
	app, d, err = deployment.ParseClusterAppRoutes(raw)
	return app, d, true, err
}

// clusterAppRoute is the app's record, revision 0 when it never had routes.
func (g *globals) clusterAppRoute(c *cli.Context, s *session, app string) (control.ClusterAppRouteView, uint64, error) {
	var found control.ClusterAppRouteView
	var epoch uint64
	err := ingressPages(c, g, s, control.IngressQuery{Part: "cluster-app-routes"}, func(p control.IngressPage) uint32 {
		epoch = p.Epoch
		for _, r := range p.ClusterAppRoutes {
			if r.App == app {
				found = r
			}
		}
		return 0
	})
	return found, epoch, err
}

// clusterAppRouteChanges lists what putting next (nil: removing) changes.
func clusterAppRouteChanges(app string, current control.ClusterAppRouteView, next *deployment.IngressDeclaration) []deployment.Change {
	name := deployment.ClusterAppPrefix + app
	live := current.Revision != 0 && !current.Removed
	var out []deployment.Change
	if next == nil {
		if live {
			out = append(out, deployment.Change{Key: name, Action: "delete", Reason: "routes removed; the ingress on " + current.Ingress.Node + " drains them"})
		}
		return out
	}
	if !live {
		return append(out, deployment.Change{Key: name, Action: "create", Reason: "routes served by the ingress on " + next.Node})
	}
	if current.Ingress.Node != next.Node {
		out = append(out, deployment.Change{Key: name, Action: "update", Reason: "ingress server " + current.Ingress.Node + " -> " + next.Node})
	}
	if !jsonEqual(current.Ingress.Listeners, next.Listeners) || !jsonEqual(current.Ingress.Runtime, next.Runtime) {
		out = append(out, deployment.Change{Key: name + " listeners", Action: "update", Reason: "listeners or limits changed"})
	}
	before, after := map[string]deployment.IngressRouteDeclaration{}, map[string]deployment.IngressRouteDeclaration{}
	for _, r := range deployment.IngressRoutes(current.Ingress) {
		before[r.ID] = r
	}
	for _, r := range deployment.IngressRoutes(*next) {
		after[r.ID] = r
	}
	ids := slices.Sorted(func(yield func(string) bool) {
		for id := range before {
			if !yield(id) {
				return
			}
		}
		for id := range after {
			if _, both := before[id]; !both && !yield(id) {
				return
			}
		}
	})
	for _, id := range ids {
		b, had := before[id]
		a, has := after[id]
		switch {
		case !had:
			out = append(out, deployment.Change{Key: name + " route " + id, Action: "create", Reason: a.Host + a.Prefix})
		case !has:
			out = append(out, deployment.Change{Key: name + " route " + id, Action: "delete", Reason: b.Host + b.Prefix})
		case !jsonEqual(a, b):
			out = append(out, deployment.Change{Key: name + " route " + id, Action: "update", Reason: b.Host + b.Prefix + " -> " + a.Host + a.Prefix})
		}
	}
	return out
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func (g *globals) clusterAppRouteDiff(c *cli.Context, s *session, app string, next *deployment.IngressDeclaration) error {
	current, _, err := g.clusterAppRoute(c, s, app)
	if err != nil {
		return err
	}
	changes := clusterAppRouteChanges(app, current, next)
	return cli.Print(c.Out, g.output.Format(), map[string]any{"App": deployment.ClusterAppPrefix + app, "Revision": current.Revision, "Changes": changes}, func() cli.Rows {
		t := cli.Rows{Header: []string{"object", "change", "reason"}}
		for _, ch := range changes {
			t.Add(ch.Key, ch.Action, ch.Reason)
		}
		return t
	})
}

func (g *globals) clusterAppRouteDeploy(c *cli.Context, s *session, id cli.IDFlag, app string, next deployment.IngressDeclaration) error {
	current, epoch, err := g.clusterAppRoute(c, s, app)
	if err != nil {
		return err
	}
	name := deployment.ClusterAppPrefix + app
	if len(clusterAppRouteChanges(app, current, &next)) == 0 {
		fmt.Fprintf(c.Err, "%s already has these routes.\n", name)
		return nil
	}
	return g.sendAndPrint(c, s, fmt.Sprintf("Serve the routes of %s on the ingress of %s.", name, next.Node), change{ID: id.Get(), Summary: "app deploy " + name, Action: "put-cluster-app-route", Expected: current.Revision, Epoch: epoch, Payload: control.ClusterAppRouteChange{App: app, Ingress: next}})
}

func (g *globals) clusterAppRouteDown(c *cli.Context, s *session, id cli.IDFlag, name string) error {
	app, ok := deployment.ClusterAppName(name)
	if !ok {
		return cli.Usagef("%s is not a cluster app that takes routes", name)
	}
	current, epoch, err := g.clusterAppRoute(c, s, app)
	if err != nil {
		return err
	}
	if current.Revision == 0 || current.Removed {
		return fmt.Errorf("%s has no routes", name)
	}
	return g.sendAndPrint(c, s, fmt.Sprintf("Remove the routes of %s. The ingress of %s stops serving them.", name, current.Ingress.Node), change{ID: id.Get(), Summary: "app down " + name, Action: "remove-cluster-app-route", Expected: current.Revision, Epoch: epoch, Payload: control.ClusterAppRouteSelection{App: app}})
}
