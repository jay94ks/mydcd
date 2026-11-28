// SPDX-License-Identifier: Apache-2.0

package sfc

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/deployment"
	"gopkg.in/yaml.v3"
)

// appDoc is the small app.yaml subset the fake understands: app name,
// tenant, and per-service image and node. Real validation is sfcd's.
type appDoc struct {
	Name string `yaml:"name"`
	XSfc struct {
		Tenant string `yaml:"tenant"`
	} `yaml:"x-sfc"`
	Services map[string]struct {
		Image string `yaml:"image"`
		XSfc  struct {
			Node string `yaml:"node"`
			// Nodes: REQ-8 (mock) replicas, one task per server; Node is
			// then the first of them.
			Nodes []string `yaml:"nodes"`
			// SecretEnv: REQ-16 (mock) a secret's value as an
			// environment variable.
			Secrets struct {
				Env []struct {
					Source string `yaml:"source"`
					Name   string `yaml:"name"`
				} `yaml:"env"`
			} `yaml:"secrets"`
		} `yaml:"x-sfc"`
		Environment any   `yaml:"environment"`
		Secrets     []any `yaml:"secrets"`
		Networks    any   `yaml:"networks"` // list or map form
		Volumes     []any `yaml:"volumes"`
		Ports       []any `yaml:"ports"` // short or long form
	} `yaml:"services"`
}

// networkNames reads a compose `networks` value (list or map form).
func networkNames(v any) []string {
	var out []string
	switch n := v.(type) {
	case []any:
		for _, x := range n {
			out = append(out, fmt.Sprint(x))
		}
	case map[string]any:
		for k := range n {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func parseApp(doc []byte) (appDoc, error) {
	var d appDoc
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return d, err
	}
	if d.Name == "" || len(d.Services) == 0 {
		return d, errors.New("name and services are required")
	}
	for name, s := range d.Services {
		if s.XSfc.Node != "" && len(s.XSfc.Nodes) > 0 {
			return d, fmt.Errorf("service %s: x-sfc.node and x-sfc.nodes together", name)
		}
		if len(s.XSfc.Nodes) > 0 {
			seen := map[string]bool{}
			for _, n := range s.XSfc.Nodes {
				if n == "" || seen[n] {
					return d, fmt.Errorf("service %s: x-sfc.nodes repeats or is empty", name)
				}
				seen[n] = true
			}
			if len(s.XSfc.Nodes) > 1 && len(parseMounts(s.Volumes)) > 0 {
				// a single-writer or node-fixed volume cannot have
				// two replicas.
				return d, &inputError{code: "REPLICA_VOLUME", detail: name}
			}
			s.XSfc.Node = s.XSfc.Nodes[0]
		}
		if s.Image == "" || s.XSfc.Node == "" {
			return d, fmt.Errorf("service %s needs image and x-sfc.node", name)
		}
		if err := checkServiceSecrets(name, s.Environment, s.Secrets, s.XSfc.Secrets.Env); err != nil {
			return d, err
		}
		if len(s.XSfc.Nodes) == 0 {
			s.XSfc.Nodes = []string{s.XSfc.Node}
		}
		d.Services[name] = s
	}
	return d, nil
}

// inputError: a planner refusal with its InputCode (REQ-8 REPLICA_VOLUME,
// REQ-16 SECRET_ENV_INVALID / SECRET_ENV_CONFLICT / SECRET_TARGET_FORBIDDEN).
type inputError struct{ code, detail string }

func (e *inputError) Error() string { return e.code + ": " + e.detail }

// secretTargetForbidden: REQ-16 file targets must be absolute and outside
// these trees.
var secretTargetForbidden = []string{"/proc", "/sys", "/dev", "/run/sfc", "/etc/hosts", "/etc/resolv.conf", "/etc/hostname"}

func checkServiceSecrets(name string, env any, secrets []any, secretEnv []struct {
	Source string `yaml:"source"`
	Name   string `yaml:"name"`
}) error {
	plain := map[string]bool{}
	switch e := env.(type) {
	case map[string]any:
		for k := range e {
			plain[k] = true
		}
	case []any:
		for _, x := range e {
			k, _, _ := strings.Cut(fmt.Sprint(x), "=")
			plain[k] = true
		}
	}
	seen := map[string]bool{}
	for _, s := range secretEnv {
		if s.Source == "" || !envNameRE.MatchString(s.Name) || seen[s.Name] {
			return &inputError{code: "SECRET_ENV_INVALID", detail: name + "." + s.Name}
		}
		if plain[s.Name] {
			return &inputError{code: "SECRET_ENV_CONFLICT", detail: name + "." + s.Name}
		}
		seen[s.Name] = true
	}
	for _, s := range secrets {
		m, ok := s.(map[string]any)
		if !ok {
			continue
		}
		target, _ := m["target"].(string)
		if target == "" || !strings.Contains(target, "/") {
			continue // a name under /run/secrets/
		}
		clean := path.Clean(target)
		if !strings.HasPrefix(target, "/") || clean != target || clean == "/" ||
			slices.ContainsFunc(secretTargetForbidden, func(f string) bool { return clean == f || strings.HasPrefix(clean, f+"/") }) {
			return &inputError{code: "SECRET_TARGET_FORBIDDEN", detail: name + " " + target}
		}
	}
	return nil
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func (w *world) knownNode(id string) bool {
	for _, m := range w.members {
		if m.ID == id {
			return true
		}
	}
	return false
}

func (w *world) nodeAllowed(tenant, node string) bool {
	for _, n := range w.tenantNodes[tenant] {
		if n == node {
			return true
		}
	}
	return false
}

// deploy accepts a new app version at the current root revision.
func (w *world) deploy(tenant, name string, doc []byte, submitter, operation string, at int64) (*fakeApp, error) {
	d, err := parseApp(doc)
	if err != nil {
		return nil, err
	}
	if d.Name != name || d.XSfc.Tenant != "" && d.XSfc.Tenant != tenant {
		return nil, errors.New("document name/tenant mismatch")
	}
	for _, s := range d.Services {
		for _, n := range s.XSfc.Nodes {
			if !w.knownNode(n) || !w.nodeAllowed(tenant, n) {
				return nil, fmt.Errorf("node %s not allowed", n)
			}
		}
	}
	if err := w.appHostPortCheck(tenant, d); err != nil {
		return nil, err
	}
	if err := w.cordonCheck(tenant, d); err != nil {
		return nil, err
	}
	key := tenant + "/" + name
	app := w.apps[key]
	if app == nil {
		app = &fakeApp{ops: map[string]*AppOperation{}}
		app.view = AppView{Tenant: tenant, App: name, Deployment: "dep-" + name}
		w.apps[key] = app
	}
	version := uint64(len(app.sources) + 1)
	app.sources = append(app.sources, AppSource{
		Tenant: tenant, App: name, Version: version, Document: append([]byte(nil), doc...),
		Digest: digestOf(doc), Submitter: submitter, Operation: operation, AcceptedAt: at,
	})
	app.view.Revision = w.root
	app.view.Retiring = false
	app.view.Operation = OperationSummary{ID: operation, Status: "succeeded", Plan: digestOf(doc), CompletedAt: uint64(at), Submitter: submitter, Epoch: 1}
	app.view.Health = "healthy"
	app.view.ObservedAt = uint64(at)
	app.view.Claims = len(d.Services)
	app.ops[operation] = &AppOperation{Tenant: tenant, App: name, ID: operation, Status: "succeeded", Submitter: submitter, StartedAt: at, CompletedAt: at,
		Steps: []string{"plan", "reserve", "pull", "start", "health"}}

	gen := version
	app.tasks = nil
	for _, svc := range sortedKeys(d.Services) {
		s := d.Services[svc]
		for i, n := range s.XSfc.Nodes {
			app.tasks = append(app.tasks, Task{
				Tenant: tenant, App: name, Service: svc, Instance: strconv.Itoa(i + 1), Node: n, Image: s.Image,
				Generation: gen, Desired: "running", Observed: "running", Health: "healthy",
				StartedAt: at, ObservedAt: at,
			})
		}
	}
	app.applyOverrides()
	return app, nil
}

func (a *fakeApp) applyOverrides() {
	for i, t := range a.tasks {
		o, ok := a.overrides[t.Service+"/"+t.Instance]
		if !ok {
			continue
		}
		if o.Observed != "" {
			t.Observed = o.Observed
		}
		if o.Health != "" {
			t.Health = o.Health
		}
		t.Restarts, t.ExitCode, t.LastCheck = o.Restarts, o.ExitCode, o.LastCheck
		a.tasks[i] = t
		if a.view.HealthReason == nil && t.Health == "unhealthy" {
			// sfcd's first cause (deployment.HealthReason), as a real
			// degraded app reports it.
			r := &deployment.HealthReason{Code: deployment.HealthTaskUnhealthy, Kind: "task", Name: t.Service, Node: t.Node}
			if t.ExitCode != 0 {
				exit := t.ExitCode
				r.Code, r.Exit = deployment.HealthTaskExited, &exit
			}
			a.view.HealthReason = r
		}
	}
}

func (a *fakeApp) running() (AppSource, bool) {
	if len(a.sources) == 0 || a.view.Retiring {
		return AppSource{}, false
	}
	return a.sources[len(a.sources)-1], true
}

func (w *world) plan(tenant string, doc []byte, diff bool) (AppPlan, error) {
	d, err := parseApp(doc)
	if err != nil {
		var ie *inputError
		if errors.As(err, &ie) {
			return AppPlan{}, &Error{Code: CodeInvalid, Method: "app-plan-stream", InputCode: ie.code, Detail: ie.detail}
		}
		return AppPlan{}, &Error{Code: CodeInvalid, Method: "app-plan-stream", InputCode: "APP_DOCUMENT_INVALID", Detail: err.Error()}
	}
	for svc, s := range d.Services {
		for _, n := range s.XSfc.Nodes {
			if !w.knownNode(n) || !w.nodeAllowed(tenant, n) {
				return AppPlan{}, &Error{Code: CodeInvalid, Method: "app-plan-stream", InputCode: "NODE_NOT_ALLOWED", Detail: svc + " → " + n}
			}
		}
	}
	if err := w.appHostPortCheck(tenant, d); err != nil {
		ie := err.(*inputError)
		return AppPlan{}, &Error{Code: CodeInvalid, Method: "app-plan-stream", InputCode: ie.code, Detail: ie.detail}
	}
	if err := w.cordonCheck(tenant, d); err != nil {
		ie := err.(*inputError)
		return AppPlan{}, &Error{Code: CodeInvalid, Method: "app-plan-stream", InputCode: ie.code, Detail: ie.detail}
	}
	current := map[string]Task{}
	currentNodes := map[string][]string{}
	var oldDoc []byte
	if app := w.apps[tenant+"/"+d.Name]; app != nil {
		if src, ok := app.running(); ok {
			oldDoc = src.Document
			for _, t := range app.tasks {
				if _, ok := current[t.Service]; !ok {
					current[t.Service] = t
				}
				currentNodes[t.Service] = append(currentNodes[t.Service], t.Node)
			}
		}
	}
	p := AppPlan{Digest: digestOf(doc), Length: len(doc), Data: append([]byte(nil), doc...), App: d.Name}
	for _, svc := range sortedKeys(d.Services) {
		s := d.Services[svc]
		change := "add"
		if t, ok := current[svc]; ok {
			change = "keep"
			if t.Image != s.Image || !slices.Equal(currentNodes[svc], s.XSfc.Nodes) {
				change = "update"
			}
			delete(current, svc)
		}
		ps := PlannedService{Name: svc, Image: s.Image, Node: s.XSfc.Node, Change: change}
		if len(s.XSfc.Nodes) > 1 {
			ps.Nodes = slices.Clone(s.XSfc.Nodes)
		}
		for _, e := range s.XSfc.Secrets.Env {
			ps.SecretEnv = append(ps.SecretEnv, e.Name)
		}
		p.Services = append(p.Services, ps)
	}
	for _, svc := range sortedKeys(current) {
		t := current[svc]
		p.Services = append(p.Services, PlannedService{Name: svc, Image: t.Image, Node: t.Node, Change: "remove"})
	}
	if diff {
		p.Diff = lineDiff(string(oldDoc), string(doc))
	}
	return p, nil
}

// lineDiff is a minimal "-"/"+" diff for display in the fake.
func lineDiff(a, b string) string {
	al, bl := splitLines(a), splitLines(b)
	seen := map[string]int{}
	for _, l := range al {
		seen[l]++
	}
	out := ""
	for _, l := range bl {
		if seen[l] > 0 {
			seen[l]--
			continue
		}
		out += "+" + l + "\n"
	}
	for _, l := range al {
		if seen[l] > 0 {
			seen[l]--
			out += "-" + l + "\n"
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// --- events ---

func cursorOf(seq uint64) string { return fmt.Sprintf("%016d", seq) }

func (w *world) addEvent(e FixtureEvent) string {
	w.evSeq++
	e.Cursor = cursorOf(w.evSeq)
	w.events = append(w.events, e)
	return e.Cursor
}

func (w *world) trimEvents(cursor string) {
	seq, err := strconv.ParseUint(cursor, 10, 64)
	if err != nil {
		return
	}
	i := sort.Search(len(w.events), func(i int) bool { return w.events[i].Cursor > cursor })
	w.events = w.events[i:]
	if seq > w.evFloor {
		w.evFloor = seq
	}
}
