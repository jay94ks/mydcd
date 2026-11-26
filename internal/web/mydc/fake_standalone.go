// SPDX-License-Identifier: Apache-2.0

package mydc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/jay94ks/mydcd/internal/cluster/control"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/containerops"
)

// REQ-29 (mock) standalone containers in the fake.

const (
	standaloneDefaultTTL   = time.Hour
	standaloneMaxLifetime  = 24 * time.Hour
	standaloneDefaultGrace = 10 * time.Minute
	standaloneMaxGrace     = time.Hour
)

// standaloneRetain: an ended or removed container stays listed as "removed".
const standaloneRetain = int64(3600)

// standaloneDef is the definition subset the fake understands: the flat
// definition (name, lifetime, restart, ttl, grace, mode) with one app.yaml
// service's fields at the same level. Only the fields below are interpreted.
type standaloneDef struct {
	Name       string `yaml:"name"`
	Lifetime   string `yaml:"lifetime"`
	TTL        string `yaml:"ttl"`
	Grace      string `yaml:"grace"`
	Restart    string `yaml:"restart"`
	Mode       string `yaml:"mode"`
	Image      string `yaml:"image"`
	Command    any    `yaml:"command"`
	Entrypoint any    `yaml:"entrypoint"`
	Networks   any    `yaml:"networks"`
	Volumes    []any  `yaml:"volumes"`
	Ports      []any  `yaml:"ports"`
	XMydc      struct {
		Node    string `yaml:"node"`
		Ingress struct {
			Routes []struct {
				Host string `yaml:"host"`
			} `yaml:"routes"`
		} `yaml:"ingress"`
	} `yaml:"x-mydc"`
}

type standaloneMount struct {
	Volume string
	RW     bool
}

// parseMounts reads a compose `volumes` list (short "src:dst[:ro]" or long
// form with source / read_only).
func parseMounts(vs []any) []standaloneMount {
	var out []standaloneMount
	for _, v := range vs {
		switch t := v.(type) {
		case string:
			p := strings.Split(t, ":")
			out = append(out, standaloneMount{Volume: p[0], RW: len(p) < 3 || p[2] != "ro"})
		case map[string]any:
			ro, _ := t["read_only"].(bool)
			out = append(out, standaloneMount{Volume: fmt.Sprint(t["source"]), RW: !ro})
		}
	}
	return out
}

// parsed is a normalized definition.
type standaloneSpec struct {
	Name, Lifetime, Mode, Image, Node, Restart string
	TTL, Grace                                 time.Duration
	Command, Entrypoint                        string
	Networks                                   []string
	Mounts                                     []standaloneMount
	Hosts                                      []string
}

type standaloneEntry struct {
	view      StandaloneView // Connections/ObservedAt/Selection filled on read
	spec      standaloneSpec
	startedAt int64
	conns     int                      // open streams on this container
	extra     int                      // fixture: a terminal attached elsewhere
	scope     string                   // mydcd's internal scope (StandaloneScopeName of the first name)
	intent    uint64                   // accepted management changes (StandaloneView.Target)
	ops       map[string]*AppOperation // real standalone-up results by Operation
}

func (f *Fake) SetStandaloneLimits(minePerUser, perTenant int) {
	f.mu.Lock()
	f.w.saMineMax, f.w.saTenantMax = minePerUser, perTenant
	f.mu.Unlock()
}

// SetStandaloneNodeLimit sets the per-server limit (all tenants; 0 = 64).
func (f *Fake) SetStandaloneNodeLimit(perNode int) {
	f.mu.Lock()
	f.w.saNodeMax = perNode
	f.mu.Unlock()
}

// ExitStandalone simulates the main process exiting with code: a temp
// container ends and is removed; a fixed one follows its restart policy.
func (f *Fake) ExitStandalone(tenant, name string, code int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.w
	e := w.standalones[tenant+"/"+name]
	if e == nil || e.removed() {
		return
	}
	now := f.now().Unix()
	if e.view.Lifetime == LifetimeTemp {
		w.endStandalone(e, now, fmt.Sprintf("exit %d", code))
		return
	}
	c := code
	e.view.ExitCode = &c
	if p := e.view.RestartPolicy; p == "always" || p == "on-failure" && code != 0 {
		e.view.Restarts++
		e.view.Generation++
		e.view.State, e.startedAt = "running", now
		w.addEvent(FixtureEvent{Time: now, Scope: "tenant", Tenant: tenant, Node: e.view.Node, Kind: "task-restarted", Target: tenant + "/standalone/" + name, Detail: fmt.Sprintf("exit %d", code)})
		return
	}
	e.view.State = "exited"
	w.addEvent(FixtureEvent{Time: now, Scope: "tenant", Tenant: tenant, Node: e.view.Node, Kind: "task-exited", Target: tenant + "/standalone/" + name, Detail: fmt.Sprintf("exit %d", code)})
}

func durationOr(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func flatten(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		parts := make([]string, len(t))
		for i, p := range t {
			parts[i] = fmt.Sprint(p)
		}
		return strings.Join(parts, " ")
	}
	return fmt.Sprint(v)
}

func (w *world) parseStandalone(tenant string, doc []byte) (standaloneSpec, error) {
	var d standaloneDef
	if err := yaml.Unmarshal(doc, &d); err != nil {
		return standaloneSpec{}, err
	}
	s := standaloneSpec{Name: d.Name, Lifetime: d.Lifetime, Mode: d.Mode, Image: d.Image, Node: d.XMydc.Node,
		Command: flatten(d.Command), Entrypoint: flatten(d.Entrypoint)}
	if !lifecycle.ValidID(s.Name) {
		return s, errors.New("name: lowercase letters, digits and -")
	}
	if s.Image == "" {
		return s, errors.New("image is required")
	}
	var err error
	switch s.Lifetime {
	case LifetimeTemp:
		if d.Restart != "" {
			return s, errors.New("restart is for fixed")
		}
		if s.TTL, err = durationOr(d.TTL, standaloneDefaultTTL); err != nil || s.TTL < time.Minute || s.TTL > standaloneMaxLifetime {
			return s, errors.New("ttl: 1m..24h")
		}
		if s.Grace, err = durationOr(d.Grace, standaloneDefaultGrace); err != nil || s.Grace < 0 || s.Grace > standaloneMaxGrace {
			return s, errors.New("grace: 0..1h")
		}
		if s.Mode == "" {
			s.Mode = ModeShell
		}
	case LifetimeFixed:
		if d.TTL != "" || d.Grace != "" {
			return s, errors.New("ttl/grace are for temp")
		}
		s.Restart = d.Restart
		if s.Restart == "" {
			s.Restart = "on-failure"
		}
		if !validRestart(s.Restart) {
			return s, errors.New("restart: no / on-failure / always")
		}
		if s.Mode == "" {
			s.Mode = ModeEntrypoint
		}
	default:
		return s, errors.New("lifetime: temp or fixed")
	}
	if s.Mode != ModeShell && s.Mode != ModeEntrypoint {
		return s, errors.New("mode: shell or entrypoint")
	}
	if s.Mode == ModeShell && s.Command == "" {
		s.Command = "/bin/sh"
	}
	if s.Node == "" {
		nodes := append([]string(nil), w.tenantNodes[tenant]...)
		sort.Strings(nodes)
		if len(nodes) == 0 {
			return s, errors.New("tenant has no servers")
		}
		s.Node = nodes[0]
	} else if !w.knownNode(s.Node) || !w.nodeAllowed(tenant, s.Node) {
		return s, fmt.Errorf("server %s is not allowed for this tenant", s.Node)
	}
	switch n := d.Networks.(type) {
	case []any:
		for _, v := range n {
			s.Networks = append(s.Networks, fmt.Sprint(v))
		}
	case map[string]any:
		for k := range n {
			s.Networks = append(s.Networks, k)
		}
	}
	sort.Strings(s.Networks)
	s.Mounts = parseMounts(d.Volumes)
	for _, r := range d.XMydc.Ingress.Routes {
		s.Hosts = append(s.Hosts, r.Host)
	}
	return s, nil
}

func validRestart(p string) bool { return p == "no" || p == "on-failure" || p == "always" }

// limits: mydcd's control.StandaloneTempLimitUser / LimitTenant /
// LimitNode unless a test set them.
func (w *world) limits() (int, int, int) {
	mine, tenant, node := w.saMineMax, w.saTenantMax, w.saNodeMax
	if mine == 0 {
		mine = control.StandaloneTempLimitUser
	}
	if tenant == 0 {
		tenant = control.StandaloneLimitTenant
	}
	if node == 0 {
		node = control.StandaloneLimitNode
	}
	return mine, tenant, node
}

// planStandalone computes the plan for doc as user would submit it.
func (w *world) planStandalone(tenant, user string, doc []byte) (StandalonePlan, standaloneSpec, error) {
	s, err := w.parseStandalone(tenant, doc)
	if err != nil {
		return StandalonePlan{}, s, err
	}
	p := StandalonePlan{Name: s.Name, Digest: sha256.Sum256(doc)}
	old := w.standalones[tenant+"/"+s.Name]
	if old != nil && old.removed() {
		old = nil // a removed row is replaced by a new container
	}
	if old == nil {
		p.Create = true
	} else {
		p.Revision = old.view.Revision
		o := old.spec
		add := func(field, before, after string, recreate bool) {
			if before != after {
				p.Changes = append(p.Changes, StandaloneChange{Field: field, Before: before, After: after})
				p.Recreate = p.Recreate || recreate
			}
		}
		add("image", o.Image, s.Image, true)
		add("mode", o.Mode, s.Mode, true)
		add("node", o.Node, s.Node, true)
		add("command", o.Command, s.Command, true)
		add("entrypoint", o.Entrypoint, s.Entrypoint, true)
		add("networks", strings.Join(o.Networks, ","), strings.Join(s.Networks, ","), true)
		add("volumes", fmt.Sprint(o.Mounts), fmt.Sprint(s.Mounts), true)
		add("ingress", strings.Join(o.Hosts, ","), strings.Join(s.Hosts, ","), false)
		add("lifetime", o.Lifetime, s.Lifetime, false)
		add("restart", o.Restart, s.Restart, false)
		add("ttl", durString(o.TTL), durString(s.TTL), false)
		add("grace", durString(o.Grace), durString(s.Grace), false)
	}
	for _, n := range s.Networks {
		found := false
		for _, r := range w.resources {
			if r.Tenant == tenant && r.Network != nil && r.Network.Name == n {
				found = true
				p.Impact = append(p.Impact, StandaloneImpact{Kind: "network", Target: n, Detail: "borrows the network; alias " + s.Name})
			}
		}
		if !found {
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "network", Target: n, Detail: "network not found", Blocking: true})
		}
	}
	for _, m := range s.Mounts {
		var vol *volumeRow
		for i := range w.volumes {
			if w.volumes[i].Tenant == tenant && w.volumes[i].Name == m.Volume {
				vol = &w.volumes[i]
			}
		}
		switch {
		case vol == nil:
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "volume", Target: m.Volume, Detail: "volume not found", Blocking: true})
		case vol.Kind == "fixed" && vol.Node != s.Node:
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "volume", Target: m.Volume, Detail: "fixed volume is on " + vol.Node, Blocking: true})
		case w.volumeConflict(tenant, s.Name, *vol, m.RW):
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "volume", Target: m.Volume, Code: VolumeWriterConflict, Detail: "another task holds the volume's writer, or reads it while this writes", Blocking: true})
		default:
			mode := "read-only"
			if m.RW {
				mode = "writer"
			}
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "volume", Target: m.Volume, Detail: "consumer (" + mode + ")"})
		}
	}
	for _, h := range s.Hosts {
		taken := ""
		for k, e := range w.standalones {
			if k == tenant+"/"+s.Name || e.removed() {
				continue
			}
			for _, oh := range e.spec.Hosts {
				if oh == h {
					taken = e.view.Tenant + "/" + e.view.Name
				}
			}
		}
		if taken != "" {
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "ingress", Target: h, Detail: "host is served by " + taken, Blocking: true})
		} else {
			p.Impact = append(p.Impact, StandaloneImpact{Kind: "ingress", Target: h, Detail: "new route"})
		}
	}
	mineMax, tenantMax, nodeMax := w.limits()
	p.Limits = StandaloneLimits{MineMax: mineMax, TenantMax: tenantMax, NodeMax: nodeMax}
	for k, e := range w.standalones {
		if k == tenant+"/"+s.Name || e.removed() {
			continue
		}
		if e.view.Node == s.Node {
			p.Limits.Node++
		}
		if e.view.Tenant != tenant {
			continue
		}
		p.Limits.Tenant++
		if e.view.Lifetime == LifetimeTemp && e.view.Owner == user {
			p.Limits.Mine++
		}
	}
	if p.Limits.Tenant+1 > tenantMax {
		p.Impact = append(p.Impact, StandaloneImpact{Kind: "limit", Target: LimitTenant, Detail: fmt.Sprintf("tenant has %d of %d standalone containers", p.Limits.Tenant, tenantMax), Blocking: true})
	}
	if s.Lifetime == LifetimeTemp && p.Limits.Mine+1 > mineMax {
		p.Impact = append(p.Impact, StandaloneImpact{Kind: "limit", Target: LimitUserTemp, Detail: fmt.Sprintf("you have %d of %d temp containers", p.Limits.Mine, mineMax), Blocking: true})
	}
	if p.Limits.Node+1 > nodeMax {
		p.Impact = append(p.Impact, StandaloneImpact{Kind: "limit", Target: LimitNode, Detail: fmt.Sprintf("server %s has %d of %d standalone containers", s.Node, p.Limits.Node, nodeMax), Blocking: true})
	}
	return p, s, nil
}

func durString(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func (e *standaloneEntry) removed() bool { return e.view.State == "removed" }

// endStandalone: the container and its write layer are gone; the row stays
// as "removed" for standaloneRetain seconds.
func (w *world) endStandalone(e *standaloneEntry, now int64, why string) {
	e.view.State, e.view.EndedAt, e.view.ExpiresAt, e.view.DisconnectedAt = "removed", now, 0, 0
	e.conns, e.extra = 0, 0
	w.addEvent(FixtureEvent{Time: now, Scope: "tenant", Tenant: e.view.Tenant, Node: e.view.Node, Kind: "standalone-ended", Target: e.view.Tenant + "/standalone/" + e.view.Name, Detail: why})
}

// expireStandalones ends temp containers past their TTL or grace and drops
// removed rows after their retention.
func (w *world) expireStandalones(now int64) {
	for _, k := range sortedKeys(w.standalones) {
		e := w.standalones[k]
		v := e.view
		if e.removed() {
			if now >= v.EndedAt+standaloneRetain {
				delete(w.standalones, k)
			}
			continue
		}
		if v.Lifetime != LifetimeTemp {
			continue
		}
		switch {
		case now >= v.ExpiresAt:
			w.endStandalone(e, now, "ttl")
		case e.conns+e.extra == 0 && v.DisconnectedAt > 0 && now >= v.DisconnectedAt+int64(v.GraceSeconds):
			w.endStandalone(e, now, "grace")
		}
	}
}

func (w *world) standaloneVisible(user string, e *standaloneEntry) bool {
	if !w.canRead(user, e.view.Tenant) {
		return false
	}
	return e.view.Lifetime == LifetimeFixed || e.view.Owner == user || w.canManage(user, e.view.Tenant)
}

func (w *world) standaloneRow(e *standaloneEntry, now int64) StandaloneView {
	v := e.view
	v.Document = append([]byte(nil), v.Document...)
	if v.ExitCode != nil {
		c := *v.ExitCode
		v.ExitCode = &c
	}
	v.Connections, v.ObservedAt, v.Selection, v.Target = e.conns+e.extra, now, ContainerSelection{Standalone: v.Name}, e.managementTarget()
	if v.Lifetime == LifetimeTemp && v.State != "removed" {
		v.RemainingSeconds = max(0, v.ExpiresAt-now)
	}
	v.Scope = e.scope
	return v
}

func (e *standaloneEntry) task() Task {
	return Task{Tenant: e.view.Tenant, App: standaloneApp, Service: e.view.Name, Instance: standalonePrefix + e.view.Name,
		Node: e.view.Node, Image: e.view.Image, Generation: e.view.Generation, Observed: e.view.State, StartedAt: e.startedAt}
}

// standaloneTarget resolves a standalone selection to a running container.
func (w *world) standaloneTarget(user, tenant, name string, now int64) (StreamTarget, *standaloneEntry, error) {
	w.expireStandalones(now)
	e := w.standalones[tenant+"/"+name]
	if e == nil {
		return StreamTarget{}, nil, errMissing
	}
	if !w.standaloneVisible(user, e) {
		return StreamTarget{}, nil, errForbidden
	}
	if e.view.State != "running" {
		return StreamTarget{}, nil, errMissing
	}
	return w.streamTarget(tenant, e.task(), e.view.Revision), e, nil
}

var errMissing = errors.New("missing")

func (c *fakeConn) Standalones(ctx context.Context, tenant, after string) (Page[StandaloneView], error) {
	const m = "standalone-list"
	if err := checkAfter(m, after); err != nil {
		return Page[StandaloneView]{}, err
	}
	if err := c.appRead(ctx, m, tenant); err != nil {
		return Page[StandaloneView]{}, err
	}
	defer c.unlock()
	w, now := c.f.w, c.f.now().Unix()
	w.expireStandalones(now)
	var items []StandaloneView
	for _, e := range w.standalones {
		if e.view.Tenant == tenant && w.standaloneVisible(c.session.User, e) {
			items = append(items, w.standaloneRow(e, now))
		}
	}
	return paginate(items, func(v StandaloneView) string { return v.Name }, after, c.f.pageSize, w.root), nil
}

func (c *fakeConn) Standalone(ctx context.Context, tenant, name string) (StandaloneView, error) {
	const m = "standalone-get"
	if err := c.appRead(ctx, m, tenant); err != nil {
		return StandaloneView{}, err
	}
	defer c.unlock()
	w, now := c.f.w, c.f.now().Unix()
	w.expireStandalones(now)
	e := w.standalones[tenant+"/"+name]
	if e == nil || !w.standaloneVisible(c.session.User, e) {
		return StandaloneView{}, fail(m, CodeMissing, "")
	}
	return w.standaloneRow(e, now), nil
}

// applyStandalone handles the REQ-29 actions. f.mu is held.
func (c *fakeConn) applyStandalone(op UserOperation, actor string, next uint64) (err error) {
	w := c.f.w
	ch := op.Change
	now := c.f.now().Unix()
	w.expireStandalones(now)
	if ch.Action == ActionStandaloneUp {
		var b control.AppBegin // mydcd's shape: an uploaded definition
		if decodePayload(ch.Payload, &b) != nil || b.Standalone == nil || b.Target == nil || b.Tenant == "" || !lifecycle.ValidID(b.Operation) {
			return errors.New("payload")
		}
		doc, err := w.uploadedStandalone(b)
		if err != nil {
			return err
		}
		tenant := b.Tenant
		if !w.canManage(actor, tenant) {
			return errForbidden
		}
		plan, s, err := w.planStandalone(tenant, actor, doc)
		if err != nil {
			return err
		}
		old := w.standalones[tenant+"/"+s.Name]
		if old != nil && old.removed() {
			old = nil
		}
		if old != nil && !w.standaloneVisible(actor, old) {
			return errForbidden
		}
		if plan.Revision != ch.Expected {
			return errCAS
		}
		if err := w.checkStandaloneBegin(op, b, old); err != nil {
			return err
		}
		for _, im := range plan.Impact {
			if im.Blocking && im.Kind == "limit" {
				return errCAS // mydcd: ConditionFailed; the plan carries the code
			}
		}
		for _, im := range plan.Impact {
			if im.Blocking {
				return errors.New(im.Detail)
			}
		}
		e := old
		if e == nil {
			e = &standaloneEntry{scope: standaloneScope(tenant, s.Name), view: StandaloneView{Name: s.Name, Tenant: tenant, Owner: actor, CreatedAt: now}}
			w.standalones[tenant+"/"+s.Name] = e
		}
		v := &e.view
		v.Lifetime, v.Mode, v.Image, v.Node, v.RestartPolicy = s.Lifetime, s.Mode, s.Image, s.Node, s.Restart
		v.Document, v.Revision = doc, next
		v.ExpiresAt, v.GraceSeconds = 0, 0
		if s.Lifetime == LifetimeTemp {
			v.ExpiresAt, v.GraceSeconds = min(now+int64(s.TTL/time.Second), v.CreatedAt+int64(standaloneMaxLifetime/time.Second)), int(s.Grace/time.Second)
			if e.conns == 0 && v.DisconnectedAt == 0 {
				v.DisconnectedAt = now
			}
		} else {
			v.DisconnectedAt = 0
		}
		if plan.Create || plan.Recreate || v.State != "running" {
			v.Generation++
			v.State, v.ExitCode, e.startedAt = "running", nil, now
		}
		e.spec = s
		e.intent++
		w.finishStandaloneBegin(e, b, actor, now)
		return nil
	}

	var name, tenant string
	var pin control.StandaloneChange       // pin / remove
	var ext control.StandaloneExtendChange // REQ-61
	var ctl *control.TaskRestartChange     // stop/start/restart
	switch ch.Action {
	case ActionStandalonePin, ActionStandaloneRemove:
		if decodePayload(ch.Payload, &pin) != nil || !lifecycle.ValidID(pin.Operation) {
			return errors.New("payload")
		}
		if ch.Action == ActionStandaloneRemove && (pin.NewName != "" || pin.Restart != "") {
			return errors.New("payload")
		}
		tenant, name = pin.Tenant, pin.Name
	case ActionStandaloneExtend:
		if decodePayload(ch.Payload, &ext) != nil || ext.Scope == "" || !control.StandaloneCASAllowed(ch) {
			return errors.New("payload")
		}
		tenant, name = ext.Tenant, ext.Name
	default:
		var q control.TaskRestartChange
		if decodePayload(ch.Payload, &q) != nil || q.Standalone == "" || q.App != "" || !lifecycle.ValidID(q.Operation) {
			return errors.New("payload")
		}
		tenant, name, ctl = q.Tenant, q.Standalone, &q
	}
	if tenant == "" || !lifecycle.ValidID(name) {
		return errors.New("payload")
	}
	if !w.canManage(actor, tenant) {
		return errForbidden
	}
	e := w.standalones[tenant+"/"+name]
	if e == nil {
		return errCAS
	}
	// extend, as mydcd: Target is the CAS; only a future revision is refused.
	if ch.Action == ActionStandaloneExtend && ch.Expected > e.view.Revision || ch.Action != ActionStandaloneExtend && e.view.Revision != ch.Expected {
		return errCAS
	}
	if !w.standaloneVisible(actor, e) {
		return errForbidden
	}
	if e.removed() {
		return errors.New("standalone container was removed")
	}
	if pin.Target != nil && *pin.Target != e.managementTarget() {
		return errCAS
	}
	var plan control.TaskRestartPlan
	if ctl != nil {
		if err := w.realStandaloneControl(e, ch.Action, *ctl); err != nil {
			return err
		}
		plan, _ = w.controlPlan(e, ch.Action)
	}
	defer func() {
		if err == nil {
			e.intent++
			if ctl != nil {
				w.recordControl(containerops.Selection{Standalone: name}, actor, *ctl, plan, next, now)
			}
		}
	}()
	v := &e.view
	switch ch.Action {
	case ActionStandalonePin:
		if pin.Restart == "" {
			pin.Restart = "on-failure"
		}
		if v.Lifetime != LifetimeTemp || !validRestart(pin.Restart) {
			return errors.New("pin: temp only, restart no/on-failure/always")
		}
		newName := name
		if pin.NewName != "" && pin.NewName != name {
			if !lifecycle.ValidID(pin.NewName) {
				return errors.New("pin: invalid new name")
			}
			if o := w.standalones[tenant+"/"+pin.NewName]; o != nil && !o.removed() {
				return errors.New("pin: new name is taken")
			}
			newName = pin.NewName
		}
		doc, err := pinnedDocument(v.Document, newName, pin.Restart)
		if err != nil {
			return err
		}
		v.Lifetime, v.RestartPolicy, v.ExpiresAt, v.GraceSeconds, v.DisconnectedAt, v.Document = LifetimeFixed, pin.Restart, 0, 0, 0, doc
		e.spec.Lifetime, e.spec.Restart, e.spec.TTL, e.spec.Grace = LifetimeFixed, pin.Restart, 0, 0
		if newName != name {
			delete(w.standalones, tenant+"/"+name)
			v.Name, e.spec.Name = newName, newName
			w.standalones[tenant+"/"+newName] = e
		}
	case ActionStandaloneExtend:
		// control.reduceStandaloneExtension: a running temp whose signed
		// coordinates still match; the new expiry is the original At + N.
		if ext.Target != e.managementTarget() || v.Lifetime != LifetimeTemp || v.State != "running" || ext.Scope != e.scope || ext.CreatedAt != v.CreatedAt || ext.PreviousExpiresAt != v.ExpiresAt {
			return errCAS
		}
		p, err := control.PlanStandaloneExtension(ext.CreatedAt, ext.PreviousExpiresAt, op.At, ext.TTLSeconds)
		if err != nil {
			return errCAS
		}
		v.ExpiresAt = p.ProposedExpiresAt
	case ActionStandaloneStop:
		if v.Lifetime == LifetimeTemp {
			v.Revision = next
			w.endStandalone(e, now, "stopped")
			return nil
		}
		zero := 0
		v.State, v.ExitCode = "exited", &zero
	case ActionStandaloneStart:
		if v.Lifetime == LifetimeTemp || v.State == "running" {
			return errors.New("start: stopped fixed container only")
		}
		v.Generation++
		v.State, v.ExitCode, e.startedAt = "running", nil, now
	case ActionStandaloneRestart:
		v.Generation++
		v.State, v.ExitCode, e.startedAt = "running", nil, now
	case ActionStandaloneRemove:
		v.Revision = next
		w.endStandalone(e, now, "removed")
		return nil
	}
	v.Revision = next
	return nil
}

// pinnedDocument sets lifetime: fixed, restart and name, and drops ttl/grace,
// keeping the rest of the flat definition as written.
func pinnedDocument(doc []byte, name, restart string) ([]byte, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(doc, &n); err != nil || len(n.Content) == 0 || n.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("document")
	}
	m := n.Content[0]
	var out []*yaml.Node
	hasRestart := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		switch k.Value {
		case "ttl", "grace":
			continue
		case "lifetime":
			v = &yaml.Node{Kind: yaml.ScalarNode, Value: LifetimeFixed}
		case "name":
			v = &yaml.Node{Kind: yaml.ScalarNode, Value: name}
		case "restart":
			v, hasRestart = &yaml.Node{Kind: yaml.ScalarNode, Value: restart, Style: yaml.DoubleQuotedStyle}, true
		}
		out = append(out, k, v)
		if k.Value == "lifetime" && !hasRestart {
			out = append(out, &yaml.Node{Kind: yaml.ScalarNode, Value: "restart"}, &yaml.Node{Kind: yaml.ScalarNode, Value: restart, Style: yaml.DoubleQuotedStyle})
			hasRestart = true
		}
	}
	m.Content = out
	return yaml.Marshal(&n)
}

// standaloneAttach/Detach count open streams (OpenStream / shutdown). f.mu is held.
func (w *world) standaloneAttach(t StreamTarget) {
	if e := w.standaloneOf(t); e != nil {
		e.conns++
		e.view.DisconnectedAt = 0
	}
}

func (w *world) standaloneDetach(t StreamTarget, now int64) {
	if e := w.standaloneOf(t); e != nil && e.conns > 0 {
		e.conns--
		if e.conns+e.extra == 0 && e.view.Lifetime == LifetimeTemp {
			e.view.DisconnectedAt = now
		}
	}
}

func (w *world) standaloneOf(t StreamTarget) *standaloneEntry {
	if t.Standalone != "" {
		return w.standalones[t.Tenant+"/"+t.Standalone]
	}
	return nil
}

// seedStandalones: fixture standalone containers.
func (w *world) seedStandalones(f Fixture) {
	w.standalones = map[string]*standaloneEntry{}
	base := time.Unix(fixtureNow, 0)
	if now := time.Now(); now.After(base) {
		base = now
	}
	for _, fs := range f.Standalones {
		s, err := w.parseStandalone(fs.Tenant, []byte(fs.Document))
		if err != nil {
			panic("mydc fake fixture standalone: " + err.Error())
		}
		w.root++
		created := base.Add(-fs.Age).Unix()
		e := &standaloneEntry{spec: s, startedAt: created, extra: fs.Attached, scope: standaloneScope(fs.Tenant, s.Name), view: StandaloneView{
			Name: s.Name, Tenant: fs.Tenant, Lifetime: s.Lifetime, Mode: s.Mode, Image: s.Image, Node: s.Node,
			State: fs.State, Restarts: fs.Restarts, RestartPolicy: s.Restart, Owner: fs.Owner,
			Revision: w.root, Generation: uint64(1 + fs.Restarts), Document: []byte(fs.Document), CreatedAt: created,
		}}
		if fs.ExitCode != nil {
			c := *fs.ExitCode
			e.view.ExitCode = &c
		}
		if s.Lifetime == LifetimeTemp {
			e.view.ExpiresAt, e.view.GraceSeconds = created+int64(s.TTL/time.Second), int(s.Grace/time.Second)
			if fs.Attached == 0 {
				e.view.DisconnectedAt = base.Unix()
			}
		}
		w.standalones[fs.Tenant+"/"+s.Name] = e
	}
}
