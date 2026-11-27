// SPDX-License-Identifier: Apache-2.0

package control

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/lifecycle"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
)

const StandaloneTempLimitUser = 8
const StandaloneLimitTenant = 32
const StandaloneLimitNode = 64

// StandaloneMetadata is the explicit tenant-workload owner kind. Scope remains
// immutable across public renames and temp→fixed pin; it is never a public app.
type StandaloneMetadata struct {
	Name, Scope, Creator, Node         string
	Lifetime, Mode, Restart, Desired   string
	Connections                        int
	DisconnectedAt, ConnectionAt       int64
	Cleanup                            *StandalonePolicyReport `json:",omitempty"`
	Revision                           uint64
	CreatedAt, ExpiresAt, GraceSeconds int64
	LastChange                         *UserOperation `json:",omitempty"`
	LastExtension                      *UserOperation `json:",omitempty"`
}
type StandaloneDefinition struct {
	Name, Lifetime, Mode, Restart string
	TTLSeconds, GraceSeconds      int64
}
type StandaloneChange struct {
	Tenant, Name, NewName, Restart, Operation string
	Target                                    *[32]byte `json:",omitempty"`
}
type StandaloneQuery struct{ Name string }
type StandaloneView struct {
	Target           [32]byte
	Tasks            []TaskView `json:",omitempty"`
	Metadata         StandaloneMetadata
	Definition       *deployment.AppDocument
	Workload         AppView
	RemainingSeconds int64
}

func (q StandaloneDefinition) metadata(tenant, user, node string, at int64) (StandaloneMetadata, error) {
	if !lifecycle.ValidID(q.Name) || !lifecycle.ValidID(user) || !lifecycle.ValidID(node) || at <= 0 {
		return StandaloneMetadata{}, access.ErrInvalid
	}
	if q.Lifetime == "" {
		q.Lifetime = "temp"
	}
	if q.Mode == "" {
		q.Mode = "entrypoint"
	}
	if q.Mode != "shell" && q.Mode != "entrypoint" {
		return StandaloneMetadata{}, access.ErrInvalid
	}
	m := StandaloneMetadata{Name: q.Name, Scope: deployment.StandaloneScopeName(tenant, q.Name), Creator: user, Node: node, Lifetime: q.Lifetime, Mode: q.Mode, Restart: q.Restart, Desired: "running", Revision: 1, CreatedAt: at, GraceSeconds: q.GraceSeconds}
	if q.Lifetime == "temp" {
		if q.Restart != "" && q.Restart != "no" {
			return m, access.ErrInvalid
		}
		m.Restart = "no"
		ttl := q.TTLSeconds
		if ttl == 0 {
			ttl = 3600
		}
		if ttl < 1 || ttl > 86400 {
			return m, access.ErrInvalid
		}
		if m.GraceSeconds == 0 {
			m.GraceSeconds = 600
		}
		if m.GraceSeconds < 1 || m.GraceSeconds > 86400 || at > int64(^uint64(0)>>1)-ttl {
			return m, access.ErrInvalid
		}
		m.ExpiresAt = at + ttl
	} else if q.Lifetime == "fixed" {
		if q.TTLSeconds != 0 || q.GraceSeconds != 0 {
			return m, access.ErrInvalid
		}
		if m.Restart == "" {
			m.Restart = "on-failure"
		}
		if m.Restart != "no" && m.Restart != "on-failure" && m.Restart != "always" {
			return m, access.ErrInvalid
		}
	} else {
		return m, access.ErrInvalid
	}
	return m, nil
}
func validStandaloneMetadata(m *StandaloneMetadata, scope deployment.AppScope) bool {
	if m == nil {
		return true
	}
	if m.Connections < 0 || m.Connections > 64 || m.ConnectionAt < 0 || m.DisconnectedAt < 0 || (m.Desired != "running" && m.Desired != "stopped") || !lifecycle.ValidID(m.Name) || m.Scope != scope.App || !strings.HasPrefix(m.Scope, "standalone-") || !lifecycle.ValidID(m.Creator) || !lifecycle.ValidID(m.Node) || m.Revision == 0 || m.CreatedAt <= 0 {
		return false
	}
	if m.LastChange != nil {
		var q StandaloneChange
		op := *m.LastChange
		if m.Lifetime != "fixed" || op.Change.Action != "standalone-pin" || op.VerifyOriginal(scope.Cluster) != nil || canonical(op.Change.Payload, &q) != nil || q.Tenant != scope.Tenant || op.Change.Expected >= m.Revision || op.At < m.CreatedAt || (q.NewName != "" && q.NewName != m.Name) || (q.NewName == "" && q.Name != m.Name) {
			return false
		}
	}
	if m.Lifetime == "temp" {
		if m.Restart != "no" || m.ExpiresAt <= m.CreatedAt || m.ExpiresAt-m.CreatedAt > 86400 || m.GraceSeconds < 1 || m.GraceSeconds > 86400 {
			return false
		}
	} else if m.Lifetime != "fixed" || m.ExpiresAt != 0 || m.GraceSeconds != 0 || m.Restart != "no" && m.Restart != "on-failure" && m.Restart != "always" {
		return false
	}
	return (m.Mode == "shell" || m.Mode == "entrypoint") && validStandaloneExtension(m, scope)
}
func (a Apps) standalone(tenant, name string) (string, appEntry, bool) {
	for key, e := range a.entries {
		if e.Standalone != nil && e.Inventory.Scope().Tenant == tenant && e.Standalone.Name == name {
			return key, e, true
		}
	}
	return "", appEntry{}, false
}

// StandaloneScope resolves only the explicit tenant owner kind. Callers cannot
// use an app name or guess an internal hashed workload name to cross the kind.
func (a Apps) StandaloneScope(tenant, name string) (string, bool) {
	_, e, ok := a.standalone(tenant, name)
	if !ok {
		return "", false
	}
	return e.Inventory.Scope().App, true
}
func (a Apps) StandaloneName(tenant, scope string) (string, bool) {
	e, ok := a.entries[appKey(tenant, scope)]
	if !ok || e.Standalone == nil {
		return "", false
	}
	return e.Standalone.Name, true
}
func (a Apps) IsStandalone(tenant, scope string) bool {
	e, ok := a.entries[appKey(tenant, scope)]
	return ok && e.Standalone != nil
}

func (p Policy) StandalonePage(s state.State, session access.Session, at int64, tenant, name, after string) ([]StandaloneView, string, error) {
	p, err := p.Current(s)
	if err != nil {
		return nil, "", err
	}
	c, err := p.Catalog(s)
	if err != nil || c.AuthorizeSession(session, p.Cluster, p.Issuer(session.Issuer), at, tenant, access.Read, "") != nil {
		return nil, "", access.ErrDenied
	}
	if name != "" && !lifecycle.ValidID(name) || after != "" && !lifecycle.ValidID(after) {
		return nil, "", access.ErrInvalid
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return nil, "", err
	}
	var keys []string
	for key, e := range a.entries {
		if e.Standalone != nil && e.Inventory.Scope().Tenant == tenant && e.Standalone.Name > after && (name == "" || name == e.Standalone.Name) {
			keys = append(keys, key)
		}
	}
	slices.SortFunc(keys, func(x, y string) int {
		return strings.Compare(a.entries[x].Standalone.Name, a.entries[y].Standalone.Name)
	})
	var out []StandaloneView
	next := ""
	for _, key := range keys {
		if len(out) == 8 {
			next = out[len(out)-1].Metadata.Name
			break
		}
		e := a.entries[key]
		m := *e.Standalone
		m.LastChange = nil
		m.LastExtension = nil
		v := StandaloneView{Target: e.standaloneTarget(), Metadata: m, Workload: appView(e, e.Inventory.Scope())}
		page, err := p.TaskPage(s, session, at, TaskSelection{Tenant: tenant, Standalone: m.Name}, "")
		if err != nil {
			return nil, "", err
		}
		v.Tasks = page.Tasks
		if x, ok := e.Inventory.Execution(); ok {
			v.Definition = x.Blueprint().OriginalDocument()
			if v.Definition != nil {
				v.Definition.Body = nil
			}
		}
		if m.Lifetime == "temp" {
			v.RemainingSeconds = max(0, m.ExpiresAt-at)
		}
		out = append(out, v)
	}
	return out, next, nil
}

func (p Policy) reduceStandalonePin(s state.State, a Apps, op UserOperation) (map[string][]byte, state.Code) {
	var q StandaloneChange
	if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Tenant) || !lifecycle.ValidID(q.Name) || !lifecycle.ValidID(q.Operation) || q.NewName != "" && !lifecycle.ValidID(q.NewName) {
		return nil, state.Invalid
	}
	key, e, ok := a.standalone(q.Tenant, q.Name)
	if !ok || !standaloneChangeMatches(e, op, q) || e.Standalone.Lifetime != "temp" || e.Standalone.Cleanup != nil || e.Down != nil {
		return nil, state.ConditionFailed
	}
	if q.Restart == "" {
		q.Restart = "on-failure"
	}
	if q.Restart != "no" && q.Restart != "on-failure" && q.Restart != "always" {
		return nil, state.Invalid
	}
	if q.NewName != "" && q.NewName != q.Name {
		if _, _, exists := a.standalone(q.Tenant, q.NewName); exists {
			return nil, state.ConditionFailed
		}
	}
	m := *e.Standalone
	if m.ExpiresAt <= op.At {
		return nil, state.ConditionFailed
	}
	m.Lifetime = "fixed"
	m.ExpiresAt, m.GraceSeconds, m.DisconnectedAt = 0, 0, 0
	m.Restart = q.Restart
	if q.NewName != "" {
		m.Name = q.NewName
	}
	m.Revision++
	m.LastChange = &op
	e.Standalone = &m
	a.entries[key] = e
	return p.appsCheckpoint(s, a, uint64(op.At))
}

func (p Policy) authorizeStandalone(c access.Catalog, op UserOperation) error {
	var q StandaloneChange
	if canonical(op.Change.Payload, &q) != nil || !lifecycle.ValidID(q.Tenant) || !lifecycle.ValidID(q.Name) {
		return access.ErrInvalid
	}
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.Deploy, "")
}

func standaloneQuota(a Apps, tenant, user, node, lifetime string) error {
	users, tenants, nodes := 0, 0, 0
	for _, e := range a.entries {
		if e.Standalone == nil {
			continue
		}
		m := e.Standalone
		if e.Inventory.Quiescent() && (e.Down != nil || e.Standalone.Cleanup != nil) {
			continue
		}
		if m.Node == node {
			nodes++
		}
		if e.Inventory.Scope().Tenant == tenant {
			tenants++
			if m.Creator == user && m.Lifetime == "temp" {
				users++
			}
		}
	}
	if lifetime != "fixed" && users >= StandaloneTempLimitUser {
		return &deployment.InputError{Code: "STANDALONE_USER_LIMIT", Path: "standalone"}
	}
	if tenants >= StandaloneLimitTenant {
		return &deployment.InputError{Code: "STANDALONE_TENANT_LIMIT", Path: "standalone"}
	}
	if nodes >= StandaloneLimitNode {
		return &deployment.InputError{Code: "STANDALONE_NODE_LIMIT", Path: "standalone"}
	}
	return nil
}

func standaloneDefinition(raw json.RawMessage) (StandaloneDefinition, error) {
	var q StandaloneDefinition
	err := canonical(raw, &q)
	return q, err
}

func (a Apps) StandaloneStopped(tenant, scope string) bool {
	e, ok := a.entries[appKey(tenant, scope)]
	return ok && e.Standalone != nil && e.Standalone.Desired == "stopped"
}
