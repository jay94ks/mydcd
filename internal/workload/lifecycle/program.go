// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"encoding/json"
	"maps"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Template selects one implementation. It deliberately cannot refer to another
// template, so use does not create a second inheritance/merge language.
type Template struct {
	Builtin    string
	Script     string
	Parameters json.RawMessage
}

type Check struct {
	ID, Use                        string
	Phase                          contract.Phase
	Template                       // one explicit selector, or Use
	Interval, Timeout, StartPeriod string
	Retries                        *uint32
	Actions                        *ActionPolicy `json:",omitempty"`
}

type Program struct {
	Compile   bool
	Scripts   map[string]Script
	Templates map[string]Template
	Checks    []Check
	Services  map[string][]Check
}

type HTTPParameters struct {
	Service        string `json:"service"`
	Path           string `json:"path"`
	Method         string `json:"method"`
	Port           uint16 `json:"port"`
	TLS            bool   `json:"tls"`
	ExpectedStatus []int  `json:"expected_status"`
	MaxBytes       int    `json:"max_bytes"`
}

type ExecParameters struct {
	Service  string   `json:"service"`
	Argv     []string `json:"argv"`
	MaxBytes int      `json:"max_bytes"`
}

type FileCondition struct {
	Service       string  `json:"service"`
	Path          string  `json:"path"`
	Kind          string  `json:"kind"`
	Mode          *uint32 `json:"mode"`
	ContentDigest string  `json:"content_digest"`
}

type DependencyCondition struct {
	Services  []string `json:"services"`
	Condition string   `json:"condition"`
}

type Builtin struct {
	Kind       string
	HTTP       *contract.HTTPProbe
	Exec       *contract.ExecProbe
	File       *FileCondition
	Dependency *DependencyCondition
}

type ResolvedCheck struct {
	ID         string
	Phase      contract.Phase
	Timing     Timing
	Builtin    *Builtin
	Script     string
	Parameters map[string]string
	Actions    *ActionPolicy `json:",omitempty"`
}

type ResolvedProgram struct {
	Scripts  map[string]ScriptSelection
	Checks   []ResolvedCheck
	Services map[string][]ResolvedCheck
	// The app planner merges these edges into its existing dependency DAG;
	// resolution alone is not permission to bypass its cycle/health checks.
	Dependencies map[string][]string
}

func durationMS(raw string, fallback int64, zero bool) (int64, error) {
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 || !zero && d == 0 || d%time.Millisecond != 0 {
		return 0, ErrContract
	}
	return int64(d / time.Millisecond), nil
}

func resolveTiming(c Check, defaults Timing, maxTimeoutMS int64) (Timing, error) {
	t := defaults
	var err error
	if t.IntervalMS, err = durationMS(c.Interval, t.IntervalMS, false); err != nil {
		return Timing{}, err
	}
	if t.TimeoutMS, err = durationMS(c.Timeout, t.TimeoutMS, false); err != nil {
		return Timing{}, err
	}
	if t.StartPeriodMS, err = durationMS(c.StartPeriod, t.StartPeriodMS, true); err != nil {
		return Timing{}, err
	}
	if c.Retries != nil {
		t.Retries = *c.Retries
	}
	t.FreshForMS, err = addTime(t.IntervalMS, t.TimeoutMS)
	if err != nil || !t.valid() || t.TimeoutMS > maxTimeoutMS {
		return Timing{}, ErrContract
	}
	return t, nil
}

func parameterObject[T any](raw json.RawMessage) (T, error) {
	var zero T
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return zero, ErrContract
	}
	value, err := schema.InputLimit[T](raw, 32<<10)
	if err != nil {
		return zero, ErrContract
	}
	return value, nil
}

func scopedService(selected, scope string, services map[string][]Check) (string, error) {
	if selected == "" {
		selected = scope
	}
	if !name(selected) || scope != "" && selected != scope {
		return "", ErrContract
	}
	if _, ok := services[selected]; !ok {
		return "", ErrReference
	}
	return selected, nil
}

func resolveBuiltin(t Template, scope string, services map[string][]Check) (*Builtin, error) {
	b := &Builtin{Kind: t.Builtin}
	var err error
	switch t.Builtin {
	case "docker_health":
		if _, err := parameterObject[struct{}](t.Parameters); err != nil || scope == "" {
			return nil, ErrContract
		}
	case "healthz":
		parameters, e := parameterObject[HTTPParameters](t.Parameters)
		q := contract.HTTPProbe(parameters)
		if e != nil {
			return nil, ErrContract
		}
		q.Service, err = scopedService(q.Service, scope, services)
		if q.Method == "" {
			q.Method = "GET"
		}
		if len(q.ExpectedStatus) == 0 {
			q.ExpectedStatus = []int{200}
		}
		if q.MaxBytes == 0 {
			q.MaxBytes = 4096
		}
		u, parseErr := url.ParseRequestURI(q.Path)
		if err != nil || parseErr != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(q.Path, "\x00\r\n#") || !strings.HasPrefix(q.Path, "/") || strings.HasPrefix(q.Path, "//") || len(q.Path) > 2048 || q.Port == 0 || q.Method != "GET" && q.Method != "HEAD" || q.MaxBytes < 1 || q.MaxBytes > 1<<20 || len(q.ExpectedStatus) > 16 {
			return nil, ErrContract
		}
		slices.Sort(q.ExpectedStatus)
		for i, code := range q.ExpectedStatus {
			if code < 100 || code > 599 || i > 0 && code == q.ExpectedStatus[i-1] {
				return nil, ErrContract
			}
		}
		b.HTTP = &q
	case "cmd":
		parameters, e := parameterObject[ExecParameters](t.Parameters)
		q := contract.ExecProbe(parameters)
		if e != nil {
			return nil, ErrContract
		}
		q.Service, err = scopedService(q.Service, scope, services)
		if q.MaxBytes == 0 {
			q.MaxBytes = 4096
		}
		if err != nil || len(q.Argv) == 0 || len(q.Argv) > 128 || q.MaxBytes < 1 || q.MaxBytes > 1<<20 {
			return nil, ErrContract
		}
		for _, a := range q.Argv {
			if len(a) > 4096 || strings.ContainsAny(a, "\x00\r\n") {
				return nil, ErrContract
			}
		}
		if q.Argv[0] == "" {
			return nil, ErrContract
		}
		b.Exec = &q
	case "file":
		q, e := parameterObject[FileCondition](t.Parameters)
		if e != nil {
			return nil, ErrContract
		}
		q.Service, err = scopedService(q.Service, scope, services)
		if q.Kind == "" {
			q.Kind = "any"
		}
		if err != nil || !path.IsAbs(q.Path) || path.Clean(q.Path) != q.Path || q.Path == "/" || strings.ContainsAny(q.Path, "\x00\r\n") || len(q.Path) > 4096 || q.Kind != "regular" && q.Kind != "directory" && q.Kind != "any" || q.Mode != nil && *q.Mode > 07777 || q.ContentDigest != "" && (!digest(q.ContentDigest) || q.Kind != "regular") {
			return nil, ErrContract
		}
		b.File = &q
	case "depends_on":
		q, e := parameterObject[DependencyCondition](t.Parameters)
		if e != nil || len(q.Services) == 0 || len(q.Services) > MaxTargets || q.Condition != "service_started" && q.Condition != "service_healthy" && q.Condition != "service_completed_successfully" {
			return nil, ErrContract
		}
		slices.Sort(q.Services)
		for i, service := range q.Services {
			if !name(service) || service == scope || i > 0 && service == q.Services[i-1] {
				return nil, ErrContract
			}
			if _, ok := services[service]; !ok {
				return nil, ErrReference
			}
		}
		b.Dependency = &q
	default:
		return nil, ErrContract
	}
	return b, nil
}

func validTemplate(t Template) bool {
	if t.Script != "" {
		return t.Builtin == "" && name(t.Script)
	}
	switch t.Builtin {
	case "docker_health", "healthz", "cmd", "file", "depends_on":
		return true
	}
	return false
}

func resolveScriptParameters(raw json.RawMessage) (map[string]string, error) {
	parameters, err := parameterObject[map[string]string](raw)
	if err != nil || len(parameters) > 64 {
		return nil, ErrContract
	}
	total := 0
	for k, v := range parameters {
		if !name(k) || len(v) > 4096 || strings.ContainsRune(v, 0) {
			return nil, ErrContract
		}
		total += len(k) + len(v)
	}
	if total > 32<<10 {
		return nil, ErrContract
	}
	return maps.Clone(parameters), nil
}

// ResolveProgram joins app/service selections to the SAME run/timing/source
// contracts. It prepares no native resource. The planner must still validate
// the merged dependency DAG, current policy and source/artifact readiness.
func ResolveProgram(tenant string, p Program, named []NamedSource, defaults Timing, maxTimeoutMS int64) (ResolvedProgram, error) {
	selected, err := ResolveScripts(tenant, p.Compile, p.Scripts, named)
	if err != nil {
		return ResolvedProgram{}, err
	}
	out, err := resolveProgramChecks(p, defaults, maxTimeoutMS)
	if err != nil {
		return ResolvedProgram{}, err
	}
	out.Scripts = selected
	return out, nil
}

// CheckProgram checks declaration syntax and scoped checks without a tenant
// catalog or fabricated source facts. It proves no named source availability,
// policy permission, merged DAG validity, source staging or runner readiness.
// Returned dependency edges belong to the caller's existing service DAG.
func CheckProgram(p Program, defaults Timing, maxTimeoutMS int64) (map[string][]string, error) {
	if err := checkScripts(p.Scripts); err != nil {
		return nil, err
	}
	out, err := resolveProgramChecks(p, defaults, maxTimeoutMS)
	return out.Dependencies, err
}

func resolveProgramChecks(p Program, defaults Timing, maxTimeoutMS int64) (ResolvedProgram, error) {
	if !defaults.valid() || maxTimeoutMS <= 0 || len(p.Templates) > 128 || len(p.Checks) > 128 || len(p.Services) == 0 || len(p.Services) > MaxTargets {
		return ResolvedProgram{}, ErrContract
	}
	for alias, t := range p.Templates {
		if !name(alias) || !validTemplate(t) {
			return ResolvedProgram{}, ErrContract
		}
		if t.Script != "" {
			if _, ok := p.Scripts[t.Script]; !ok {
				return ResolvedProgram{}, ErrReference
			}
		}
	}
	count := len(p.Checks)
	for service, checks := range p.Services {
		if !name(service) {
			return ResolvedProgram{}, ErrContract
		}
		count += len(checks)
		if count > 256 {
			return ResolvedProgram{}, ErrContract
		}
	}
	out := ResolvedProgram{Services: map[string][]ResolvedCheck{}, Dependencies: map[string][]string{}}
	resolve := func(scope string, checks []Check) ([]ResolvedCheck, error) {
		if len(checks) > 128 {
			return nil, ErrContract
		}
		var result []ResolvedCheck
		seen := map[string]bool{}
		hasActions := false
		for _, c := range checks {
			if !name(c.ID) || !validPhase(c.Phase) || seen[c.ID] || !validCheckActions(scope, c.Phase, c.Actions) || c.Actions != nil && hasActions {
				return nil, ErrContract
			}
			seen[c.ID] = true
			t := c.Template
			if c.Use != "" {
				if t.Builtin != "" || t.Script != "" {
					return nil, ErrContract
				}
				base, ok := p.Templates[c.Use]
				if !ok || len(base.Parameters) != 0 && len(t.Parameters) != 0 {
					return nil, ErrReference
				}
				if len(t.Parameters) == 0 {
					t.Parameters = base.Parameters
				}
				t.Builtin, t.Script = base.Builtin, base.Script
			}
			if !validTemplate(t) {
				return nil, ErrContract
			}
			timing, err := resolveTiming(c, defaults, maxTimeoutMS)
			if err != nil {
				return nil, err
			}
			r := ResolvedCheck{ID: c.ID, Phase: c.Phase, Timing: timing, Script: t.Script}
			if c.Actions != nil {
				copy := *c.Actions
				r.Actions, hasActions = &copy, true
			}
			if t.Script != "" {
				if _, ok := p.Scripts[t.Script]; !ok {
					return nil, ErrReference
				}
				r.Parameters, err = resolveScriptParameters(t.Parameters)
				if err != nil {
					return nil, err
				}
			} else {
				r.Builtin, err = resolveBuiltin(t, scope, p.Services)
				if err != nil {
					return nil, err
				}
				if scope != "" && r.Builtin.Dependency != nil {
					out.Dependencies[scope] = append(out.Dependencies[scope], r.Builtin.Dependency.Services...)
				}
			}
			result = append(result, r)
		}
		return result, nil
	}
	var err error
	out.Checks, err = resolve("", p.Checks)
	if err != nil {
		return ResolvedProgram{}, err
	}
	for service, checks := range p.Services {
		out.Services[service], err = resolve(service, checks)
		if err != nil {
			return ResolvedProgram{}, err
		}
		deps := out.Dependencies[service]
		slices.Sort(deps)
		out.Dependencies[service] = slices.Compact(deps)
	}
	return out, nil
}
