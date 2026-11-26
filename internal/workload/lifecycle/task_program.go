// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"slices"
)

// TaskProgram is a self-contained projection for the native owner. It retains
// local checks, the coordinator's app checks and only their exact sources.
// The global digest is checked against FrozenProgram at Blueprint acceptance.
type TaskProgram struct {
	Schema          uint8
	Cluster         [32]byte
	Program         [32]byte
	Tenant, Service string
	Coordinator     string
	Services        []string
	Policy          TenantPolicy
	Checks          []ResolvedCheck
	AppChecks       []ResolvedCheck `json:",omitempty"`
	Scripts         map[string]ScriptSelection
	Sources         map[string]SourceFact
}

func (f FrozenProgram) Task(service string) (TaskProgram, error) {
	checks, exists := f.Program.Services[service]
	if f.Schema != 1 || !exists || len(f.Program.Services) == 0 {
		return TaskProgram{}, ErrReference
	}
	services := make([]string, 0, len(f.Program.Services))
	for id := range f.Program.Services {
		services = append(services, id)
	}
	slices.Sort(services)
	out := TaskProgram{Schema: 1, Cluster: f.Cluster, Program: f.Digest(), Tenant: f.Tenant, Service: service,
		Coordinator: services[0], Services: services, Policy: f.Policy.Clone(),
		Checks: checks, Scripts: map[string]ScriptSelection{}, Sources: map[string]SourceFact{}}
	if service == out.Coordinator {
		out.AppChecks = f.Program.Checks
	}
	all := append(slices.Clone(out.Checks), out.AppChecks...)
	for _, c := range all {
		if c.Script == "" {
			continue
		}
		script, ok := f.Program.Scripts[c.Script]
		fact, found := f.Sources[c.Script]
		if !ok || !found {
			return TaskProgram{}, ErrReference
		}
		out.Scripts[c.Script], out.Sources[c.Script] = script, fact
	}
	return out.Clone(), nil
}

func (t TaskProgram) Clone() TaskProgram {
	raw, _ := json.Marshal(t)
	var out TaskProgram
	_ = json.Unmarshal(raw, &out)
	return out
}

func (t TaskProgram) Selection() (*Selection, error) {
	checks := append(slices.Clone(t.Checks), t.AppChecks...)
	return selectProgramSources(checks, t.Scripts, t.Sources, t.Policy.Revision)
}

func (t TaskProgram) Validate(cluster [32]byte) error {
	if t.Schema != 1 || t.Cluster != cluster || t.Program == ([32]byte{}) || cluster == ([32]byte{}) || !name(t.Tenant) || t.Policy.Tenant != t.Tenant || t.Policy.Validate() != nil || !t.Policy.Enabled || len(t.Services) == 0 || len(t.Services) > MaxTargets || !slices.IsSorted(t.Services) || t.Coordinator != t.Services[0] || !slices.Contains(t.Services, t.Service) || t.Service != t.Coordinator && len(t.AppChecks) != 0 || len(t.Scripts) != len(t.Sources) || len(t.Scripts) > MaxScripts {
		return ErrContract
	}
	services := map[string][]Check{}
	for i, id := range t.Services {
		if !name(id) || i > 0 && id == t.Services[i-1] {
			return ErrContract
		}
		services[id] = nil
	}
	if err := validateResolvedChecks(t.Service, t.Checks, services, t.Scripts, t.Policy.Execution.TimeoutMS); err != nil {
		return err
	}
	if err := validateResolvedChecks("", t.AppChecks, services, t.Scripts, t.Policy.Execution.TimeoutMS); err != nil {
		return err
	}
	used := map[string]bool{}
	for _, c := range append(slices.Clone(t.Checks), t.AppChecks...) {
		if c.Script != "" {
			used[c.Script] = true
		}
	}
	if len(used) != len(t.Scripts) {
		return ErrReference
	}
	for alias, s := range t.Scripts {
		fact, ok := t.Sources[alias]
		if !name(alias) || !ok || !used[alias] || fact.Cluster != cluster || !t.Policy.AllowsSource(fact) || s.Source != "" || s.Compile && len(t.Policy.Build.Nodes) == 0 || s.Ref != nil && (!name(s.Ref.Name) || s.Ref.Revision == 0) {
			return ErrReference
		}
		content := fact.ContentDigest()
		if s.Digest != hex.EncodeToString(content[:]) {
			return ErrReference
		}
	}
	_, err := t.Selection()
	return err
}

func (t TaskProgram) ValidateCatalog(c Catalog) error {
	if err := t.Validate(c.Cluster()); err != nil {
		return err
	}
	return validateProgramCatalog(t.Cluster, t.Tenant, t.Policy, t.Scripts, t.Sources, c)
}

// Compare with the same builtin resolver and script parameter validator used
// by declaration resolution. No catalog, source or Active bit is synthesized.
func validateResolvedChecks(scope string, checks []ResolvedCheck, services map[string][]Check, scripts map[string]ScriptSelection, maxTimeout int64) error {
	if len(checks) > 128 {
		return ErrContract
	}
	seen := map[string]bool{}
	hasActions := false
	for _, c := range checks {
		fresh, err := addTime(c.Timing.IntervalMS, c.Timing.TimeoutMS)
		if !name(c.ID) || seen[c.ID] || !validPhase(c.Phase) || !c.Timing.valid() || err != nil || c.Timing.FreshForMS != fresh || c.Timing.TimeoutMS > maxTimeout || !validCheckActions(scope, c.Phase, c.Actions) || c.Actions != nil && hasActions {
			return ErrContract
		}
		if c.Actions != nil {
			hasActions = true
		}
		seen[c.ID] = true
		if c.Script != "" {
			if c.Builtin != nil {
				return ErrContract
			}
			if _, ok := scripts[c.Script]; !ok {
				return ErrReference
			}
			raw, err := json.Marshal(c.Parameters)
			if err != nil {
				return ErrContract
			}
			if _, err := resolveScriptParameters(raw); err != nil {
				return err
			}
			continue
		}
		if c.Builtin == nil || c.Parameters != nil {
			return ErrContract
		}
		var parameters any
		switch c.Builtin.Kind {
		case "docker_health":
			parameters = struct{}{}
		case "healthz":
			if c.Builtin.HTTP != nil {
				parameters = HTTPParameters(*c.Builtin.HTTP)
			}
		case "cmd":
			if c.Builtin.Exec != nil {
				parameters = ExecParameters(*c.Builtin.Exec)
			}
		case "file":
			parameters = c.Builtin.File
		case "depends_on":
			parameters = c.Builtin.Dependency
		default:
			return ErrContract
		}
		raw, err := json.Marshal(parameters)
		if err != nil {
			return ErrContract
		}
		b, err := resolveBuiltin(Template{Builtin: c.Builtin.Kind, Parameters: raw}, scope, services)
		if err != nil {
			return err
		}
		a, _ := json.Marshal(c.Builtin)
		canonical, _ := json.Marshal(b)
		if !bytes.Equal(a, canonical) {
			return ErrContract
		}
	}
	return nil
}
