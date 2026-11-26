// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"maps"
	"math"
	"slices"

	"github.com/jay94ks/mydcd/internal/schema"
	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
	"gopkg.in/yaml.v3"
)

// These are declaration DTOs, not accepted source facts or native commands.
// Conversion below feeds the same Program used by the actual checker core.
type LifecycleDeclaration struct {
	Optimizer *LifecycleOptimizer          `yaml:"optimizer,omitempty" json:",omitempty"`
	Scripts   map[string]checker.Script    `yaml:"scripts,omitempty" json:",omitempty"`
	Templates map[string]LifecycleTemplate `yaml:"templates,omitempty" json:",omitempty"`
	Checks    []LifecycleCheck             `yaml:"checks,omitempty" json:",omitempty"`
}

type LifecycleOptimizer struct {
	Compile bool `yaml:"compile"`
}

type ServiceLifecycle struct {
	Checks []LifecycleCheck `yaml:"checks"`
}

type LifecycleTemplate struct {
	Builtin    string              `yaml:"builtin,omitempty" json:",omitempty"`
	Script     string              `yaml:"script,omitempty" json:",omitempty"`
	Parameters LifecycleParameters `yaml:"parameters,omitempty" json:",omitempty"`
}

type LifecycleCheck struct {
	ID                string         `yaml:"id"`
	Use               string         `yaml:"use,omitempty" json:",omitempty"`
	Phase             contract.Phase `yaml:"phase"`
	LifecycleTemplate `yaml:",inline"`
	Interval          string                `yaml:"interval,omitempty" json:",omitempty"`
	Timeout           string                `yaml:"timeout,omitempty" json:",omitempty"`
	StartPeriod       string                `yaml:"start_period,omitempty" json:",omitempty"`
	Retries           *uint32               `yaml:"retries,omitempty" json:",omitempty"`
	Actions           *checker.ActionPolicy `yaml:"actions,omitempty" json:",omitempty"`
}

// Parameters stay JSON bytes so typed builtin validation never goes through
// an untyped JSON float64 conversion. Absent and explicit {} remain distinct
// when the core checks conflicting template parameters.
type LifecycleParameters json.RawMessage

func (p *LifecycleParameters) UnmarshalJSON(raw []byte) error {
	value, err := schema.InputLimit[map[string]json.RawMessage](raw, 32<<10)
	if err != nil || value == nil {
		return ErrInputs
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ErrInputs
	}
	*p = LifecycleParameters(canonical)
	return nil
}

func (p LifecycleParameters) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}
	var checked LifecycleParameters
	if err := checked.UnmarshalJSON(p); err != nil {
		return nil, err
	}
	return bytes.Clone(checked), nil
}

func (p *LifecycleParameters) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return ErrInputs
	}
	var value map[string]any
	if err := n.Decode(&value); err != nil {
		return ErrInputs
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrInputs
	}
	return p.UnmarshalJSON(raw)
}

func (p LifecycleParameters) MarshalYAML() (any, error) {
	if p == nil {
		return nil, nil
	}
	raw, err := p.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var tree yaml.Node
	if yaml.Unmarshal(raw, &tree) != nil || len(tree.Content) != 1 {
		return nil, ErrInputs
	}
	return tree.Content[0], nil
}

func (t LifecycleTemplate) programTemplate() checker.Template {
	return checker.Template{Builtin: t.Builtin, Script: t.Script, Parameters: bytes.Clone(t.Parameters)}
}

func lifecycleChecks(in []LifecycleCheck) []checker.Check {
	var out []checker.Check
	for _, c := range in {
		var retries *uint32
		if c.Retries != nil {
			v := *c.Retries
			retries = &v
		}
		var actions *checker.ActionPolicy
		if c.Actions != nil {
			copy := *c.Actions
			actions = &copy
		}
		out = append(out, checker.Check{ID: c.ID, Use: c.Use, Phase: c.Phase, Actions: actions,
			Template: c.programTemplate(), Interval: c.Interval, Timeout: c.Timeout,
			StartPeriod: c.StartPeriod, Retries: retries})
	}
	return out
}

func lifecycleTiming() checker.Timing {
	return checker.Timing{IntervalMS: 10000, TimeoutMS: 3000, Retries: 3, FreshForMS: 13000}
}

func (c Compose) hasLifecycle() bool {
	if c.MyDC.Lifecycle != nil {
		return true
	}
	for _, service := range c.Services {
		if service.MyDC.Lifecycle != nil {
			return true
		}
	}
	return false
}

// LifecycleProgram owns its returned declarations. It checks shape, bounds and
// scope with the product core without querying or fabricating a named catalog.
// The current catalog/policy is required separately by ResolveLifecycle.
func (c Compose) LifecycleProgram() (checker.Program, bool, error) {
	if !c.hasLifecycle() {
		return checker.Program{}, false, nil
	}
	p := checker.Program{Services: map[string][]checker.Check{}}
	present := c.MyDC.Lifecycle != nil
	if d := c.MyDC.Lifecycle; d != nil {
		p.Compile = d.Optimizer != nil && d.Optimizer.Compile
		if d.Scripts != nil {
			p.Scripts = make(map[string]checker.Script, len(d.Scripts))
		}
		for alias, s := range d.Scripts {
			s.Modules = slices.Clone(s.Modules)
			if s.Ref != nil {
				r := *s.Ref
				s.Ref = &r
			}
			if s.Compile != nil {
				v := *s.Compile
				s.Compile = &v
			}
			p.Scripts[alias] = s
		}
		if d.Templates != nil {
			p.Templates = make(map[string]checker.Template, len(d.Templates))
		}
		for alias, t := range d.Templates {
			p.Templates[alias] = t.programTemplate()
		}
		p.Checks = lifecycleChecks(d.Checks)
	}
	for service, d := range c.Services {
		p.Services[service] = nil
		if d.MyDC.Lifecycle != nil {
			present = true
			p.Services[service] = lifecycleChecks(d.MyDC.Lifecycle.Checks)
		}
	}
	if present {
		edges, err := checker.CheckProgram(p, lifecycleTiming(), math.MaxInt64)
		if err != nil {
			return checker.Program{}, true, inputError("INVALID_LIFECYCLE", "x-mydc.lifecycle")
		}
		// Use the existing service DAG for both kinds of dependency, without
		// mutating the original Compose condition or inventing a healthcheck.
		services := maps.Clone(c.Services)
		for service, deps := range edges {
			s := services[service]
			s.DependsOn = maps.Clone(s.DependsOn)
			if s.DependsOn == nil {
				s.DependsOn = Dependencies{}
			}
			for _, dependency := range deps {
				if _, exists := s.DependsOn[dependency]; !exists {
					s.DependsOn[dependency] = ServiceDependency{Condition: "service_started"}
				}
			}
			services[service] = s
		}
		if _, err := serviceOrder(services); err != nil {
			return checker.Program{}, true, err
		}
	}
	return p, present, nil
}

// ResolveLifecycle binds exact named revisions and timing to the current
// tenant policy. This is still a plan, never a source/native readiness fact.
func (c Compose) ResolveLifecycle(catalog checker.Catalog) (checker.ResolvedProgram, error) {
	p, present, err := c.LifecycleProgram()
	if err != nil || !present {
		return checker.ResolvedProgram{}, err
	}
	policy, ok := catalog.Policy(c.MyDC.Tenant, 0)
	if !ok || !policy.Enabled {
		return checker.ResolvedProgram{}, inputError("LIFECYCLE_POLICY_REQUIRED", "x-mydc.lifecycle")
	}
	resolved, err := checker.ResolveProgram(c.MyDC.Tenant, p, catalog.Sources(c.MyDC.Tenant), lifecycleTiming(), policy.Execution.TimeoutMS)
	if err != nil {
		return checker.ResolvedProgram{}, err
	}
	for _, selected := range resolved.Scripts {
		if selected.Compile && len(policy.Build.Nodes) == 0 {
			return checker.ResolvedProgram{}, inputError("LIFECYCLE_BUILDER_REQUIRED", "x-mydc.lifecycle")
		}
		if selected.Ref != nil {
			record, ok := catalog.Script(c.MyDC.Tenant, selected.Ref.Name)
			allowed := false
			if ok {
				for _, version := range record.Versions {
					if version.Revision == selected.Ref.Revision && version.Active && !version.Deleted && policy.AllowsSource(version.Source) {
						allowed = true
					}
				}
			}
			if !allowed {
				return checker.ResolvedProgram{}, inputError("LIFECYCLE_SOURCE_FORBIDDEN", "x-mydc.lifecycle")
			}
		}
	}
	return resolved, nil
}

// A null extension cannot silently become the absent/default declaration.
func lifecycleSubset(root *yaml.Node) error {
	check := func(n *yaml.Node) error {
		x := nodeField(nodeField(n, "x-mydc"), "lifecycle")
		if x == nil {
			return nil
		}
		if x.Kind != yaml.MappingNode {
			return inputError("LIFECYCLE_MAPPING_REQUIRED", "x-mydc.lifecycle")
		}
		var walk func(*yaml.Node) error
		walk = func(n *yaml.Node) error {
			if n.Tag == "!!null" {
				return inputError("LIFECYCLE_NULL_FORBIDDEN", "x-mydc.lifecycle")
			}
			for _, child := range n.Content {
				if err := walk(child); err != nil {
					return err
				}
			}
			return nil
		}
		return walk(x)
	}
	if err := check(root); err != nil {
		return err
	}
	if services := nodeField(root, "services"); services != nil && services.Kind == yaml.MappingNode {
		for i := 1; i < len(services.Content); i += 2 {
			if err := check(services.Content[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

// Only source text at the exact declared path is literal code. All remaining
// Compose strings retain the existing no-interpolation input contract.
func lifecycleLiteralSources(tree *yaml.Node) map[*yaml.Node]bool {
	result := map[*yaml.Node]bool{}
	if len(tree.Content) != 1 {
		return result
	}
	scripts := nodeField(nodeField(nodeField(tree.Content[0], "x-mydc"), "lifecycle"), "scripts")
	if scripts != nil && scripts.Kind == yaml.MappingNode {
		for i := 1; i < len(scripts.Content); i += 2 {
			if source := nodeField(scripts.Content[i], "source"); source != nil && source.Kind == yaml.ScalarNode && source.Tag == "!!str" {
				result[source] = true
			}
		}
	}
	return result
}
