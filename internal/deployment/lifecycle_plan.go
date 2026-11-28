// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"

	checker "github.com/jay94ks/seafield/internal/workload/lifecycle"
)

func freezeCheckerPlan(c Compose, ctx PlanningContext) (checker.FrozenProgram, error) {
	p, present, err := c.LifecycleProgram()
	if err != nil || !present || ctx.Checkers.Cluster() != ctx.Cluster {
		return checker.FrozenProgram{}, ErrInputs
	}
	frozen, err := checker.FreezeProgram(c.Sfc.Tenant, p, ctx.Checkers, ctx.CheckerSources, lifecycleTiming())
	if err != nil {
		return checker.FrozenProgram{}, err
	}
	for _, fact := range frozen.Sources {
		if !ctx.CheckerProviders[fact.Owner] {
			return checker.FrozenProgram{}, inputError("LIFECYCLE_PROVIDER_REQUIRED", "x-sfc.lifecycle")
		}
	}
	// Keep an accepted identity when only the policy sequence changed. The
	// current freeze above still checks active sources, policy and membership.
	scope := AppScope{ctx.Cluster, ctx.Actor, c.Sfc.Tenant, c.Name, c.Sfc.Deployment}
	if accepted, ok := ctx.CheckerPrograms[scope]; ok && accepted.ValidateCatalog(ctx.Checkers) == nil && accepted.Validate(p, ctx.Cluster, lifecycleTiming()) == nil {
		comparable := frozen.Clone()
		comparable.Policy.Revision = accepted.Policy.Revision
		if comparable.Digest() == accepted.Digest() {
			return accepted.Clone(), nil
		}
	}
	return frozen, nil
}

// CheckerProgram returns owned accepted metadata for subsequent planning. It
// supplies neither current permission nor readiness or a capacity credit.
func (b Blueprint) CheckerProgram() *checker.FrozenProgram {
	if b.d.Checkers == nil {
		return nil
	}
	copy := b.d.Checkers.Clone()
	return &copy
}

func (b Blueprint) inlineCheckerSources() map[string]checker.SourceFact {
	if b.d.Checkers == nil {
		return nil
	}
	out := map[string]checker.SourceFact{}
	for alias, script := range b.d.Checkers.Program.Scripts {
		if script.Ref == nil {
			out[alias] = b.d.Checkers.Sources[alias].Clone()
		}
	}
	return out
}

func (b Blueprint) frozenTask(service string, s ComposeService) (ComposeService, error) {
	s = frozenTaskService(s, b.d.FixedVolumes)
	s.SocketRevisions = b.d.SocketRevisions[service]
	if b.d.Checkers == nil {
		return s, nil
	}
	program, err := b.d.Checkers.Task(service)
	if err != nil {
		return ComposeService{}, err
	}
	if err = program.Validate(b.d.Cluster); err != nil {
		return ComposeService{}, err
	}
	selection, err := program.Selection()
	if err != nil {
		return ComposeService{}, err
	}
	s.LifecycleProgram, s.LifecycleSources = &program, selection
	return s, nil
}

func validCheckerPlan(d blueprintRecord) bool {
	p, present, err := d.Input.LifecycleProgram()
	if err != nil || present != (d.Checkers != nil) {
		return false
	}
	if d.Checkers != nil && (d.Checkers.Tenant != d.Tenant || d.Checkers.Validate(p, d.Cluster, lifecycleTiming()) != nil) {
		return false
	}
	return true
}

// Called by the existing Task goal decode in validPlanTaskMetadata, so legacy
// plans do not acquire a second per-Task JSON decode for absent lifecycle.
func validTaskCheckers(d blueprintRecord, id string, service, actual ComposeService) bool {
	if d.Checkers == nil {
		return actual.LifecycleProgram == nil && actual.LifecycleSources == nil
	}
	expected, err := (Blueprint{d}).frozenTask(id, service)
	if err != nil {
		return false
	}
	a, _ := json.Marshal(actual.LifecycleProgram)
	e, _ := json.Marshal(expected.LifecycleProgram)
	return bytes.Equal(a, e) && sameCheckerSelection(actual.LifecycleSources, expected.LifecycleSources)
}

func sameCheckerSelection(a, b *checker.Selection) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func (s ComposeService) hasReadiness() bool {
	if s.Healthcheck != nil && !s.Healthcheck.disabled() || s.Sfc.Readiness != nil {
		return true
	}
	if s.Sfc.Lifecycle != nil {
		for _, check := range s.Sfc.Lifecycle.Checks {
			if check.Phase == "startup" || check.Phase == "readiness" {
				return true
			}
		}
	}
	return false
}

// ValidateLifecycleCatalog is historical structural validation, never current
// admission. Current acceptance recompiles with the current policy/membership.
func (b Blueprint) ValidateLifecycleCatalog(c checker.Catalog) error {
	if b.d.Checkers == nil {
		return nil
	}
	if !validCheckerPlan(b.d) || !validPlanTaskMetadata(b.d) {
		return ErrInputs
	}
	return b.d.Checkers.ValidateCatalog(c)
}

// CheckLifecycleInputs joins a CLI's original inline preparation to the plan
// returned by the authenticated planner. It grants no current/native authority.
func (b Blueprint) CheckLifecycleInputs(original Compose, inline map[string]checker.SourceFact) error {
	p, present, err := original.LifecycleProgram()
	if err != nil || !present || b.d.Checkers == nil || b.d.Checkers.Validate(p, b.d.Cluster, lifecycleTiming()) != nil {
		return ErrInputs
	}
	count := 0
	for alias, script := range p.Scripts {
		if script.Ref != nil {
			continue
		}
		count++
		fact, ok := inline[alias]
		expected, found := b.d.Checkers.Sources[alias]
		a, _ := json.Marshal(fact)
		e, _ := json.Marshal(expected)
		if !ok || !found || !bytes.Equal(a, e) {
			return ErrInputs
		}
	}
	if count != len(inline) {
		return ErrInputs
	}
	return nil
}

func mergeCheckerDependencies(deps []Dependency, checks []checker.ResolvedCheck, key func(string, string) string) ([]Dependency, error) {
	for _, check := range checks {
		if check.Builtin == nil || check.Builtin.Dependency == nil {
			continue
		}
		d := check.Builtin.Dependency
		when, err := dependencyCondition(d.Condition)
		if err != nil {
			return nil, err
		}
		for _, service := range d.Services {
			wanted := key("task", service)
			found := false
			for i := range deps {
				if deps[i].Key == wanted {
					merged, err := mergeDependencyCondition(deps[i].Condition, when)
					if err != nil {
						return nil, err
					}
					deps[i].Condition = merged
					found = true
					break
				}
			}
			if !found {
				deps = append(deps, Dependency{wanted, when})
			}
		}
	}
	return deps, nil
}
