// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
)

// A task's DNS dependency points to a stable service lifetime/address, not to
// every TTL/view revision. Only a currently owned same-generation DNS service
// may retain this original reference. Native preparation/readiness is separate.
func annotateDNSBindings(b *Blueprint, ctx PlanningContext) {
	producers := map[string]Step{}
	for _, s := range b.d.Steps {
		producers[s.Key] = s
	}
	for i, task := range b.d.Steps {
		if task.Kind != "task" || !task.BasePresent {
			continue
		}
		var old GoalCommand
		current := ctx.Current[task.Key]
		if !current.Present || json.Unmarshal([]byte(current.Value), &old) != nil || old.Lifecycle != nil || old.Cluster != b.d.Cluster || old.Tenant != b.d.Tenant || old.App != b.d.App || old.Deployment != b.d.Deployment || old.Owner != task.Owner || old.Node != task.Node || old.Kind != task.Kind || !bytes.Equal(old.Config, task.Goal) || !bytes.Equal(goal(old.Activation), goal(task.Activation)) {
			continue
		}
		for _, dep := range task.Dependencies {
			producer := producers[dep.Key]
			source := ctx.Current[dep.Key]
			if producer.Kind != "dns" || !producer.BasePresent || !source.Present {
				continue
			}
			var wanted, before DNSDeclaration
			var g GoalCommand
			if json.Unmarshal(producer.Goal, &wanted) != nil || !wanted.Enabled || json.Unmarshal([]byte(source.Value), &g) != nil || g.Lifecycle != nil || g.Cluster != b.d.Cluster || g.Tenant != b.d.Tenant || g.App != b.d.App || g.Deployment != b.d.Deployment || g.Kind != "dns" || g.Node != producer.Node || g.Owner != producer.Owner || json.Unmarshal(g.Config, &before) != nil || !before.Enabled {
				continue
			}
			index := slices.IndexFunc(old.Dependencies, func(ref ObjectRef) bool { return ref.Key == dep.Key })
			if index < 0 {
				continue
			}
			ref := old.Dependencies[index]
			if ref.Generation != source.Generation || ref.Generation == 0 || ref.Revision < ref.Generation || ref.Revision > source.Revision {
				continue
			}
			b.d.Steps[i].StableDNS = append(b.d.Steps[i].StableDNS, ref)
		}
	}
}
func stableDNSReference(task Step, producer Step, ref ObjectRef) bool {
	if task.Kind != "task" || producer.Kind != "dns" || !producer.BasePresent || ref.Generation != producer.Base.Generation {
		return false
	}
	return slices.Contains(task.StableDNS, ref)
}
func validDNSBindings(steps []Step) bool {
	producers := map[string]Step{}
	for _, s := range steps {
		producers[s.Key] = s
	}
	for _, s := range steps {
		if len(s.StableDNS) > len(s.Dependencies) || len(s.StableDNS) > 0 && (s.Kind != "task" || !s.BasePresent) {
			return false
		}
		prior := -1
		for _, ref := range s.StableDNS {
			at := slices.IndexFunc(s.Dependencies, func(d Dependency) bool { return d.Key == ref.Key })
			p := producers[ref.Key]
			var cfg DNSDeclaration
			if at <= prior || ref.Generation == 0 || ref.Revision < ref.Generation || ref.Revision > p.Base.Revision || !stableDNSReference(s, p, ref) || json.Unmarshal(p.Goal, &cfg) != nil || !cfg.Enabled {
				return false
			}
			prior = at
		}
	}
	return true
}
