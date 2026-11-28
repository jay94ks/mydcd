// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"
)

// A consumer's dependency normally pins its producer's exact position
// (revision and generation), so any producer change makes it stale. Two
// producers change in place under the same generation and keep that
// position meaningful, so a consumer that is itself unchanged keeps its
// original reference (Step.Stable):
//
//   - a DNS service, for the Tasks that depend on it: they point to a stable
//     service lifetime/address, not to every TTL/view revision;
//   - a Task whose next goal changes only aliases (taskAliasOnly), only
//     its sfev.sock source revisions (taskSocketOnly) or only attaches
//     networks (taskNetworkGoalChange), for its inputs and the
//     Tasks that depend on it: the container and its projected files stay,
//     so they need not follow its new revision.
//
// Only a currently owned same-generation producer may be kept this way.
// Native preparation/readiness is separate.
func annotateStable(b *Blueprint, ctx PlanningContext) {
	producers := map[string]Step{}
	for _, s := range b.d.Steps {
		producers[s.Key] = s
	}
	for i, consumer := range b.d.Steps {
		if consumer.Kind != "task" && consumer.Kind != "inputs" || !consumer.BasePresent {
			continue
		}
		var old GoalCommand
		current := ctx.Current[consumer.Key]
		if !current.Present || json.Unmarshal([]byte(current.Value), &old) != nil || old.Lifecycle != nil || old.Cluster != b.d.Cluster || old.Tenant != b.d.Tenant || old.App != b.d.App || old.Deployment != b.d.Deployment || old.Owner != consumer.Owner || old.Node != consumer.Node || old.Kind != consumer.Kind || !bytes.Equal(old.Config, consumer.Goal) || !bytes.Equal(goal(old.Activation), goal(consumer.Activation)) {
			continue
		}
		for _, dep := range consumer.Dependencies {
			producer := producers[dep.Key]
			source := ctx.Current[dep.Key]
			if !producer.BasePresent || !source.Present {
				continue
			}
			var g GoalCommand
			if json.Unmarshal([]byte(source.Value), &g) != nil || g.Lifecycle != nil || g.Cluster != b.d.Cluster || g.Tenant != b.d.Tenant || g.App != b.d.App || g.Deployment != b.d.Deployment || g.Kind != producer.Kind || g.Node != producer.Node || g.Owner != producer.Owner {
				continue
			}
			switch {
			case producer.Kind == "dns" && consumer.Kind == "task":
				var wanted, before DNSDeclaration
				if json.Unmarshal(producer.Goal, &wanted) != nil || !wanted.Enabled || json.Unmarshal(g.Config, &before) != nil || !before.Enabled {
					continue
				}
			case producer.Kind == "task":
				if c, attach := taskNetworkGoalChange(g, producer); !bytes.Equal(g.Config, producer.Goal) && !taskAliasOnly(g, producer) && (!taskSocketOnly(g, producer) || !bytes.Equal(goal(g.Activation), goal(producer.Activation))) && (!attach || c.detaches) {
					continue
				}
			default:
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
			b.d.Steps[i].Stable = append(b.d.Steps[i].Stable, ref)
		}
	}
}

// stableReference reports whether consumer keeps ref, its original
// reference to producer, through this plan.
func stableReference(consumer Step, producer Step, ref ObjectRef) bool {
	if !producer.BasePresent || ref.Generation != producer.Base.Generation {
		return false
	}
	switch {
	case producer.Kind == "dns" && consumer.Kind == "task":
	case producer.Kind == "task" && (consumer.Kind == "task" || consumer.Kind == "inputs"):
	default:
		return false
	}
	return slices.Contains(consumer.Stable, ref)
}

func validStableReferences(steps []Step) bool {
	producers := map[string]Step{}
	for _, s := range steps {
		producers[s.Key] = s
	}
	for _, s := range steps {
		if len(s.Stable) > len(s.Dependencies) || len(s.Stable) > 0 && (s.Kind != "task" && s.Kind != "inputs" || !s.BasePresent) {
			return false
		}
		prior := -1
		for _, ref := range s.Stable {
			at := slices.IndexFunc(s.Dependencies, func(d Dependency) bool { return d.Key == ref.Key })
			p := producers[ref.Key]
			if at <= prior || ref.Generation == 0 || ref.Revision < ref.Generation || ref.Revision > p.Base.Revision || !stableReference(s, p, ref) {
				return false
			}
			if p.Kind == "dns" {
				var cfg DNSDeclaration
				if json.Unmarshal(p.Goal, &cfg) != nil || !cfg.Enabled {
					return false
				}
			}
			prior = at
		}
	}
	return true
}
