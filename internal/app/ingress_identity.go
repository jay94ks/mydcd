// SPDX-License-Identifier: Apache-2.0

package app

import (
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/deployment"
	"github.com/jay94ks/seafield/internal/ingress"
)

// ingressNativeBinding selects a native only from an exact current stage or a
// proven narrow runtime update of its original claim. A node journal pin must
// agree; it cannot replace missing shared ownership evidence.
func (r *Runtime) ingressNativeBinding(shared state.State, apps control.Apps, goal deployment.GoalCommand, key string, o state.Object, spec ingress.Spec, bind bool) (string, error) {
	if spec.Lifecycle.Drain {
		inventory, ok := apps.Inventory(goal.Tenant, goal.App)
		if !ok {
			return "", deployment.ErrInputs
		}
		for _, claim := range inventory.Claims() {
			if claim.Removed || claim.Step.Kind != "ingress" || claim.Step.Key != key || claim.Result.Generation != o.Generation || claim.Step.Node != goal.Node || claim.Step.Owner != goal.Owner {
				continue
			}
			native := claim.Native
			if native == "" {
				native = managedIngressID(key, o.Generation, spec)
			}
			if source, pinned, known := r.ingress.NativeSource(key, o.Generation); known {
				if pinned != "" && pinned != native || pinned == "" && managedIngressID(key, o.Generation, source) != native {
					return "", deployment.ErrInputs
				}
			}
			return native, nil
		}
		return "", deployment.ErrInputs
	}
	native := ""
	if current, found := apps.Claim(goal.Tenant, goal.App, deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}); found && o.Present && current.Step.Owner == goal.Owner && current.Step.Node == goal.Node {
		// A Planned replacement has no stage command yet. Its exact original
		// committed source still owns the serving listener until dispatch.
		native, _ = deployment.CurrentIngressNative(current, deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}, o.Value)
	}
	if native == "" {
		execution, exists := apps.Execution(goal.Tenant, goal.App)
		if !exists {
			return "", deployment.ErrInputs
		}
		stage, exists := execution.Stage(key)
		if !exists || stage.Command == nil || stage.Command.Value != o.Value {
			return "", deployment.ErrInputs
		}
		result, known := shared.LookupResult(*stage.Command)
		if stage.Result != nil {
			result, known = *stage.Result, true
		}
		if !known || result.Generation != o.Generation || result.Revision != o.Revision || result.Code != state.Applied {
			return "", deployment.ErrInputs
		}

		var step deployment.Step
		found := false
		for _, s := range execution.Steps() {
			if s.Key == key {
				step = s
				found = true
				break
			}
		}
		if !found {
			return "", deployment.ErrInputs
		}
		if current, found := apps.Claim(goal.Tenant, goal.App, deployment.ObjectRef{Key: key, Generation: o.Generation, Revision: o.Revision}); found && (current.Command == *stage.Command || stage.Noop && current.Command.Value == stage.Command.Value) && current.Result == result && !current.Removed && current.Step.Owner == goal.Owner && current.Step.Node == goal.Node {
			native = current.Native
			if native == "" {
				native = managedIngressID(key, o.Generation, spec)
			}
		} else if step.BasePresent {
			original, found := apps.Claim(goal.Tenant, goal.App, step.Base)
			if !found {
				return "", deployment.ErrInputs
			}
			var valid bool
			native, valid = deployment.RetainedIngressNative(original, step, *stage.Command, result)
			if !valid {
				return "", deployment.ErrInputs
			}
		} else {
			native = managedIngressID(key, o.Generation, spec)
		}
	}
	if source, pinned, found := r.ingress.NativeSource(key, o.Generation); found {
		if pinned != "" {
			if pinned != native {
				return "", deployment.ErrInputs
			}
		} else if managedIngressID(key, o.Generation, source) != native {
			return "", deployment.ErrInputs
		}
		if bind {
			if err := r.ingress.BindNative(key, o.Generation, native); err != nil {
				return "", err
			}
		}
	}
	return native, nil
}
