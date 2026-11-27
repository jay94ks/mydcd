// SPDX-License-Identifier: Apache-2.0

package deployment

import (
	"bytes"
	"encoding/json"
	"slices"

	"github.com/jay94ks/seafield/internal/cluster/state"
)

// CurrentIngressNative identifies the exact committed source already owned by
// an app. A later accepted plan need not have dispatched its corresponding
// stage yet. This selects an existing identity; it grants no new native effect.
func CurrentIngressNative(claim Claim, source ObjectRef, value string) (string, bool) {
	if claim.Removed || claim.Retained || claim.Native == "" || claim.Step.Kind != "ingress" || claim.Step.Key != source.Key || claim.Command.Key != source.Key || claim.Command.Delete || claim.Command.Value != value || claim.Result.Code != state.Applied || source.Generation == 0 || source.Revision == 0 || claim.Result.Generation != source.Generation || claim.Result.Revision != source.Revision {
		return "", false
	}
	var original GoalCommand
	if json.Unmarshal([]byte(value), &original) != nil || original.Schema != 1 || original.Kind != "ingress" || original.Lifecycle != nil || original.Node != claim.Step.Node || original.Owner != claim.Step.Owner || !bytes.Equal(original.Config, claim.Step.Goal) {
		return "", false
	}
	return claim.Native, true
}

// IngressRuntimeUpdate permits only routing policy over the same original
// listener and backend dependency recipe. It is not a generic hot mutation
// grant and never creates or selects a replacement native identity.
func IngressRuntimeUpdate(claim Claim, step Step) bool {
	if claim.Removed || claim.Retained || claim.Native == "" || claim.Result.Code != state.Applied || claim.Step.Kind != "ingress" || step.Kind != "ingress" || claim.Step.Key != step.Key || claim.Step.Node != step.Node || claim.Step.Owner != step.Owner || !bytes.Equal(goal(claim.Step.Dependencies), goal(step.Dependencies)) || !slices.Equal(claim.Step.Identity, step.Identity) || !bytes.Equal(goal(claim.Step.Activation), goal(step.Activation)) {
		return false
	}
	var original GoalCommand
	var before, after IngressDeclaration
	if json.Unmarshal([]byte(claim.Command.Value), &original) != nil || original.Kind != "ingress" || original.Node != step.Node || original.Owner != step.Owner || json.Unmarshal(original.Config, &before) != nil || json.Unmarshal(step.Goal, &after) != nil {
		return false
	}
	listenerSame := bytes.Equal(goal(before.Listeners), goal(after.Listeners))
	handoff := len(before.Listeners) == 1 && len(after.Listeners) == 1 && before.Listeners[0].Shared == "" && after.Listeners[0].Shared != ""
	if !listenerSame && !handoff || before.Node != after.Node || before.Runtime != after.Runtime || len(before.Routes) != len(after.Routes) {
		return false
	}
	normalize := func(i IngressDeclaration) IngressDeclaration {
		i.Host, i.Gateway = "", ""
		i.Balance = nil
		i.Routes = append([]IngressRouteDeclaration(nil), i.Routes...)
		for at := range i.Routes {
			i.Routes[at].Host, i.Routes[at].Prefix, i.Routes[at].Gateway = "", "", ""
			i.Routes[at].Balance = nil
		}
		return i
	}
	if handoff {
		after.Listeners = before.Listeners
	}
	return bytes.Equal(goal(normalize(before)), goal(normalize(after)))
}

// RetainedIngressNative proves a same-generation runtime update against the
// original claim and the current accepted stage. Missing or conflicting
// evidence is an error; callers must never fall back to an arbitrary saved ID.
func RetainedIngressNative(claim Claim, step Step, command state.Command, result state.Result) (string, bool) {
	if !IngressRuntimeUpdate(claim, step) || command.Key != step.Key || result.Code != state.Applied || result.Generation != claim.Result.Generation || result.Revision <= claim.Result.Revision || command.Expected != claim.Result.Revision {
		return "", false
	}
	var original, current GoalCommand
	_ = json.Unmarshal([]byte(claim.Command.Value), &original)
	if json.Unmarshal([]byte(command.Value), &current) != nil || current.Kind != "ingress" || current.Node != step.Node || current.Owner != step.Owner || !bytes.Equal(current.Config, step.Goal) || current.Lifecycle != nil || !bytes.Equal(goal(current.Dependencies), goal(original.Dependencies)) || !slices.Equal(current.Follow, original.Follow) {
		return "", false
	}
	return claim.Native, true
}
