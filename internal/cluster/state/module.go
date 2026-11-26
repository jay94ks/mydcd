// SPDX-License-Identifier: Apache-2.0

package state

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// Reducer is a deterministic typed module boundary. Writes are metadata rows,
// not native effects; nil values delete an existing row. It must authorize the
// authenticated actor against current module policy and return no partial state.
// Module rows can exceed one command in aggregate, but each row stays <=64KiB.
type Reducer func(before State, command Command) (writes map[string][]byte, code Code)

// ModuleAuthorizer authenticates a module-only actor against committed policy.
// It grants no legacy rights and must not consult clocks or external state.
type ModuleAuthorizer func(before State, command Command) bool

// ModulePatchAuthorizer admits explicitly related control metadata namespaces
// for ONE typed reducer transaction. New native rows remain forbidden. An
// existing native source also requires a full validator for explicit cleanup.
// The default remains the original command's namespace only.
type ModulePatchAuthorizer func(before State, command Command, relatedKeys []string) bool

const ModuleActorLimit = 4096

// AppObservationTarget identifies an immutable owner fact, not an effect or
// a general module CAS exemption. The installed reducer verifies its target.
const AppObservationTarget = "app-observation"

// AppInventoryTarget keeps member progress on the exact app inventory revision.
// The reducer also checks the original operation/step and current authority.
const AppInventoryTarget = "app-inventory"

func appInventoryCAS(c Command) bool {
	return c.Kind == ModuleReport && c.Key == "control/apps" && strings.HasPrefix(c.Actor, "node/") && c.Target == AppInventoryTarget
}

// RouteDispatchTarget is a reference-scoped native grant proposal. The typed
// reducer must validate the CURRENT original reference and signed dispatch;
// it is distinct from an immutable observation and grants no generic bypass.
const RouteDispatchTarget = "route-dispatch"

func routeDispatchCAS(c Command) bool {
	return c.Kind == ModuleReport && c.Key == "control/apps" && strings.HasPrefix(c.Actor, "node/") && c.Target == RouteDispatchTarget
}

// AppDeliveryTarget scopes source/controller metadata to its signed CD
// revision/ticket/choice. The installed reducer must revalidate that target
// and current authority; this grants no general module-root CAS exemption.
const AppDeliveryTarget = "app-delivery"

func appDeliveryCAS(c Command) bool {
	return c.Kind == ModuleReport && c.Key == "control/apps" && strings.HasPrefix(c.Actor, "node/") && c.Target == AppDeliveryTarget
}
func scopedAppReport(c Command) bool {
	return appObservation(c) || appInventoryCAS(c) || routeDispatchCAS(c) || appDeliveryCAS(c)
}

func appObservation(c Command) bool {
	return c.Kind == ModuleReport && c.Key == "control/apps" && strings.HasPrefix(c.Actor, "node/") && c.Target == AppObservationTarget
}

func applyModule(before, candidate State, index uint64, c Command, validate Validator, reduce Reducer, admitPatch ModulePatchAuthorizer) (State, Result) {
	n, r, _ := applyModuleStage(before, candidate, index, c, validate, reduce, admitPatch)
	return n, r
}

// ExplainModule names the module step that refuses c on before: "cas",
// "reduce", "root", "patch-key", "patch-admit", "validate" or "" when it
// applies. It ignores the request ledger; it is for local diagnostics only.
func ExplainModule(before State, c Command, validate Validator, reduce Reducer, admitPatch ModulePatchAuthorizer) string {
	candidate := clone(before)
	candidate.index = before.index + 1
	_, _, stage := applyModuleStage(before, candidate, candidate.index, c, validate, reduce, admitPatch)
	return stage
}

func applyModuleStage(before, candidate State, index uint64, c Command, validate Validator, reduce Reducer, admitPatch ModulePatchAuthorizer) (State, Result, string) {
	old := before.Object(c.Key)
	result := Result{Code: Invalid, Index: index, Revision: old.Revision, Generation: old.Generation}
	if reduce == nil || !strings.HasPrefix(c.Key, "control/") || len(c.Key) <= len("control/") || len(c.Key) > 512 || !utf8.ValidString(c.Key) || c.Delete || c.Target != "" && !scopedAppReport(c) || c.Rights != 0 || len(c.Value) > 64<<10 {
		return candidate, result, "command"
	}
	if c.Expected != old.Revision && (c.Kind != ModuleUpload && c.Kind != ModuleAppDown && !scopedAppReport(c) || c.Expected > old.Revision) {
		result.Code = ConditionFailed
		return candidate, result, "cas"
	}
	writes, code := reduce(before, c)
	if code != Applied {
		if code == Forbidden || code == ConditionFailed || RejectionReason(code) != "" {
			result.Code = code
			result.Reason = RejectionReason(code)
		}
		return candidate, result, "reduce"
	}
	root, exists := writes[c.Key]
	if !exists || root == nil {
		return candidate, result, "root"
	}
	// Validate the entire patch before changing even one row. A rejected patch
	// still gets the ordinary retained request result, with no module side effect.
	var related []string
	for key, value := range writes {
		control := strings.HasPrefix(key, "control/") && len(key) > len("control/")
		// A typed legacy cleanup may atomically change/delete its exact
		// original source. The callback admits the signed source/CAS; the
		// validator enforces its native lifecycle transition. Neither permits
		// creating a raw source or resurrecting a retired tombstone here.
		existingNative := !control && namespaceRights(key) != 0 && before.Object(key).Present && validate != nil && admitPatch != nil
		if !control && !existingNative || len(key) > 512 || !utf8.ValidString(key) || len(value) > 64<<10 || value == nil && !before.Object(key).Present {
			return candidate, result, "patch-key"
		}
		if key != c.Key && !strings.HasPrefix(key, c.Key+"/") {
			related = append(related, key)
		}
	}
	slices.Sort(related)
	if len(related) != 0 && (admitPatch == nil || !admitPatch(before, c, related)) {
		return candidate, result, "patch-admit"
	}
	for key, value := range writes {
		original := before.Object(key)
		object := Object{Revision: index, Generation: original.Generation, Value: string(value), Present: value != nil}
		if object.Present && !original.Present {
			object.Generation = index
		}
		candidate.objects[key] = object
	}
	if validate != nil && validate(before, candidate, c) != nil {
		for key := range writes {
			if original, exists := before.objects[key]; exists {
				candidate.objects[key] = original
			} else {
				delete(candidate.objects, key)
			}
		}
		return candidate, result, "validate"
	}
	object := candidate.Object(c.Key)
	return candidate, Result{Code: Applied, Index: index, Revision: object.Revision, Generation: object.Generation}, ""
}
