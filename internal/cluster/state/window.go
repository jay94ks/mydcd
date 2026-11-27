// SPDX-License-Identifier: Apache-2.0

package state

import "strings"

// moduleWindow fences retired module identities without keeping one tombstone
// per session key. Exactly one rotation receipt survives until the next explicit
// window. A missing/expired receipt is never evidence of nonexecution.
type moduleWindow struct {
	Epoch     uint64
	Actor, ID string
	Digest    [32]byte
	Result    Result
}

func moduleActor(actor string) bool {
	return strings.HasPrefix(actor, "user/") || strings.HasPrefix(actor, "node/")
}

func (s State) ModuleEpoch() uint64 {
	if s.window == nil {
		return 1
	}
	return s.window.Epoch
}

func (s State) ModuleWindowRevision() uint64 {
	if s.window == nil {
		return 0
	}
	return s.window.Result.Revision
}

// LedgerEpoch is a committed replay fence, not an existence/authority lookup.
// Retired module actors still have the namespace floor after their principal
// row was reclaimed. Legacy actors retain their individual epoch contract.
func (s State) LedgerEpoch(actor string) (uint64, bool) {
	p, known := s.principals[actor]
	if moduleActor(actor) && (!known || p.Rights == 0) {
		return s.ModuleEpoch(), true
	}
	return p.Epoch, known
}

// ModuleExpired describes the retention window, not an original effect's result.
func (s State) ModuleExpired(c Command) bool {
	return (c.Kind == Module || c.Kind == ModuleReport || c.Kind == ModuleUpload || c.Kind == ModuleAppDown || c.Kind == ModuleWindow || c.Kind == Mutate) && moduleActor(c.Actor) && c.Epoch != s.ModuleEpoch() || s.reportExpired(c)
}

func (s State) windowResult(c Command) (Result, bool) {
	w := s.window
	if w != nil && c.Kind == ModuleWindow && c.Epoch == w.Epoch-1 && c.Actor == w.Actor && c.RequestID == w.ID && Digest(c) == w.Digest {
		return w.Result, true
	}
	return Result{}, false
}

// Successful maintenance escapes both full budgets using a bounded window row.
// An authenticated failure retains its ordinary receipt when space permits;
// otherwise it reports LedgerFull, never a retained original result.
func applyModuleWindow(before, candidate State, index uint64, c Command, validate Validator, reduce Reducer, admit ModuleAuthorizer) (State, Result, error) {
	denied := Result{Code: Forbidden, Index: index}
	if !strings.HasPrefix(c.Actor, "user/") || c.Key != "control/storage" || c.Epoch != before.ModuleEpoch() || c.Epoch == ^uint64(0) || reduce == nil || admit == nil || !admit(before, c) {
		return candidate, denied, nil
	}
	if p, ok := before.principals[c.Actor]; ok && (p.Rights != 0 || p.Epoch != c.Epoch) {
		return candidate, denied, nil
	}
	if old, ok := before.request(requestKey{c.Actor, c.RequestID}); ok {
		if old.digest != Digest(c) {
			return candidate, Result{Code: RequestConflict, Index: index}, nil
		}
		return candidate, old.result, nil
	}
	// Apply the complete metadata patch and ordinary policy validation first.
	// No changes escape on a rejected candidate.
	next, result := applyModule(before, candidate, index, c, nil, reduce, nil)
	if result.Code != Applied {
		return retainWindowFailure(before, next, index, c, result)
	}
	retired := make(map[string]bool)
	for actor, principal := range next.principals {
		if principal.Rights == 0 && moduleActor(actor) {
			delete(next.principals, actor)
			retired[actor] = true
		}
	}
	for actor := range retired {
		var requests, reports []requestKey
		next.actorRequests(actor, func(k requestKey, _ receipt) bool { requests = append(requests, k); return true })
		next.actorReports(actor, func(k requestKey, _ reportReceipt) bool { reports = append(reports, k); return true })
		for _, k := range requests {
			next.dropRequest(k)
		}
		for _, k := range reports {
			next.dropReport(k)
		}
	}
	for key := range next.reportFloors {
		if retired[key.Actor] {
			delete(next.reportFloors, key)
		}
	}
	next.window = &moduleWindow{Epoch: c.Epoch + 1, Actor: c.Actor, ID: c.RequestID, Digest: Digest(c), Result: result}
	if validate != nil && validate(before, next, c) != nil {
		unchanged := clone(before)
		unchanged.index = index
		return retainWindowFailure(before, unchanged, index, c, Result{Code: Invalid, Index: index})
	}
	return next, result, nil
}

func retainWindowFailure(before, candidate State, index uint64, c Command, result Result) (State, Result, error) {
	p, known := before.principals[c.Actor]
	count := before.requestCount(c.Actor)
	if count >= LedgerLimit || !known && len(before.principals) >= ModuleActorLimit {
		return candidate, Result{Code: LedgerFull, Index: index}, nil
	}
	if !known {
		p = principal{Epoch: c.Epoch, Revision: index}
	}
	candidate.principals[c.Actor] = p
	candidate.putRequest(requestKey{c.Actor, c.RequestID}, receipt{Digest(c), result})
	return candidate, result, nil
}
