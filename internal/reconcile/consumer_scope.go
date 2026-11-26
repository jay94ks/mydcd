// SPDX-License-Identifier: Apache-2.0

package reconcile

import "strings"

// ConsumerScope is original resource ownership, not an authorization grant.
// The installed caller must validate it against the exact shared source.
type ConsumerScope struct {
	Tenant, Node, Owner string
}

func (s ConsumerScope) Valid() bool {
	return journalKey(s.Tenant) && len(s.Tenant) <= 63 && !strings.Contains(s.Tenant, "/") && journalKey(s.Node) && len(s.Node) <= 63 && !strings.Contains(s.Node, "/") && journalKey(s.Owner) && len(s.Owner) <= 256
}

// BindConsumerScope upgrades only the SAME known, currently authorized source.
// It does not infer a tenant from a key/label, move pins or grant native Ready.
// Unknown/revoked sources without original scope must settle their old pins.
func (j *Journal) BindConsumerScope(key string, source Desired, scope ConsumerScope) error {
	if !scope.Valid() {
		return ErrLease
	}
	j.life.RLock()
	defer j.life.RUnlock()
	e, err := j.entry(key, false)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failed {
		return ErrJournalUncertain
	}
	r := cloneRecord(e.r)
	if r.Scope != (ConsumerScope{}) {
		if r.Scope != scope {
			return ErrLease
		}
		return nil
	}
	if r.State.Desired != source || !source.Resource.Present || r.State.Applied != source.Resource || r.State.Pending != nil || r.State.Stopped {
		return ErrLease
	}
	r.Scope = scope
	return j.save(key, e, r)
}
