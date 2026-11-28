// SPDX-License-Identifier: Apache-2.0

package reconcile

import (
	"encoding/json"
	"errors"

	"github.com/jay94ks/seafield/internal/storage"
)

// ErrMove refuses a Move whose source does not qualify or whose target is
// taken.
var ErrMove = errors.New("journal record cannot move")

// Move puts the record of from under the key to in one synchronous write, so
// a crash leaves it under exactly one of them. accept sees the record first
// and refuses the move by returning false. to must hold no record. It is how
// a surge parks the original generation of a Task (devel/design/
// zero-downtime-apply.md) while the new generation starts under from.
func (j *Journal) Move(from, to string, accept func(Record) bool) error {
	j.life.RLock()
	defer j.life.RUnlock()
	if from == to {
		return ErrMove
	}
	src, err := j.entry(from, false)
	if err != nil {
		return err
	}
	dst, err := j.entry(to, true)
	if err != nil {
		return err
	}
	first, second := src, dst
	if to < from {
		first, second = dst, src
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	second.mu.Lock()
	defer second.mu.Unlock()
	if src.failed || dst.failed {
		return ErrJournalUncertain
	}
	if src.r.Schema == 0 {
		return storage.ErrMissing
	}
	if dst.r.Schema != 0 || accept != nil && !accept(cloneRecord(src.r)) {
		return ErrMove
	}
	r := cloneRecord(src.r)
	if err := validateRecord(r); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err = j.db.Write(map[string][]byte{"resource/" + from: nil, "resource/" + to: b}); err != nil {
		src.failed, dst.failed = true, true
		return errors.Join(ErrJournalUncertain, err)
	}
	dst.r, src.r = r, Record{}
	return nil
}
