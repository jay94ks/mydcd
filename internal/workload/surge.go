// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"context"
	"strconv"
	"strings"

	"github.com/jay94ks/seafield/internal/reconcile"
)

// A surge (devel/design/zero-downtime-apply.md) runs two generations of one
// Task on this server for a while. The new generation starts under the Task
// key as usual; the original's journal record is parked under ParkedKey
// first, where it is stepped with its own identity (the Task key, its own
// generation) until it is stopped and gone.

const parkedSeparator = "#surge/"

// ParkedKey is where the original generation of key is kept during a surge.
func ParkedKey(key string, generation uint64) string {
	return key + parkedSeparator + strconv.FormatUint(generation, 10)
}

// ParkedTask splits a ParkedKey; ok is false for any other key.
func ParkedTask(parked string) (key string, generation uint64, ok bool) {
	key, rest, found := strings.Cut(parked, parkedSeparator)
	if !found || key == "" {
		return "", 0, false
	}
	generation, err := strconv.ParseUint(rest, 10, 64)
	return key, generation, err == nil && generation > 0 && ParkedKey(key, generation) == parked
}

// parkedDriver steps a parked record with the identity of the Task it came
// from: every native name, label, lease and pin is derived from the Task key.
type parkedDriver struct {
	d   *DockerDriver
	key string
}

func (p parkedDriver) Execute(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	return p.d.Execute(ctx, p.key, op)
}
func (p parkedDriver) Recover(ctx context.Context, _ string, op reconcile.Operation) (reconcile.Outcome, error) {
	return p.d.Recover(ctx, p.key, op)
}
func (p parkedDriver) Retire(ctx context.Context, _ string, op reconcile.Operation, receipt []byte, save func([]byte) error) (bool, error) {
	return p.d.Retire(ctx, p.key, op, receipt, save)
}
func (p parkedDriver) RemoveCheckpoint(ctx context.Context, _ string, op reconcile.Operation, receipt []byte, save func([]byte) error) (reconcile.Outcome, error) {
	return p.d.RemoveCheckpoint(ctx, p.key, op, receipt, save)
}
func (p parkedDriver) ExecuteCheckpoint(ctx context.Context, _ string, op reconcile.Operation, save func([]byte) error) (reconcile.Outcome, error) {
	return p.d.ExecuteCheckpoint(ctx, p.key, op, save)
}

// Park moves the running original generation of key aside so its new
// generation can start next to it. It refuses unless that generation is
// applied, settled and still desired; a record already parked stays.
func (m *Manager) Park(key string, generation uint64) error {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	if _, _, ok := ParkedTask(key); ok || generation == 0 {
		return reconcile.ErrMove
	}
	return m.journal.Move(key, ParkedKey(key, generation), func(r reconcile.Record) bool {
		s := r.State
		return s.Pending == nil && !s.Stopped && s.Applied.Present && s.Applied.Generation == generation && s.Desired.Resource == s.Applied
	})
}

// Parked reads the parked original generation of key.
func (m *Manager) Parked(key string, generation uint64) (reconcile.Record, error) {
	return m.journal.Read(ParkedKey(key, generation))
}

// RetireParked stops and removes the parked original generation of key.
// revision is the Task object's revision that superseded it.
func (m *Manager) RetireParked(ctx context.Context, key string, revision, generation uint64) error {
	m.controlMu.Lock()
	defer m.controlMu.Unlock()
	parked := ParkedKey(key, generation)
	r, err := m.journal.Read(parked)
	if err != nil {
		return err
	}
	if r.State.Desired.Present || r.State.Desired.Retiring != generation {
		if err = m.journal.Desired(parked, reconcile.Desired{Revision: max(revision, r.State.Desired.Revision), Retiring: generation}, r.Capacity); err != nil {
			return err
		}
		if r, err = m.journal.Read(parked); err != nil {
			return err
		}
	}
	driver := *m.driver
	driver.startCheckpoint = r.Checkpoint
	return m.journal.Step(ctx, parked, parkedDriver{d: &driver, key: key})
}

// ParkedGone reports whether the parked original generation of key is
// stopped, released and absent from the engine; its successor may still
// run.
func (m *Manager) ParkedGone(ctx context.Context, key string, generation uint64) (bool, error) {
	r, err := m.journal.Read(ParkedKey(key, generation))
	if err != nil {
		return false, err
	}
	s := r.State
	if s.GenerationFloor != generation || s.Pending != nil || s.Applied.Present || s.Desired.Present || len(r.Consumers) != 0 {
		return false, nil
	}
	return m.driver.Engine.GoneGeneration(ctx, "container", key, generation)
}
