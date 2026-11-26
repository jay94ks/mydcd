// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
)

// A batch is one original task, not an arbitrary set of independent starts.
// Stable physical-name ordering makes it share every volume's Fence lock.
func activationBatch(refs []Activation) ([]Activation, error) {
	if len(refs) == 0 || len(refs) > 32 {
		return nil, ErrActivation
	}
	refs = slices.Clone(refs)
	slices.SortFunc(refs, func(a, b Activation) int { return strings.Compare(a.Consumer.Owner.Native, b.Consumer.Owner.Native) })
	first := refs[0]
	for i, r := range refs {
		if !validActivation(r, first.Scope.Cluster, r.Consumer.Owner.Key) || r.Scope.Tenant != first.Scope.Tenant || r.TaskKey != first.TaskKey || r.Task != first.Task || r.Operation != first.Operation || taskOwner(r) != taskOwner(first) || r.Consumer.Owner.Node != first.Consumer.Owner.Node || i > 0 && refs[i-1].Consumer.Owner.Native == r.Consumer.Owner.Native {
			return nil, ErrActivation
		}
	}
	return refs, nil
}

type activationBatchEntry struct {
	r Activation
	e *activationEntry
	d activationRecord
	g Gate
	i int
}

// Caller holds life.RLock. All entry locks are held through the actual SDK
// effect, so no accepted member can be fenced between checking and dispatch.
func (s *Activations) lockBatch(refs []Activation) ([]activationBatchEntry, func(), error) {
	return s.lockBatchEntries(refs, true)
}

func (s *Activations) lockBatchEntries(refs []Activation, requireBinding bool) ([]activationBatchEntry, func(), error) {
	rows := make([]activationBatchEntry, 0, len(refs))
	owners := []*Activations{}
	unlock := func() {
		for i := len(rows) - 1; i >= 0; i-- {
			rows[i].e.mu.Unlock()
		}
		for i := len(owners) - 1; i >= 0; i-- {
			owners[i].life.RUnlock()
		}
	}
	for _, r := range refs {
		owner := s.ownerStore(r.Consumer.Owner.Key)
		if owner == nil {
			unlock()
			return nil, nil, ErrActivation
		}
		if owner != s && !slices.Contains(owners, owner) {
			owner.life.RLock()
			owners = append(owners, owner)
			if owner.closed {
				unlock()
				return nil, nil, ErrActivation
			}
		}
		e, err := s.entry(r, !requireBinding)
		if err != nil {
			unlock()
			return nil, nil, err
		}
		e.mu.Lock()
		d := copyActivation(e.disk)
		i := bindingIndex(d, r)
		rows = append(rows, activationBatchEntry{r, e, d, e.gate, i})
		if requireBinding && (i < 0 || d.Bindings[i].Ref != r) {
			unlock()
			return nil, nil, ErrActivation
		}
	}
	return rows, unlock, nil
}

// Each original owner journal keeps its gate. Every affected journal must be
// durable before a whole-task SDK effect; errors retain the exact pending facts.
func (s *Activations) saveBatch(rows []activationBatchEntry) error {
	stores := []*Activations{}
	for i := range rows {
		if rows[i].e.store == nil {
			rows[i].e.store = s
		}
		owner := rows[i].e.store
		if !slices.Contains(stores, owner) {
			stores = append(stores, owner)
		}
	}
	// One write per ORIGINAL owner DB. A partial durable prefix never dispatches
	// the SDK; its prepared/Starting records remain recoverable or Unknown.
	for _, owner := range stores {
		writes := map[string][]byte{}
		for i := range rows {
			row := &rows[i]
			if row.e.store != owner {
				continue
			}
			row.d.Gate = row.g.Checkpoint()
			raw, err := json.Marshal(row.d)
			if err != nil {
				return err
			}
			writes[activationRecordKey(row.e.owner.Native)] = raw
		}
		if err := owner.db.Write(writes); err != nil {
			return err
		}
		for _, row := range rows {
			if row.e.store == owner {
				row.e.disk, row.e.gate = row.d, row.g
			}
		}
	}
	return nil
}

func (s *Activations) completeVolumeMounts(got container.InspectResponse, refs []Activation) bool {
	type sourceRef struct {
		source   string
		bind     bool
		writable bool
	}
	sources := make([]sourceRef, 0, len(refs))
	for _, r := range refs {
		source, bind, err := s.mountSource(r.NativeKey, r.Scope, r.Consumer.Owner, r.NativeGeneration, r.NativeBinding)
		if err != nil {
			return false
		}
		sources = append(sources, sourceRef{source, bind, r.Consumer.Writable})
	}
	counts := make([]int, len(sources))
	for _, m := range got.Mounts {
		matched := false
		for i, r := range sources {
			if r.writable == m.RW && (!r.bind && m.Type == mount.TypeVolume && m.Name == r.source || r.bind && m.Type == mount.TypeBind && m.Source == r.source && m.Propagation == mount.PropagationRPrivate) {
				counts[i]++
				matched = true
			}
		}
		if matched {
			continue
		}
		if m.Type == mount.TypeVolume || m.Type == mount.TypeBind && s.fixedSourcePath(m.Source) {
			return false
		}
	}
	for _, count := range counts {
		if count != 1 {
			return false
		}
	}
	return true
}

// ActivateAll obtains ALL permits and syncs ALL Starting records before ONE
// ContainerStart. Calling Activate in a loop would start before the later
// volume's authorization and is therefore deliberately rejected by coverage.
func (s *Activations) ActivateAll(ctx context.Context, refs []Activation) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	for _, r := range refs {
		if err = s.Plan(ctx, r); err != nil {
			return err
		}
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	nativeID := ""
	running := false
	var exit *engine.ContainerExit
	for i := range rows {
		row := &rows[i]
		b := &row.d.Bindings[row.i]
		if b.Closed || b.StopSent {
			return ErrActivation
		}
		if b.CreatePrepared {
			return reconcile.ErrPending
		}
		if b.Started && row.d.Gate.Starting != nil {
			return reconcile.ErrPending
		}
		got, err := s.container(ctx, row.r, b.NativeID)
		if err != nil {
			return err
		}
		observed := engine.ObserveContainerExit(got.State)
		if !s.completeVolumeMounts(got, refs) || i > 0 && (nativeID != got.ID || running != got.State.Running || (exit == nil) != (observed == nil) || exit != nil && *exit != *observed) {
			return engine.ErrOwnership
		}
		nativeID, running = got.ID, got.State.Running
		exit = observed
		if b.NativeID == "" {
			if running {
				return ErrActivation
			}
			b.NativeID = nativeID
		}
		if running || exit != nil {
			if running {
				if err = s.checkFixedProcess(ctx, rows, got); err != nil {
					return err
				}
			}
			if row.d.Gate.Starting != nil && *row.d.Gate.Starting != row.r.Consumer {
				return ErrActivation
			}
			if exit != nil && !b.Started && row.d.Gate.Starting == nil {
				// Exit alone cannot invent this binding's original Start grant.
				return ErrActivation
			}
			if row.d.Gate.Starting != nil && *row.d.Gate.Starting == row.r.Consumer {
				row.g, err = row.g.SettleStart(row.r.Consumer, reconcile.EffectApplied)
				if err != nil {
					return err
				}
			} else if !b.Started {
				return ErrActivation
			}
			b.Started = true
		} else if row.d.Gate.Starting != nil || b.Started || !engine.ContainerStartable(got.State) {
			// Neither an ambiguous stopped state nor absence of a current PID
			// permits running an already dispatched/executed command again.
			return reconcile.ErrPending
		}
	}
	if err = s.saveBatch(rows); err != nil || running || exit != nil {
		return err
	}
	api, closeAPI, err := s.bindClient(ctx, rows)
	if err != nil {
		return err
	}
	defer closeAPI()
	if err = s.requestActivationStarts(ctx, rows); err != nil {
		return err
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, err = api.ContainerStart(ctx, nativeID, client.ContainerStartOptions{}); err != nil {
		if errors.Is(err, engine.ErrBindBeforeRequest) {
			for i := range rows {
				row := &rows[i]
				settled, settleErr := row.g.SettleStart(row.r.Consumer, reconcile.EffectNotApplied)
				if settleErr != nil {
					return errors.Join(err, settleErr)
				}
				row.g = settled
			}
			return errors.Join(err, s.saveBatch(rows))
		}
		return err
	}
	for i := range rows {
		row := &rows[i]
		got, err := s.container(ctx, row.r, nativeID)
		if err != nil || !got.State.Running && engine.ObserveContainerExit(got.State) == nil || !s.completeVolumeMounts(got, refs) {
			return errors.Join(reconcile.ErrPending, err)
		}
		if got.State.Running {
			if err = s.checkFixedProcess(ctx, rows, got); err != nil {
				return err
			}
		}
		row.g, err = row.g.SettleStart(row.r.Consumer, reconcile.EffectApplied)
		if err != nil {
			return err
		}
		row.d.Bindings[row.i].Started = true
	}
	return s.saveBatch(rows)
}

// RetireAll first binds every mount to the same positively observed original
// native ID. Otherwise deleting it for the first volume could strand the next
// volume at an unobserved absence after a crash or response loss.
func (s *Activations) RetireAll(ctx context.Context, refs []Activation) error {
	refs, err := activationBatch(refs)
	if err != nil {
		return err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	rows, unlock, err := s.lockBatch(refs)
	if err != nil {
		return err
	}
	defer unlock()
	nativeID := ""
	running, present := false, false
	var stop engine.StopPolicy
	stopSent := false
	for i := range rows {
		row := &rows[i]
		b := &row.d.Bindings[row.i]
		if b.Closed {
			continue
		}
		stopSent = stopSent || b.StopSent
		if b.CreatePrepared {
			// This synced flag is consumed BEFORE the original SDK Create.
			// Unlike ordinary absence it positively proves no dispatch.
			if _, err := s.container(ctx, row.r, ""); !cerrdefs.IsNotFound(err) {
				return errors.Join(ErrActivation, err)
			}
			b.CreatePrepared, b.Unsent, b.Closed = false, true, true
			continue
		}
		got, err := s.container(ctx, row.r, b.NativeID)
		if cerrdefs.IsNotFound(err) && b.NativeID == "" {
			return reconcile.ErrPending
		}
		if err != nil && !cerrdefs.IsNotFound(err) {
			return err
		}
		if err == nil {
			if !s.completeVolumeMounts(got, refs) || nativeID != "" && nativeID != got.ID {
				return engine.ErrOwnership
			}
			policy, policyErr := engine.MatchStopPolicy(row.r.Task.Spec, got.Config)
			if policyErr != nil || present && policy != stop {
				return errors.Join(engine.ErrStopPolicy, policyErr)
			}
			stop = policy
			nativeID, present, running = got.ID, true, running || got.State.Running
			b.NativeID = got.ID
		} else if nativeID != "" && nativeID != b.NativeID {
			return engine.ErrOwnership
		} else {
			nativeID = b.NativeID
		}
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	if present {
		if running {
			if stopSent {
				return reconcile.ErrPending
			}
			if err = engine.CheckStopBudget(ctx, stop); err != nil {
				return err
			}
			for i := range rows {
				if !rows[i].d.Bindings[rows[i].i].Closed {
					rows[i].d.Bindings[rows[i].i].StopSent = true
				}
			}
			if err = s.saveBatch(rows); err != nil {
				return err
			}
			if err = s.client.StopContainer(ctx, nativeID, stop); err != nil {
				return err
			}
		}
		// Stop ACK alone does not prove a normal exit. Observe the exact ID
		// and ALL original mounts, then sync its terminal state for every
		// binding before Remove destroys this evidence. A legacy/created
		// object without an exit remains eligible for cleanup, not backup.
		for i := range rows {
			row := &rows[i]
			b := &row.d.Bindings[row.i]
			if b.Closed {
				continue
			}
			got, err := s.container(ctx, row.r, nativeID)
			if err != nil || !s.completeVolumeMounts(got, refs) {
				return errors.Join(ErrActivation, err)
			}
			if got.State.Running || got.State.Paused || got.State.Restarting {
				return reconcile.ErrPending
			}
			sent := ""
			if b.StopSent {
				sent = sentStopSignal(stop, got)
			}
			b.Exit = observedExit(got.State, sent)
		}
		if err = s.saveBatch(rows); err != nil {
			return err
		}
		if _, err = s.client.API.ContainerRemove(ctx, nativeID, client.ContainerRemoveOptions{}); err != nil {
			return err
		}
		if _, err = s.client.API.ContainerInspect(ctx, nativeID, client.ContainerInspectOptions{}); !cerrdefs.IsNotFound(err) {
			return errors.Join(reconcile.ErrPending, err)
		}
	}
	for i := range rows {
		row := &rows[i]
		if row.d.Bindings[row.i].Closed {
			continue
		}
		if row.d.Gate.Starting != nil && *row.d.Gate.Starting == row.r.Consumer {
			row.g, err = row.g.CloseStart(row.r.Consumer)
			if err != nil {
				return err
			}
		}
		row.d.Bindings[row.i].Closed = true
	}
	if err = s.saveBatch(rows); err != nil {
		return err
	}
	for i := range rows {
		row := &rows[i]
		if !row.d.Bindings[row.i].Released {
			if err = s.returnLease(row.d.Bindings[row.i].Lease); err != nil {
				return err
			}
			row.d.Bindings[row.i].Released = true
		}
	}
	return s.saveBatch(rows)
}
