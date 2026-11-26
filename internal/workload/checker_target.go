// SPDX-License-Identifier: Apache-2.0

package workload

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/jay94ks/mydcd/internal/engine"
	"github.com/jay94ks/mydcd/internal/reconcile"
	"log"
	"net/netip"
	"strings"
	"time"

	checker "github.com/jay94ks/mydcd/internal/workload/lifecycle"
	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Public metadata only. No Process.Env, host paths or private input files.
type ProbeTarget struct {
	Key                  string
	Generation, Revision uint64
	IPv4, IPv6           netip.Addr
	Status               ContainerStatus
}

func probeTaskRecord(r reconcile.Record, generation, revision uint64) (ContainerSpec, error) {
	s := r.State
	if generation == 0 || revision < generation || s.Pending != nil || s.Stopped || !s.Applied.Present || !s.Desired.Present || s.Applied != s.Desired.Resource || s.Applied.Generation != generation || s.Desired.Revision != revision {
		return ContainerSpec{}, reconcile.ErrPending
	}
	spec, err := DecodeContainer(s.Applied.Spec)
	if err != nil {
		return ContainerSpec{}, err
	}
	if spec.Lifecycle.Drain {
		return ContainerSpec{}, reconcile.ErrStopped
	}
	return spec, nil
}
func sameProbeTask(a, b reconcile.Record) bool {
	return a.State.Pending == nil && b.State.Pending == nil && a.State.Stopped == b.State.Stopped && a.State.Desired == b.State.Desired && a.State.Applied == b.State.Applied && a.State.LastID == b.State.LastID
}

// ProbeTarget reuses actual Status ownership checks WITHOUT recursively
// issuing HTTP readiness. It neither starts a container nor changes a pin.
func (m *Manager) ProbeTarget(ctx context.Context, key string, generation, revision uint64) (ProbeTarget, error) {
	if ctx == nil {
		return ProbeTarget{}, ErrPlacement
	}
	if ctx.Err() != nil {
		return ProbeTarget{}, errors.Join(ErrPlacement, ctx.Err())
	}
	before, err := m.journal.Read(key)
	if err != nil {
		return ProbeTarget{}, err
	}
	spec, err := probeTaskRecord(before, generation, revision)
	if err != nil {
		return ProbeTarget{}, err
	}
	status, err := m.status(ctx, key, false)
	if err != nil {
		return ProbeTarget{}, err
	}
	after, err := m.journal.Read(key)
	if err != nil || !sameProbeTask(before, after) || ctx.Err() != nil {
		return ProbeTarget{}, errors.Join(reconcile.ErrPending, err, ctx.Err())
	}
	return ProbeTarget{Key: key, Generation: generation, Revision: revision, IPv4: spec.IPv4, IPv6: spec.IPv6, Status: status}, nil
}

// ReadProbeLease is an original A3 consumer for client I/O lifetime. Alone it
// grants neither Docker exec permission nor a native process closure assertion.
type ReadProbeLease struct {
	purpose string
	Target  ProbeTarget
	RunID   string
	Call    [32]byte
	Pin     reconcile.Lease
}

func (l ReadProbeLease) consumer() string {
	purpose := l.purpose
	if purpose == "" {
		purpose = "checker-read"
	}
	return purpose + "/" + l.RunID + "/" + hex.EncodeToString(l.Call[:])
}
func validReadProbe(l ReadProbeLease) bool {
	raw, err := hex.DecodeString(l.RunID)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == l.RunID && !bytes.Equal(raw, make([]byte, 32)) && l.Call != ([32]byte{}) && l.Target.Key != "" && l.Target.Generation != 0 && l.Target.Revision >= l.Target.Generation && l.Target.Status.NativeID != ""
}

// The caller persists its run/call before borrowing. On a failed post-borrow
// check the returned lease MUST still be retained and explicitly returned.
func (m *Manager) BorrowReadProbe(ctx context.Context, key string, generation, revision uint64, native, runID string, call [32]byte) (ReadProbeLease, error) {
	return m.borrowReadProbe(ctx, key, generation, revision, native, runID, call, "checker-read")
}
func (m *Manager) borrowReadProbe(ctx context.Context, key string, generation, revision uint64, native, runID string, call [32]byte, purpose string) (ReadProbeLease, error) {
	started := time.Now()
	phase := "parameters"
	var targetTime, pinTime time.Duration
	defer func() {
		if elapsed := time.Since(started); elapsed >= 200*time.Millisecond {
			log.Printf("checker read borrow slow: elapsed=%s cumulative_target=%s cumulative_pin=%s phase=%s", elapsed, targetTime, pinTime, phase)
		}
	}()
	if ctx == nil {
		return ReadProbeLease{}, ErrPlacement
	}
	if err := ctx.Err(); err != nil {
		return ReadProbeLease{}, errors.Join(ErrPlacement, err)
	}
	before, err := m.journal.Read(key)
	if err != nil {
		return ReadProbeLease{}, err
	}
	spec, err := probeTaskRecord(before, generation, revision)
	if err != nil {
		return ReadProbeLease{}, err
	}
	// Pin the original journal before SDK I/O. The supplied native is only
	// the expected identity until the full current ProbeTarget check below.
	// Keeping it here also lets the caller return the exact pin on failure.
	l := ReadProbeLease{Target: ProbeTarget{Key: key, Generation: generation, Revision: revision, IPv4: spec.IPv4, IPv6: spec.IPv6, Status: ContainerStatus{NativeID: native}}, RunID: runID, Call: call, purpose: purpose}
	if !validReadProbe(l) {
		return ReadProbeLease{}, engine.ErrOwnership
	}
	phase = "pin"
	l.Pin, err = m.journal.Borrow(key, l.consumer(), generation)
	pinTime = time.Since(started)
	if err != nil {
		return l, err
	}
	phase = "native-target"
	target, err := m.ProbeTarget(ctx, key, generation, revision)
	targetTime = time.Since(started)
	if err != nil {
		return l, err
	}
	if target.Status.NativeID != native {
		return l, engine.ErrOwnership
	}
	l.Target = target
	current, err := m.journal.Read(key)
	if err != nil || current.Consumers[l.consumer()] != l.Pin || !sameProbeTask(before, current) || ctx.Err() != nil {
		return l, errors.Join(reconcile.ErrLease, err, ctx.Err())
	}
	phase = "complete"
	return l, nil
}
func (m *Manager) CheckReadProbe(ctx context.Context, l ReadProbeLease) error {
	if !validReadProbe(l) || l.Pin == (reconcile.Lease{}) || l.Pin.Generation != l.Target.Generation {
		return reconcile.ErrLease
	}
	r, err := m.journal.Read(l.Target.Key)
	if err != nil || r.Consumers[l.consumer()] != l.Pin {
		return errors.Join(reconcile.ErrLease, err)
	}
	target, err := m.ProbeTarget(ctx, l.Target.Key, l.Target.Generation, l.Target.Revision)
	if err != nil {
		return err
	}
	if target.Status.NativeID != l.Target.Status.NativeID || target.Status.Running != l.Target.Status.Running || target.Status.StartedAt != l.Target.Status.StartedAt || target.IPv4 != l.Target.IPv4 || target.IPv6 != l.Target.IPv6 {
		return engine.ErrOwnership
	}
	return nil
}

// Cleanup uses the exact consumer/token after the read callback and all its
// sockets/SDK bodies returned. Revocation does not erase the original pin.
func (m *Manager) ReturnReadProbe(l ReadProbeLease) error {
	if !validReadProbe(l) || l.Pin == (reconcile.Lease{}) {
		return reconcile.ErrLease
	}
	return m.journal.Return(l.Target.Key, l.consumer(), l.Pin)
}

// ReturnReadRun is cleanup for a check whose original Probe calls have all
// been closed. The node's single checker flow establishes that boundary. It
// returns only this run's exact reader consumers, never workload/Volume pins.
func (m *Manager) ReturnReadRun(ctx context.Context, request contract.Request) error {
	return m.returnReadCalls(ctx, request, "", [32]byte{})
}

// ReturnReadCall is provider cleanup AFTER the original call's client I/O
// has joined. Other calls of the same check may still be live on this node;
// never return their A3 consumers just because this call ended. This says
// nothing about a Docker exec's termination, which has its own receipt.
func (m *Manager) ReturnReadCall(ctx context.Context, request contract.Request, service string, call [32]byte) error {
	if service == "" || call == ([32]byte{}) {
		return ErrPlacement
	}
	return m.returnReadCalls(ctx, request, service, call)
}

func (m *Manager) returnReadCalls(ctx context.Context, request contract.Request, service string, call [32]byte) error {
	if m == nil || m.driver == nil || m.driver.Engine == nil || ctx == nil || checker.ValidateRequest(request) != nil {
		return ErrPlacement
	}
	local := false
	for _, target := range request.Targets {
		local = local || (service == "" || target.Service == service) && m.driver.Engine.Owner == request.Cluster+"/"+target.Owner
	}
	if !local {
		return ErrPlacement
	}
	for _, target := range request.Targets {
		if service != "" && target.Service != service || m.driver.Engine.Owner != request.Cluster+"/"+target.Owner {
			continue // app observations may also name other owners; cleanup is local only
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := m.journal.Read(target.TaskKey)
		if err != nil {
			return err
		}
		for consumer, pin := range r.Consumers {
			if !strings.HasPrefix(consumer, "checker-read/"+request.RunID+"/") {
				continue
			}
			if service != "" && consumer != "checker-read/"+request.RunID+"/"+hex.EncodeToString(call[:]) {
				continue
			}
			if pin.Generation != target.Generation {
				return reconcile.ErrLease
			}
			if err := m.journal.Return(target.TaskKey, consumer, pin); err != nil {
				return err
			}
		}
	}
	return nil
}
