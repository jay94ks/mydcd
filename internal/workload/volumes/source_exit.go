// SPDX-License-Identifier: Apache-2.0

package volumes

import (
	"context"
	"errors"
	"time"

	"github.com/jay94ks/seafield/internal/engine"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"golang.org/x/sys/unix"
)

// ProcessExit is an original Engine observation synced BEFORE native removal.
// Missing legacy observations remain unknown. Clean is a process fact, not an
// assertion of database format/image/keyring compatibility or successful SQL.
type ProcessExit struct {
	StartedAt, FinishedAt string
	Code                  int
	OOM, Error            bool
	Status                string
	// StopSignal is the signal sfcli sent to stop this process, when it did.
	// A process that ends on that signal (exit 128+n) stopped as asked.
	StopSignal string `json:",omitempty"`
}

func (e ProcessExit) valid() bool {
	start, a := time.Parse(time.RFC3339Nano, e.StartedAt)
	finish, b := time.Parse(time.RFC3339Nano, e.FinishedAt)
	return len(e.StartedAt) <= 64 && len(e.FinishedAt) <= 64 && a == nil && b == nil && start.Unix() > 0 && !finish.Before(start) && e.Code >= 0 && e.Code <= 255 && (e.Status == "exited" || e.Status == "dead") && len(e.StopSignal) <= 16
}

// Clean means the process exited by itself with 0, or ended on the stop
// signal sfcli sent (for example 143 after SIGTERM) before its grace ran out.
// SIGKILL, including Docker's kill after the grace, OOM and errors are not.
func (e ProcessExit) Clean() bool {
	if !e.valid() || e.OOM || e.Error || e.Status != "exited" {
		return false
	}
	if e.Code == 0 {
		return true
	}
	// Signal numbers are Linux's: every voter runs Linux, so this reducer
	// input is the same on all of them. Other OSes number signals differently.
	n := unix.SignalNum(e.StopSignal)
	return e.StopSignal != "" && n > 0 && n != unix.SIGKILL && e.Code == 128+int(n)
}

func observedExit(state *container.State, stopSignal string) *ProcessExit {
	if state == nil || state.Running || state.Paused || state.Restarting {
		return nil
	}
	e := ProcessExit{StartedAt: state.StartedAt, FinishedAt: state.FinishedAt, Code: state.ExitCode, OOM: state.OOMKilled, Error: state.Error != "", Status: string(state.Status), StopSignal: stopSignal}
	if !e.valid() {
		return nil
	}
	return &e
}

// sentStopSignal is the signal Docker delivered for a stop under p: the
// Task's signal, else the container's configured one, else SIGTERM.
func sentStopSignal(p engine.StopPolicy, got container.InspectResponse) string {
	if p.Signal != "" {
		return p.Signal
	}
	if got.Config != nil && got.Config.StopSignal != "" {
		if name, err := engine.NormalizeStopSignal(got.Config.StopSignal); err == nil && name != "" {
			return name
		}
		return ""
	}
	return "SIGTERM"
}

type ColdSource struct {
	Writer   Activation
	NativeID string
	Exit     ProcessExit
}

// ClosedWriters returns durable historical facts only, including after native
// source deletion. It grants no access to files and does not assert that the
// source is currently cold. Restore consumers select the ORIGINAL recipe hash,
// never whichever writer happened to run most recently.
func (s *Activations) ClosedWriters(ready NativeReady) ([]ColdSource, error) {
	if ready.Verify() != nil || ready.Spec.Scope.Cluster != s.cluster || ready.Owner.Key != s.node {
		return nil, ErrActivation
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return nil, ErrActivation
	}
	s.mu.Lock()
	e := s.entries[ready.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		return nil, ErrActivation
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disk.Scope != ready.Spec.Scope || e.disk.Owner != ready.Owner {
		return nil, ErrActivation
	}
	var out []ColdSource
	for _, b := range e.disk.Bindings {
		if b.Ref.Consumer.Writable && b.Closed && b.Released && !b.Unsent && b.Exit != nil && b.Exit.Clean() {
			out = append(out, ColdSource{Writer: b.Ref, NativeID: b.NativeID, Exit: *b.Exit})
		}
	}
	return out, nil
}

// ColdSource reads only the latest original writable consumer's durable exit.
// All local activations must be closed/released and the exact source currently
// unmounted. Callers must also hold the shared cold reader and obtain current
// quorum authorization before/after copying. This never manufactures a clean
// source from container absence, a stopped flag, or an unobserved old record.
func (s *Activations) ColdSource(ctx context.Context, ready NativeReady) (ColdSource, error) {
	return s.coldSource(ctx, ready, true)
}

// StoppedSource is ColdSource without the clean-exit requirement: every
// writer is closed and released and no container uses the volume, but the
// last writer may have been killed. Only a move cancel uses it, because a
// cancel copies nothing and leaves the data where it is.
func (s *Activations) StoppedSource(ctx context.Context, ready NativeReady) (ColdSource, error) {
	return s.coldSource(ctx, ready, false)
}

func (s *Activations) coldSource(ctx context.Context, ready NativeReady, clean bool) (ColdSource, error) {
	var out ColdSource
	if ready.Verify() != nil || ready.Spec.Scope.Cluster != s.cluster || ready.Owner.Key != s.node {
		return out, activationProblem("ready-not-local")
	}
	if err := s.RetainReady(ctx, NativeKey(ready.Spec), ready.Spec.Scope, ready.Owner); err != nil {
		return out, err
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return out, activationProblem("closed")
	}
	s.mu.Lock()
	e := s.entries[ready.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		return out, activationProblem("no-activation")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disk.Scope != ready.Spec.Scope || e.disk.Owner != ready.Owner || e.disk.Gate.Starting != nil {
		return out, activationProblem("starting")
	}
	var latest *activationBinding
	for i := range e.disk.Bindings {
		b := &e.disk.Bindings[i]
		if !b.Closed || !b.Released {
			return out, activationProblem("binding-open")
		}
		if b.Ref.Consumer.Writable && !b.Unsent && (latest == nil || b.Ref.Consumer.Lease.Token > latest.Ref.Consumer.Lease.Token) {
			latest = b
		}
	}
	if latest == nil {
		return out, activationProblem("no-writer")
	}
	if clean && (latest.Exit == nil || !latest.Exit.Clean()) {
		return out, activationProblem("no-clean-exit")
	}
	got, err := s.client.API.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: client.Filters{}.Add("volume", ready.Owner.Native)})
	if err != nil {
		return out, errors.Join(activationProblem("container-list"), err)
	}
	if len(got.Items) != 0 {
		return out, activationProblem("container-uses-volume")
	}
	out = ColdSource{Writer: latest.Ref, NativeID: latest.NativeID}
	if latest.Exit != nil {
		out.Exit = *latest.Exit
	}
	return out, nil
}

// activationReason is a fixed name for why a cold source or fence check
// failed. It is still ErrActivation; the name is only for this server's log.
type activationReason string

func activationProblem(reason string) error { return activationReason(reason) }
func (a activationReason) Error() string    { return ErrActivation.Error() + ": " + string(a) }
func (a activationReason) Is(target error) bool {
	return target == ErrActivation
}

// ActivationReason returns the fixed reason inside err, or "".
func ActivationReason(err error) string {
	var a activationReason
	if errors.As(err, &a) {
		return string(a)
	}
	return ""
}

// PlanningWriter reads the currently held original writer recipe. It grants
// no clean-stop/file access/Start authority, and never substitutes an old closed
// writer when a current activation is missing or uncertain.
func (s *Activations) PlanningWriter(ready NativeReady) (Activation, error) {
	if ready.Verify() != nil || ready.Spec.Scope.Cluster != s.cluster || ready.Owner.Key != s.node {
		return Activation{}, ErrActivation
	}
	s.life.RLock()
	defer s.life.RUnlock()
	if s.closed {
		return Activation{}, ErrActivation
	}
	s.mu.Lock()
	e := s.entries[ready.Owner.Native]
	s.mu.Unlock()
	if e == nil {
		return Activation{}, ErrActivation
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.disk.Scope != ready.Spec.Scope || e.disk.Owner != ready.Owner || e.disk.Gate.Starting != nil {
		return Activation{}, ErrActivation
	}
	var out Activation
	for _, b := range e.disk.Bindings {
		if b.Ref.Consumer.Writable && !b.Closed && !b.Released && !b.Unsent && b.Started && validNativeID(b.NativeID) {
			if out.Consumer.ID != "" {
				return Activation{}, ErrActivation
			}
			out = b.Ref
		}
	}
	if out.Validate() != nil || out.NativeKey != NativeKey(ready.Spec) || out.NativeGeneration != ready.Generation {
		return Activation{}, ErrActivation
	}
	return out, nil
}
