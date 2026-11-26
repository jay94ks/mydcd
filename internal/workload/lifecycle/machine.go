// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"

	contract "github.com/jay94ks/mydcd/lifecycle/v1"
)

// Timing is normalized milliseconds supplied by the app/policy resolver.
// FreshForMS bounds observations; it is not a process termination deadline.
type Timing struct {
	IntervalMS, TimeoutMS, StartPeriodMS, FreshForMS int64
	Retries                                          uint32
}

func (t Timing) valid() bool {
	return t.IntervalMS > 0 && t.TimeoutMS > 0 && t.StartPeriodMS >= 0 && t.FreshForMS > 0 && t.Retries > 0 && t.Retries <= 1000
}

// Definition is one immutable, prepared binding. RunID and deadline in its
// Request are empty; each Plan derives them without changing the source/target.
// A replacement binding retires/settles this one, never rewrites an active run.
type Definition struct {
	Scope          string `json:",omitempty"` // empty: app; otherwise one service
	ProgramDigest  string `json:",omitempty"`
	Request        contract.Request
	Timing         Timing
	PolicyRevision uint64
	Stop           *ShutdownScope `json:",omitempty"`
}

// ShutdownScope binds a one-shot check to its accepted retirement, without
// exposing a new script entrypoint or changing existing SDK1 request bytes.
type ShutdownScope struct {
	Operation string
	Revision  uint64
}

func (d Definition) Validate() error {
	if d.Stop != nil && (d.Request.Phase != contract.Shutdown || !text(d.Stop.Operation, 256) || d.Stop.Revision == 0) {
		return ErrContract
	}
	if d.ProgramDigest != "" && !digest(d.ProgramDigest) {
		return ErrContract
	}
	if d.Request.RunID != "" || d.Request.DeadlineUnixMilli != 0 || !d.Timing.valid() || d.PolicyRevision == 0 || d.Scope != "" && (!name(d.Scope) || len(d.Request.Targets) != 1 || d.Request.Targets[0].Service != d.Scope) {
		return ErrContract
	}
	return validateRequestFields(d.Request)
}

func (d Definition) Digest() [32]byte {
	raw, _ := json.Marshal(d)
	return sha256.Sum256(append([]byte("mydc-checker-binding-1\x00"), raw...))
}

type RunPhase string

const (
	Prepared   RunPhase = "prepared"
	Dispatched RunPhase = "dispatched"
)

type Run struct {
	Sequence      uint64
	Phase         RunPhase
	PreparedAt    int64
	Request       contract.Request
	RequestDigest [32]byte
}

type Observation struct {
	Run    Run
	Result contract.Result
	At     int64
}

type Checkpoint struct {
	Schema             uint8
	Definition         Definition
	StartedAt, Clock   int64
	NextAt             int64
	Sequence           uint64
	Active             *Run
	Last               *Observation
	Failures           uint32
	Published          contract.Status
	EverPassed, Retire bool
}

// Machine admits external state only through New/Restore and returns owned
// copies. Private schema checks reject its zero value without rehashing the
// unchanged request/definition on every health observation.
type Machine struct{ d Checkpoint }

func addTime(a, b int64) (int64, error) {
	if a <= 0 || b < 0 || a > math.MaxInt64-b {
		return 0, ErrClock
	}
	return a + b, nil
}

func ownRun(r Run) Run { r.Request = ownRequest(r.Request); return r }

func ownCheckpoint(d Checkpoint) Checkpoint {
	d.Definition.Request = ownRequest(d.Definition.Request)
	if d.Definition.Stop != nil {
		stop := *d.Definition.Stop
		d.Definition.Stop = &stop
	}
	if d.Active != nil {
		r := ownRun(*d.Active)
		d.Active = &r
	}
	if d.Last != nil {
		o := *d.Last
		o.Run = ownRun(o.Run)
		d.Last = &o
	}
	return d
}

func New(d Definition, startedAt int64) (Machine, error) {
	if d.Validate() != nil {
		return Machine{}, ErrContract
	}
	if _, err := addTime(startedAt, d.Timing.StartPeriodMS); err != nil {
		return Machine{}, err
	}
	return Restore(Checkpoint{Schema: contract.Schema, Definition: d, StartedAt: startedAt, Clock: startedAt, NextAt: startedAt, Published: contract.Unknown})
}

func (m Machine) Checkpoint() Checkpoint { return ownCheckpoint(m.d) }

func (m Machine) Validate() error {
	_, err := Restore(m.d)
	return err
}

func expectedRun(d Definition, sequence uint64, at int64) (Run, error) {
	deadline, err := addTime(at, d.Timing.TimeoutMS)
	if err != nil || sequence == 0 {
		return Run{}, ErrClock
	}
	binding := d.Digest()
	raw := append([]byte("mydc-checker-run-1\x00"), binding[:]...)
	raw = binary.LittleEndian.AppendUint64(raw, sequence)
	r := ownRequest(d.Request)
	runHash := sha256.Sum256(raw)
	r.RunID = hex.EncodeToString(runHash[:])
	r.DeadlineUnixMilli = deadline
	if err := ValidateRequest(r); err != nil {
		return Run{}, err
	}
	return Run{Sequence: sequence, Phase: Prepared, PreparedAt: at, Request: r, RequestDigest: requestDigest(r)}, nil
}

// ValidateRun is the same deterministic binding check used by Restore and
// remote native authorization. It does not grant transport or native rights.
func ValidateRun(d Definition, r Run) error {
	if d.Validate() != nil {
		return ErrContract
	}
	want, err := expectedRun(d, r.Sequence, r.PreparedAt)
	if err != nil || r.Phase != Prepared && r.Phase != Dispatched || ValidateRequest(r.Request) != nil || want.RequestDigest != r.RequestDigest || requestDigest(r.Request) != r.RequestDigest || want.Request.RunID != r.Request.RunID {
		return ErrContract
	}
	return nil
}

func Restore(d Checkpoint) (Machine, error) {
	if d.Schema != contract.Schema || d.Definition.Validate() != nil || d.StartedAt <= 0 || d.Clock < d.StartedAt || d.NextAt < d.StartedAt || !validStatus(d.Published) || d.Failures > d.Definition.Timing.Retries {
		return Machine{}, ErrContract
	}
	if _, err := addTime(d.StartedAt, d.Definition.Timing.StartPeriodMS); err != nil {
		return Machine{}, err
	}
	if d.Active != nil && (ValidateRun(d.Definition, *d.Active) != nil || d.Active.Sequence != d.Sequence || d.Active.PreparedAt > d.Clock || d.Active.PreparedAt < d.StartedAt) {
		return Machine{}, ErrContract
	}
	if d.Last != nil {
		o := d.Last
		if ValidateRun(d.Definition, o.Run) != nil || o.Run.Phase != Dispatched || ValidateResult(o.Result) != nil || o.Run.Sequence > d.Sequence || o.Run.PreparedAt < d.StartedAt || o.At < o.Run.PreparedAt || o.At > d.Clock || o.At > d.NextAt || d.Active != nil && o.Run.Sequence >= d.Active.Sequence || o.At >= o.Run.Request.DeadlineUnixMilli && (o.Result.Status != contract.Unknown || o.Result.Reason != "deadline-expired") {
			return Machine{}, ErrContract
		}
		switch o.Result.Status {
		case contract.Pass:
			if !d.EverPassed || d.Published != contract.Pass || d.Failures != 0 {
				return Machine{}, ErrContract
			}
		case contract.Unknown:
			if d.Published != contract.Unknown || d.Failures != 0 {
				return Machine{}, ErrContract
			}
		case contract.Fail:
			graceEnd, _ := addTime(d.StartedAt, d.Definition.Timing.StartPeriodMS)
			if !d.EverPassed && o.At < graceEnd {
				if d.Failures != 0 || d.Published != contract.Unknown {
					return Machine{}, ErrContract
				}
			} else if d.Failures == 0 || d.Failures < d.Definition.Timing.Retries && d.Published == contract.Fail || d.Failures == d.Definition.Timing.Retries && d.Published != contract.Fail {
				return Machine{}, ErrContract
			}
		}
	} else if d.Failures != 0 || d.Published != contract.Unknown || d.EverPassed {
		return Machine{}, ErrContract
	}
	if d.Sequence == 0 && (d.Active != nil || d.Last != nil || d.Clock != d.StartedAt || d.NextAt != d.StartedAt) {
		return Machine{}, ErrContract
	}
	if d.Published == contract.Pass && !d.EverPassed || d.Published == contract.Fail && d.Failures != d.Definition.Timing.Retries || d.Definition.Request.Phase == contract.Startup && d.EverPassed && (d.Active != nil || d.Last.Result.Status != contract.Pass) {
		return Machine{}, ErrContract
	}
	return Machine{d: ownCheckpoint(d)}, nil
}

// Plan returns Prepared state. The owner must sync it before Dispatch, and
// sync Dispatched before spawning a helper. A timeout never clears Active.
func (m Machine) Plan(now int64) (Machine, Run, error) {
	if m.d.Schema != contract.Schema {
		return m, Run{}, ErrContract
	}
	if now < m.d.Clock {
		return m, Run{}, ErrClock
	}
	if m.d.Retire {
		return m, Run{}, ErrRetiring
	}
	if m.d.Active != nil {
		return m, Run{}, ErrPending
	}
	if now < m.d.NextAt || m.d.Definition.Request.Phase == contract.Startup && m.d.EverPassed {
		return m, Run{}, ErrNotDue
	}
	if m.d.Sequence == math.MaxUint64 {
		return m, Run{}, ErrContract
	}
	r, err := expectedRun(m.d.Definition, m.d.Sequence+1, now)
	if err != nil {
		return m, Run{}, err
	}
	d := m.Checkpoint()
	d.Active, d.Sequence, d.Clock = &r, r.Sequence, now
	return Machine{d: d}, ownRun(r), nil
}

func (m Machine) Dispatch(id string) (Machine, error) {
	if m.d.Schema != contract.Schema {
		return m, ErrContract
	}
	if m.d.Retire {
		return m, ErrRetiring
	}
	if m.d.Active == nil || m.d.Active.Request.RunID != id || m.d.Active.Phase != Prepared {
		return m, ErrStale
	}
	d := m.Checkpoint()
	d.Active.Phase = Dispatched
	return Machine{d: d}, nil
}

// CancelPrepared uses only the positive pre-dispatch state. It cannot settle a
// dispatched run, an unknown helper or a container exec that may still run.
func (m Machine) CancelPrepared(id string, now int64) (Machine, error) {
	if m.d.Schema != contract.Schema {
		return m, ErrContract
	}
	if now < m.d.Clock {
		return m, ErrClock
	}
	if m.d.Active == nil || m.d.Active.Phase != Prepared || m.d.Active.Request.RunID != id {
		return m, ErrPending
	}
	next, err := addTime(now, m.d.Definition.Timing.IntervalMS)
	if err != nil {
		return m, err
	}
	d := m.Checkpoint()
	d.Active, d.Clock, d.NextAt = nil, now, next
	return Machine{d: d}, nil
}

type Completion struct {
	RunID                      string
	RequestDigest              [32]byte
	Result                     contract.Result
	At                         int64
	HelperExited, ProbesClosed bool
}

// Finish must be persisted with its immutable Observation receipt in the SAME
// local DB transaction. Neither elapsed deadline nor helper exit alone proves
// that the run's container exec/probes have ended.
func (m Machine) Finish(c Completion) (Machine, Observation, error) {
	if m.d.Schema != contract.Schema {
		return m, Observation{}, ErrContract
	}
	if m.d.Active == nil {
		if o := m.d.Last; o != nil && o.Run.Request.RunID == c.RunID && o.Run.RequestDigest == c.RequestDigest && o.Result == c.Result && c.HelperExited && c.ProbesClosed {
			copy := *o
			copy.Run = ownRun(o.Run)
			return Machine{d: m.Checkpoint()}, copy, nil // replay cannot refresh At
		}
		return m, Observation{}, ErrStale
	}
	r := m.d.Active
	if r.Phase != Dispatched || r.Request.RunID != c.RunID || r.RequestDigest != c.RequestDigest {
		return m, Observation{}, ErrStale
	}
	if !c.HelperExited || !c.ProbesClosed {
		return m, Observation{}, ErrPending
	}
	if c.At < m.d.Clock {
		return m, Observation{}, ErrClock
	}
	if ValidateResult(c.Result) != nil {
		return m, Observation{}, ErrContract
	}
	if c.At >= r.Request.DeadlineUnixMilli {
		c.Result = contract.Result{Schema: contract.Schema, Status: contract.Unknown, Reason: "deadline-expired"}
	}
	next, err := addTime(c.At, m.d.Definition.Timing.IntervalMS)
	if err != nil {
		return m, Observation{}, err
	}
	d := m.Checkpoint()
	o := Observation{Run: ownRun(*r), Result: c.Result, At: c.At}
	d.Active, d.Last, d.Clock, d.NextAt = nil, &o, c.At, next
	switch c.Result.Status {
	case contract.Pass:
		d.Failures, d.Published, d.EverPassed = 0, contract.Pass, true
	case contract.Unknown:
		d.Failures, d.Published = 0, contract.Unknown
	case contract.Fail:
		graceEnd, _ := addTime(d.StartedAt, d.Definition.Timing.StartPeriodMS)
		if !d.EverPassed && c.At < graceEnd {
			d.Failures, d.Published = 0, contract.Unknown
		} else {
			d.Failures = min(d.Failures+1, d.Definition.Timing.Retries)
			if d.Failures == d.Definition.Timing.Retries {
				d.Published = contract.Fail
			} else if m.Status(c.At) != contract.Pass {
				// A new failed sample must not revive an already expired pass
				// merely because the retry threshold has not been reached.
				d.Published = contract.Unknown
			}
		}
	}
	return Machine{d: d}, Observation{Run: ownRun(o.Run), Result: o.Result, At: o.At}, nil
}

func (m Machine) Retire() (Machine, error) {
	if m.d.Schema != contract.Schema {
		return m, ErrContract
	}
	d := m.Checkpoint()
	d.Retire = true
	return Machine{d: d}, nil
}

func (m Machine) Closed() bool {
	return m.d.Schema == contract.Schema && m.d.Retire && m.d.Active == nil
}

// Replace is the same logical checker's next binding. The owner uses it only
// after authorizing current material and closing every old helper/probe. The
// sequence floor survives policy/target changes, so returning to an old source
// cannot reuse a previously dispatched run ID or its completion.
func (m Machine) Replace(d Definition, startedAt int64) (Machine, error) {
	if m.d.Schema != contract.Schema {
		return m, ErrContract
	}
	if !m.Closed() {
		return m, ErrPending
	}
	old := m.d.Definition.Request
	if d.Validate() != nil || d.Scope != m.d.Definition.Scope || d.Request.Phase != old.Phase || d.Request.Cluster != old.Cluster || d.Request.Tenant != old.Tenant || d.Request.App != old.App || d.Request.Checker != old.Checker || d.PolicyRevision < m.d.Definition.PolicyRevision || d.Digest() == m.d.Definition.Digest() {
		return m, ErrContract
	}
	if startedAt < m.d.Clock {
		return m, ErrClock
	}
	next, err := New(d, startedAt)
	if err != nil {
		return m, err
	}
	next.d.Sequence = m.d.Sequence
	return next, nil
}

func (m Machine) Status(now int64) contract.Status {
	if m.d.Schema != contract.Schema || m.d.Retire || now < m.d.Clock || m.d.Last == nil || m.d.Active != nil && now >= m.d.Active.Request.DeadlineUnixMilli {
		return contract.Unknown
	}
	if m.d.Definition.Request.Phase == contract.Startup && m.d.EverPassed {
		return contract.Pass
	}
	if now-m.d.Last.At > m.d.Definition.Timing.FreshForMS {
		return contract.Unknown
	}
	return m.d.Published
}
