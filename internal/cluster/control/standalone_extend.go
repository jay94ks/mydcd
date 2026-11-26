// SPDX-License-Identifier: Apache-2.0

package control

import (
	"errors"
	"math"

	"github.com/jay94ks/mydcd/internal/access"
	"github.com/jay94ks/mydcd/internal/cluster/lifecycle"
	"github.com/jay94ks/mydcd/internal/cluster/state"
	"github.com/jay94ks/mydcd/internal/deployment"
)

const StandaloneMaximumLifetimeSeconds int64 = 86400

var (
	ErrStandaloneExtensionLimit        = errors.New("STANDALONE_TTL_LIMIT")
	ErrStandaloneExtensionExpired      = errors.New("STANDALONE_TTL_EXPIRED")
	ErrStandaloneExtensionNotIncreased = errors.New("STANDALONE_TTL_NOT_INCREASED")
)

// StandaloneExtendChange fixes the original numeric result independently of
// later extensions or pin. Scope is the immutable internal workload name;
// Name is its public name when this operation was signed.
type StandaloneExtendChange struct {
	Tenant, Name, Scope, Operation           string
	CreatedAt, PreviousExpiresAt, TTLSeconds int64
	Target                                   [32]byte
}

func (q StandaloneExtendChange) valid() bool {
	return lifecycle.ValidID(q.Tenant) && lifecycle.ValidID(q.Name) && lifecycle.ValidID(q.Scope) && lifecycle.ValidID(q.Operation) && q.CreatedAt > 0 && q.PreviousExpiresAt > q.CreatedAt && q.TTLSeconds > 0 && q.Target != ([32]byte{})
}

// StandaloneExtensionPlan is public arithmetic, not an admission or a native
// command. AllowedTTLSeconds is the largest TTL at At; RemainingExtensionSeconds
// is the unused creation-time allowance after the proposed expiry (or after
// the unchanged previous expiry when the request is refused).
type StandaloneExtensionPlan struct {
	CreatedAt, At, PreviousExpiresAt, ProposedExpiresAt            int64
	MaximumExpiresAt, AllowedTTLSeconds, RemainingExtensionSeconds int64
}

// PlanStandaloneExtension uses only the supplied signed coordinates. It returns
// numeric bounds even for an over-limit or non-increasing request. No current
// wall clock, account authority or native state is inferred here.
func PlanStandaloneExtension(createdAt, expiresAt, at, ttl int64) (StandaloneExtensionPlan, error) {
	p := StandaloneExtensionPlan{CreatedAt: createdAt, At: at, PreviousExpiresAt: expiresAt}
	if createdAt <= 0 || createdAt > math.MaxInt64-StandaloneMaximumLifetimeSeconds || at < createdAt || expiresAt <= createdAt {
		return p, access.ErrInvalid
	}
	p.MaximumExpiresAt = createdAt + StandaloneMaximumLifetimeSeconds
	p.AllowedTTLSeconds = max(0, p.MaximumExpiresAt-at)
	p.RemainingExtensionSeconds = max(0, p.MaximumExpiresAt-expiresAt)
	if expiresAt > p.MaximumExpiresAt || ttl <= 0 || ttl > math.MaxInt64-at {
		return p, access.ErrInvalid
	}
	p.ProposedExpiresAt = at + ttl
	if at >= expiresAt {
		return p, ErrStandaloneExtensionExpired
	}
	if ttl > p.AllowedTTLSeconds {
		return p, ErrStandaloneExtensionLimit
	}
	if p.ProposedExpiresAt <= expiresAt {
		return p, ErrStandaloneExtensionNotIncreased
	}
	p.RemainingExtensionSeconds = p.MaximumExpiresAt - p.ProposedExpiresAt
	return p, nil
}

// StandaloneExtensionResult reconstructs the ORIGINAL proposed result. A caller
// must still look up that operation's committed state.Result before describing
// it as successful; this helper alone grants no effect or successful receipt.
func StandaloneExtensionResult(op UserOperation) (StandaloneExtensionPlan, error) {
	var q StandaloneExtendChange
	if op.Change.Action != "standalone-extend" || !StandaloneCASAllowed(op.Change) || canonical(op.Change.Payload, &q) != nil || !q.valid() || op.VerifyOriginal(op.Session.Cluster) != nil {
		return StandaloneExtensionPlan{}, access.ErrInvalid
	}
	return PlanStandaloneExtension(q.CreatedAt, q.PreviousExpiresAt, op.At, q.TTLSeconds)
}

func (p Policy) authorizeStandaloneExtension(c access.Catalog, op UserOperation) error {
	var q StandaloneExtendChange
	if canonical(op.Change.Payload, &q) != nil || !q.valid() {
		return access.ErrInvalid
	}
	if c.OperationAllowed(op.Session, op.Change.Action) != nil {
		return access.ErrDenied
	}
	return c.AuthorizeSession(op.Session, p.Cluster, p.Issuer(op.Session.Issuer), op.At, q.Tenant, access.Deploy, "")
}

func (p Policy) reduceStandaloneExtension(s state.State, a Apps, c access.Catalog, op UserOperation) (map[string][]byte, state.Code) {
	var q StandaloneExtendChange
	if canonical(op.Change.Payload, &q) != nil || !q.valid() {
		return nil, state.Invalid
	}
	key, entry, found := a.standalone(q.Tenant, q.Name)
	if !found || !standaloneActor(c, entry, op.Session.User) || !StandaloneCASAllowed(op.Change) || op.Change.Expected > entry.Standalone.Revision || q.Target != entry.standaloneTarget() {
		return nil, state.ConditionFailed
	}
	m := *entry.Standalone
	if m.Lifetime != "temp" || m.Desired != "running" || m.Cleanup != nil || entry.Down != nil || q.Scope != m.Scope || q.CreatedAt != m.CreatedAt || q.PreviousExpiresAt != m.ExpiresAt || m.LastExtension != nil && op.At < m.LastExtension.At {
		return nil, state.ConditionFailed
	}
	if _, retiring := entry.Inventory.Retirement(); retiring {
		return nil, state.ConditionFailed
	}
	plan, err := PlanStandaloneExtension(q.CreatedAt, q.PreviousExpiresAt, op.At, q.TTLSeconds)
	if err != nil {
		return nil, state.ConditionFailed
	}
	m.ExpiresAt = plan.ProposedExpiresAt
	m.Revision++
	m.LastExtension = &op
	entry.Standalone = &m
	a.entries[key] = entry
	return p.appsCheckpoint(s, a, uint64(op.At))
}

// A bounded last proof authenticates the new expiry without becoming the
// workload's accepted authority or the pin policy issuer. Generic operation
// receipts/history retain earlier outcomes; this is not a second history.
func validStandaloneExtension(m *StandaloneMetadata, scope deployment.AppScope) bool {
	if m.LastExtension == nil {
		return true
	}
	op := *m.LastExtension
	var q StandaloneExtendChange
	if op.VerifyOriginal(scope.Cluster) != nil || canonical(op.Change.Payload, &q) != nil || !q.valid() || op.Change.Action != "standalone-extend" || !StandaloneCASAllowed(op.Change) || op.Change.Expected >= m.Revision || q.Tenant != scope.Tenant || q.Scope != scope.App || q.CreatedAt != m.CreatedAt {
		return false
	}
	plan, err := StandaloneExtensionResult(op)
	if err != nil {
		return false
	}
	if m.Lifetime == "temp" {
		return q.Name == m.Name && plan.ProposedExpiresAt == m.ExpiresAt && m.LastChange == nil
	}
	// Pin preserves this previous extension proof while changing lifetime and
	// possibly public name. Its original signed pin names the pre-pin owner.
	if m.Lifetime != "fixed" || m.LastChange == nil || m.LastChange.At < op.At || m.LastChange.Change.Expected <= op.Change.Expected {
		return false
	}
	var pin StandaloneChange
	return canonical(m.LastChange.Change.Payload, &pin) == nil && pin.Name == q.Name
}

// CheckStandaloneExtensionSubmission rejects a new, unconfirmed submission
// after the current expiry. The adapter supplies now after authenticating its
// current request and looking up the original receipt. The deterministic
// reducer still consumes only op.At; this check never mutates state or signs
// another operation. An existing original receipt always keeps its outcome.
func (p Policy) CheckStandaloneExtensionSubmission(s state.State, op UserOperation, now int64) error {
	if op.Change.Action != "standalone-extend" {
		return nil
	}
	current, err := p.Current(s)
	if err != nil {
		return err
	}
	p = current
	cmd, err := op.Command()
	if err != nil || op.VerifyOriginal(p.Cluster) != nil {
		return access.ErrDenied
	}
	if _, found := s.LookupResult(cmd); found {
		return nil
	}
	if now < 0 {
		return access.ErrInvalid
	}
	c, err := p.Catalog(s)
	if err != nil {
		return err
	}
	if _, err := p.Operation(c, cmd, false); err != nil || p.authorizeStandaloneExtension(c, op) != nil {
		return access.ErrDenied
	}
	var q StandaloneExtendChange
	if canonical(op.Change.Payload, &q) != nil || !q.valid() {
		return access.ErrInvalid
	}
	a, err := p.readOnlyApps(s)
	if err != nil {
		return err
	}
	_, entry, found := a.standalone(q.Tenant, q.Name)
	if !found || q.Scope != entry.Standalone.Scope || q.CreatedAt != entry.Standalone.CreatedAt || !standaloneActor(c, entry, op.Session.User) {
		return access.ErrDenied
	}
	if entry.Standalone.Desired != "running" || entry.Standalone.Cleanup != nil || entry.Down != nil {
		return access.ErrDenied
	}
	if _, retiring := entry.Inventory.Retirement(); retiring {
		return access.ErrDenied
	}
	if entry.Standalone.Lifetime == "temp" && now >= entry.Standalone.ExpiresAt {
		return ErrStandaloneExtensionExpired
	}
	return nil
}

func validStandaloneExtensionOrigin(entry appEntry) bool {
	m := entry.Standalone
	if m == nil || m.LastExtension == nil && m.Lifetime != "temp" {
		return true
	}
	var begin AppBegin
	if entry.Origin.Change.Action != "standalone-up" || canonical(entry.Origin.Change.Payload, &begin) != nil || begin.Standalone == nil || m.CreatedAt != entry.Origin.At {
		return false
	}
	if m.LastExtension != nil {
		return true
	}
	// Legacy temp has no extension proof: its expiry is still the TTL from
	// its signed original acceptance. Dropping a new extension proof cannot
	// launder the changed expiry into this legacy case.
	original, err := begin.Standalone.metadata(entry.Inventory.Scope().Tenant, m.Creator, m.Node, entry.Origin.At)
	return err == nil && original.Lifetime == "temp" && original.ExpiresAt == m.ExpiresAt
}
