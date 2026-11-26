// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jay94ks/mydcd/internal/schema"
	"github.com/jay94ks/mydcd/internal/storage"
)

const pushPrefix = "registry/push/"
const pushStateKey = pushPrefix + "state"

var ErrPushLeaseActive = errors.New("registry push lease active")
var ErrMaintenanceFence = errors.New("registry maintenance fence active")

type PushLease struct {
	Repository string
	ExpiresAt  int64
}
type PushFence struct {
	Operation string
	At        int64
}
type pushState struct {
	Schema    uint8
	Scope     Scope
	WarmUntil int64
	Leases    []PushLease
	Fence     *PushFence `json:",omitempty"`
}

func (p pushState) valid(scope Scope) bool {
	if p.Schema != 1 || p.Scope != scope || p.WarmUntil < 0 || len(p.Leases) > 16384 {
		return false
	}
	last := ""
	for _, lease := range p.Leases {
		if _, err := repoID(lease.Repository); err != nil || lease.Repository <= last || lease.ExpiresAt <= 0 {
			return false
		}
		last = lease.Repository
	}
	return p.Fence == nil || p.Fence.At > 0 && validImageActionScope(p.Fence.Operation, "registry.example")
}
func (m *Metadata) pushState() (pushState, error) {
	raw, err := m.db.GetBounded(pushStateKey, m.limits.TotalBytes)
	if err != nil {
		return pushState{}, err
	}
	value, err := schema.Decode[pushState](raw)
	if err != nil || !value.valid(m.scope) {
		return pushState{}, ErrStorage
	}
	return value, nil
}
func (s *Store) savePushState(value pushState) error {
	if !value.valid(s.Metadata.scope) {
		return ErrStorage
	}
	raw, _ := json.Marshal(value)
	changes := map[string][]byte{pushStateKey: raw}
	if err := s.maintenanceBudget(changes); err != nil {
		return err
	}
	if err := s.db.Write(changes); err != nil {
		s.Metadata.failed = true
		return ErrStorage
	}
	return nil
}
func (s *Store) initializePushState(ctx context.Context) error {
	s.Metadata.mu.Lock()
	defer s.Metadata.mu.Unlock()
	if s.Metadata.enter(ctx) != nil {
		return ErrStorage
	}
	_, err := s.Metadata.pushState()
	if err == nil {
		return nil
	}
	if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	// A legacy serving DB may have issued access tokens before this sidecar
	// existed. Persist one conservative maximum-token warmup, not a fresh timer
	// on every restart. A genuinely new owner DB has no historical tokens.
	value := pushState{Schema: 1, Scope: s.Metadata.scope}
	if !s.Metadata.fresh {
		value.WarmUntil = time.Now().Unix() + MaxGrantSeconds
	}
	return s.savePushState(value)
}

// RegisterPushLease runs only after current grant/account/run validation. It
// stores public repository/expiry metadata before a push token is returned or
// an existing push-capable token enters a request (including pull HEAD).
// No raw credential, Session, nonce, header or token is retained.
func (s *Store) RegisterPushLease(ctx context.Context, repo string, issued, expires, now int64, issuing bool) error {
	if _, err := repoID(repo); err != nil || now <= 0 || issued <= 0 || issued > now || expires <= now || expires-issued > MaxGrantSeconds {
		return ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStorage
	}
	m := s.Metadata
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enter(ctx) != nil {
		return ErrStorage
	}
	value, err := m.pushState()
	if err != nil {
		return err
	}
	var knownRepo int64
	for _, lease := range value.Leases {
		if lease.Repository == repo {
			knownRepo = lease.ExpiresAt
		}
	}
	known := max(value.WarmUntil, knownRepo)
	if value.Fence != nil {
		if issuing || issued > value.Fence.At || expires > known {
			return ErrMaintenanceFence
		}
		return nil // only an already covered finite old token may finish its request
	}
	if knownRepo >= expires {
		return nil
	} // HEAD/pull retries must not re-commit an unchanged window
	next := value.Leases[:0]
	found := false
	for _, lease := range value.Leases {
		if lease.ExpiresAt <= now {
			continue
		}
		if lease.Repository == repo {
			lease.ExpiresAt = max(lease.ExpiresAt, expires)
			found = true
		}
		next = append(next, lease)
	}
	if !found {
		next = append(next, PushLease{Repository: repo, ExpiresAt: expires})
	}
	slices.SortFunc(next, func(a, b PushLease) int { return strings.Compare(a.Repository, b.Repository) })
	value.Leases = next
	if len(next) > m.limits.Records {
		return ErrStorage
	}
	return s.savePushState(value)
}

// BeginWriteFence is owner work admission, not a user command. It stops new
// token issuance first; the owner may observe WaitUntil without blocking its
// reconcile loop. Restart retains the original fence/expiry floor.
func (s *Store) BeginWriteFence(ctx context.Context, operation string, now int64) (int64, error) {
	if !validImageActionScope(operation, "registry.example") || now <= 0 {
		return 0, ErrStorage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStorage
	}
	s.Metadata.mu.Lock()
	defer s.Metadata.mu.Unlock()
	if s.Metadata.enter(ctx) != nil {
		return 0, ErrStorage
	}
	return s.beginPushFence(operation, now)
}
func (s *Store) beginPushFence(operation string, now int64) (int64, error) {
	value, err := s.Metadata.pushState()
	if err != nil {
		return 0, err
	}
	if value.Fence != nil && value.Fence.Operation != operation {
		return 0, ErrMaintenanceFence
	}
	if value.Fence == nil {
		value.Fence = &PushFence{Operation: operation, At: now}
		if err = s.savePushState(value); err != nil {
			return 0, err
		}
	}
	until := value.WarmUntil
	for _, lease := range value.Leases {
		until = max(until, lease.ExpiresAt)
	}
	return until, nil
}

// EndWriteFence is for positively settled/no-effect owner jobs. An unfinished
// native GC intent cannot be abandoned; its original cleanup must finish.
func (s *Store) EndWriteFence(ctx context.Context, operation string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStorage
	}
	m := s.Metadata
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enter(ctx) != nil {
		return ErrStorage
	}
	raw, err := s.db.GetBounded(actionReceiptKey(gcPrefix, operation), 16<<20)
	if err == nil {
		receipt, e := schema.Decode[GCReceipt](raw)
		if e != nil || !receipt.Valid() || receipt.Scope != m.scope || receipt.State != "done" {
			return ErrStorage
		}
	} else if !errors.Is(err, storage.ErrMissing) {
		return err
	}
	value, err := m.pushState()
	if err != nil {
		return err
	}
	if value.Fence == nil {
		return nil
	}
	if value.Fence.Operation != operation {
		return ErrMaintenanceFence
	}
	value.Fence = nil
	return s.savePushState(value)
}

func clearPushFence(db *storage.DB, scope Scope, operation string, maxBytes int) ([]byte, error) {
	raw, err := db.GetBounded(pushStateKey, maxBytes)
	if err != nil {
		return nil, err
	}
	value, err := schema.Decode[pushState](raw)
	if err != nil || !value.valid(scope) || value.Fence == nil || value.Fence.Operation != operation {
		return nil, ErrStorage
	}
	value.Fence = nil
	return json.Marshal(value)
}
