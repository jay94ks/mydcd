// SPDX-License-Identifier: Apache-2.0

package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
)

// fakeLedger stands in for the Raft store with the same CAS rules: an
// absent-only put and a once-only consume.
type fakeLedger struct {
	mu      sync.Mutex
	ready   bool
	master  []byte
	records map[string]BuiltinRecord
}

func (l *fakeLedger) Cluster() [32]byte { return [32]byte{41} }
func (l *fakeLedger) Self() [32]byte    { return [32]byte{42} }
func (l *fakeLedger) Ready() bool       { return l.ready }
func (l *fakeLedger) Master() ([]byte, error) {
	return bytes.Clone(l.master), nil
}
func (l *fakeLedger) Record(_ context.Context, id string) (BuiltinRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.records[id]
	return r, ok, nil
}
func (l *fakeLedger) Put(_ context.Context, r BuiltinRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.records[r.ID]; ok || !r.Valid(l.Cluster()) || r.Sealer != l.Self() {
		return ErrDenied
	}
	l.records[r.ID] = r
	return nil
}
func (l *fakeLedger) Consume(_ context.Context, id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.records[id]
	if !ok || r.Consumed {
		return ErrDenied
	}
	r.Consumed = true
	l.records[id] = r
	return nil
}

func TestBuiltinStoreIssuesVerifiesAndConsumesOnceWithoutVault(t *testing.T) {
	ledger := &fakeLedger{ready: true, master: bytes.Repeat([]byte{7}, 32), records: map[string]BuiltinRecord{}}
	b, err := NewBackends(ledger, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b.DefaultProfile() != BuiltinProfile {
		t.Fatal("builtin is not the default without an external Vault")
	}
	r := InitialRequest{Schema: 1, Cluster: ledger.Cluster(), Owner: ledger.Self(), Operation: [32]byte{43}, User: "new-user", Username: "new.user", Credential: "first", Profile: BuiltinProfile, Method: access.Token, ExpectedUserRevision: 4, At: time.Now().Unix(), Seconds: 86400}
	if !b.Ready(r.Reference()) {
		t.Fatal("ready voter refused")
	}
	issued, err := b.PrepareInitial(context.Background(), r, nil, "admin-source", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer issued.Destroy()
	if err = b.ObserveInitial(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, err = b.PrepareInitial(context.Background(), r, nil, "admin-source", time.Now()); err == nil {
		t.Fatal("second write of the same intent")
	}
	stored, _ := json.Marshal(ledger.records)
	if bytes.Contains(stored, issued.Token) {
		t.Fatal("token in the store")
	}
	credential := r.CredentialRecord()
	u := access.User{ID: r.User, Username: r.Username, Enabled: true, Credentials: []access.Credential{credential}}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := b.Verify(context.Background(), r.Cluster, u, credential, issued.Token, "login-source", time.Now()); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("one-use successes=%d", successes.Load())
	}

	// A node that is not a voter cannot open the record, and says so before
	// any secret is sent.
	ledger.ready = false
	if b.Ready(r.Reference()) {
		t.Fatal("non-voter reported ready")
	}
	ledger.ready = true

	// A record opened with another master, or with changed public binding,
	// fails closed.
	for id, rec := range ledger.records {
		rec.User = "someone-else"
		if _, err := OpenBuiltin(ledger.master, rec); err == nil {
			t.Fatal("rebound record opened")
		}
		if _, err := OpenBuiltin(bytes.Repeat([]byte{6}, 32), ledger.records[id]); err == nil {
			t.Fatal("foreign master opened record")
		}
	}
}

func TestBuiltinProfileNameIsReservedForTheClusterStore(t *testing.T) {
	ledger := &fakeLedger{ready: true, master: bytes.Repeat([]byte{7}, 32), records: map[string]BuiltinRecord{}}
	external := &Backend{stores: map[string]Store{BuiltinProfile: builtinStore{ledger}}, budget: NewBudget()}
	if _, err := NewBackends(ledger, external); err == nil {
		t.Fatal("external store took the builtin name")
	}
	other := &Backend{stores: map[string]Store{"system": builtinStore{ledger}}, budget: NewBudget()}
	b, err := NewBackends(ledger, other)
	if err != nil || b.DefaultProfile() != "system" || !b.Has(BuiltinProfile) {
		t.Fatal("an installed external provider is the default, builtin stays", err)
	}
}
