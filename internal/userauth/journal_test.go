// SPDX-License-Identifier: Apache-2.0

package userauth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jay94ks/seafield/internal/access"
	"github.com/jay94ks/seafield/internal/cluster/control"
	"github.com/jay94ks/seafield/internal/cluster/state"
	"github.com/jay94ks/seafield/internal/identity"
	"github.com/jay94ks/seafield/internal/sfcp"
)

func journalFixture(t *testing.T) (string, Client, access.Session, *identity.Identity) {
	t.Helper()
	issuer, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(issuer.Private); clear(self.Private) })
	c := Client{Self: self, Cluster: [32]byte{84}, Peers: []sfcp.Peer{{ID: "node", Endpoint: "127.0.0.1:7443", Policy: sfcp.Policy{Key: sfcp.Identity(issuer.Public), Respond: true}}}}
	now := time.Now().Unix()
	s := access.Session{Schema: 1, ID: "session", Cluster: c.Cluster, User: "alice", Credential: "key", AccountRevision: 1, Key: self.Public, Issuer: issuer.Public, IssuerEpoch: 1, IssuedAt: now, ExpiresAt: now + 3600, Scopes: []access.Scope{{Tenant: "*", Actions: []access.Action{access.Read}}}}
	s.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(s))
	home := t.TempDir()
	if err = Save(home, c, s, ""); err != nil {
		t.Fatal(err)
	}
	return home, c, s, issuer
}

func journalOperation(t *testing.T, c Client, s access.Session, id string) control.UserOperation {
	t.Helper()
	op := control.UserOperation{Schema: 1, Session: s, At: s.IssuedAt, Epoch: 1, RequestID: id, RootRevision: 3, Change: control.Change{Schema: 1, Action: "create-tenant", Principal: s.User, Payload: json.RawMessage(`{"ID":"alpha"}`)}}
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	if op.VerifyOriginal(c.Cluster) != nil {
		t.Fatal("invalid operation fixture")
	}
	return op
}

func TestManagementJournalConcurrentImmutableOriginalAndCurrentUser(t *testing.T) {
	home, c, s, issuer := journalFixture(t)
	if _, err := LoadOperation(home, c, s, "original"); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("missing intent", err)
	}
	op := journalOperation(t, c, s, "original")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := StageOperation(home, c, op); errs <- err }()
	}
	wg.Wait()
	close(errs)
	succeeded := 0
	for err := range errs {
		if err == nil {
			succeeded++
		} else if !errors.Is(err, ErrPrivateState) {
			t.Fatal("concurrent original publication", err)
		}
	}
	if succeeded == 0 {
		t.Fatal("no original publication succeeded")
	}
	record, err := LoadOperation(home, c, s, op.RequestID)
	if err != nil || !sameOperation(record.Operation, op) {
		t.Fatal("original changed", err)
	}
	if _, err = json.Marshal(record); err == nil || fmt.Sprintf("%+v", record) != "[redacted management intent]" {
		t.Fatal("journal leaked by ordinary encoder")
	}
	different := op
	different.RootRevision++
	different.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(different))
	if _, err = StageOperation(home, c, different); err == nil {
		t.Fatal("request ID rebound to new CAS")
	}
	result := state.Result{Code: state.Applied, Index: 9, Revision: 4}
	if err = RecordOperationResult(home, c, s, op, result); err != nil {
		t.Fatal(err)
	}
	if err = RecordOperationResult(home, c, s, op, result); err != nil {
		t.Fatal("idempotent result", err)
	}
	wrong := result
	wrong.Index++
	if RecordOperationResult(home, c, s, op, wrong) == nil || RecordOperationResult(home, c, s, op, state.Result{Code: state.Expired, Index: 12}) == nil {
		t.Fatal("conflicting/expired result accepted")
	}
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(self.Private)
	current := s
	current.ID = "new-session"
	current.Key = self.Public
	current.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(current))
	newClient := c
	newClient.Self = self
	if err = Save(home, newClient, current, ""); err != nil {
		t.Fatal(err)
	}
	recovered, err := LoadOperation(home, newClient, current, op.RequestID)
	if err != nil || !sameOperation(recovered.Operation, op) || recovered.Result == nil || *recovered.Result != result {
		t.Fatal("new login replaced original", err)
	}
	other := current
	other.User = "bob"
	other.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(other))
	if _, err = LoadOperation(home, newClient, other, op.RequestID); err == nil {
		t.Fatal("another user inherited request")
	}
	wrongProfile := newClient
	wrongProfile.Peers = append([]sfcp.Peer(nil), c.Peers...)
	wrongProfile.Peers[0].Endpoint = "127.0.0.1:7444"
	if _, err = LoadOperation(home, wrongProfile, current, op.RequestID); err != nil {
		t.Fatal("a moved endpoint lost the cluster's request", err)
	}
	otherCluster := newClient
	otherCluster.Cluster[0] ^= 1
	if _, err = LoadOperation(home, otherCluster, current, op.RequestID); err == nil {
		t.Fatal("another cluster inherited request")
	}
}

func TestManagementJournalPrivateFilesTamperAndHistoricalUnknown(t *testing.T) {
	home, c, s, issuer := journalFixture(t)
	op := journalOperation(t, c, s, "original")
	// A historical original is still recoverable with a valid current session.
	op.Session.IssuedAt -= 7200
	op.Session.ExpiresAt -= 7200
	op.At -= 7200
	op.Session.Signature = ed25519.Sign(issuer.Private, access.SessionBytes(op.Session))
	op.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(op))
	// Initial stage requires a current signing session; create a historical file
	// at the explicit private writer boundary to model an earlier successful sync.
	r, err := operationRoot(home, c, s.User, true)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	record := operationRecord{Schema: 1, Profile: c.Profile(), User: s.User, Operation: op}
	name := operationName(op.RequestID)
	if err = writePrivate(r, name, record); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadOperation(home, c, s, op.RequestID); err != nil {
		t.Fatal("expired original lost", err)
	}
	if n, err := PruneOperations(home, c, s, 2); err != nil || n != 0 {
		t.Fatal("unknown expired original discarded", n, err)
	}
	info, err := r.Stat(name)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private mode", err)
	}
	path := r.Name() + "/" + name
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadOperation(home, c, s, op.RequestID); err == nil || errors.Is(err, ErrOperationMissing) {
		t.Fatal("unsafe file mistaken for absence")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = r.Rename(name, name+".good"); err != nil {
		t.Fatal(err)
	}
	if err = r.Symlink(name+".good", name); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadOperation(home, c, s, op.RequestID); err == nil || errors.Is(err, ErrOperationMissing) {
		t.Fatal("symlink accepted as original/missing")
	}
	if err = r.Remove(name); err != nil {
		t.Fatal(err)
	}
	if err = r.Rename(name+".good", name); err != nil {
		t.Fatal(err)
	}
	if err = r.Rename("session.lock", "old.lock"); err != nil {
		t.Fatal(err)
	}
	if err = r.Symlink("old.lock", "session.lock"); err != nil {
		t.Fatal(err)
	}
	if _, err = lockProfile(r); err == nil {
		t.Fatal("internal lock symlink accepted")
	}
	record.Operation.Change.Payload = json.RawMessage(`{"ID":"tampered"}`)
	if err = writePrivate(r, name, record); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadOperation(home, c, s, op.RequestID); err == nil || errors.Is(err, ErrOperationMissing) {
		t.Fatal("tampering accepted as original/missing")
	}
}

func TestManagementJournalBoundedWindowAndConfirmedOnlyPruning(t *testing.T) {
	home, c, s, _ := journalFixture(t)
	for i := 0; i < operationLimit; i++ {
		op := journalOperation(t, c, s, fmt.Sprintf("original-%d", i))
		if _, err := StageOperation(home, c, op); err != nil {
			t.Fatal(i, err)
		}
		if i == 0 {
			if err := RecordOperationResult(home, c, s, op, state.Result{Code: state.Forbidden, Index: 10}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := StageOperation(home, c, journalOperation(t, c, s, "overflow")); err == nil {
		t.Fatal("unbounded private journal")
	}
	rotate := journalOperation(t, c, s, "window")
	rotate.Change.Action = "rotate-ledger"
	rotate.Change.Payload = json.RawMessage(`{"NextEpoch":2}`)
	rotate.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(rotate))
	if _, err := StageOperation(home, c, rotate); err != nil {
		t.Fatal("maintenance slot unavailable", err)
	}
	second := rotate
	second.RequestID = "second-window"
	second.Signature = ed25519.Sign(c.Self.Private, control.OperationBytes(second))
	if _, err := StageOperation(home, c, second); err == nil {
		t.Fatal("extra unbounded maintenance slot")
	}
	if n, err := PruneOperations(home, c, s, 2); err != nil || n != 1 {
		t.Fatal("confirmed-only epoch reclamation", n, err)
	}
	if _, err := LoadOperation(home, c, s, "original-0"); !errors.Is(err, ErrOperationMissing) {
		t.Fatal("confirmed old intent not reclaimed", err)
	}
	for _, id := range []string{"original-1", "window"} {
		record, err := LoadOperation(home, c, s, id)
		if err != nil || record.Result != nil {
			t.Fatal("unknown intent reclaimed/settled", err)
		}
	}
	record, err := LoadOperation(home, c, s, "original-1")
	if err != nil || !bytes.Equal(record.Operation.Signature, journalOperation(t, c, s, "original-1").Signature) {
		t.Fatal("unknown signature changed", err)
	}
}
