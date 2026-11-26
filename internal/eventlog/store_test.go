// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jay94ks/mydcd/internal/identity"
	"github.com/jay94ks/mydcd/internal/storage"
)

func fixture(t *testing.T, node string) (*Store, *storage.DB) {
	t.Helper()
	self, err := identity.Ephemeral()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(self.Private) })
	db, err := storage.Open(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s, err := Open(db, [32]byte{11}, node, self)
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}
func taskEvent(at uint64, tenant, kind string) Event {
	return Event{Kind: kind, Scope: "app", At: at, Target: Target{Tenant: tenant, App: "app", Service: "web", Task: "workload/task/" + tenant + "/app/web", Native: "native", Node: "node-a", Generation: 1, Revision: 1}, Detail: Detail{Reason: "exit"}}
}
func accept(Record) bool { return true }

func TestScopedEventCursorOrdersThreeRestartsAndSurvivesReopen(t *testing.T) {
	s, db := fixture(t, "node-a")
	now := uint64(100000)
	for i := range 3 {
		if _, err := s.Append(string(rune('a'+i)), taskEvent(now+uint64(i), "tenant", "task-restarted"), now+3); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Append("foreign", taskEvent(now+4, "other", "task-exited"), now+4); err != nil {
		t.Fatal(err)
	}
	q := Query{Tenant: "tenant", Limit: 1}
	var ids []string
	for range 3 {
		page, err := s.Page(q, now+5, accept)
		if err != nil || len(page.Items) != 1 {
			t.Fatal("scoped page", err)
		}
		ids = append(ids, page.Items[0].ID)
		q.After = page.Cursor
	}
	if ids[0] == ids[1] || ids[1] == ids[2] {
		t.Fatal("short restarts coalesced")
	}
	page, err := s.Page(q, now+5, accept)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("foreign event leaked", err)
	}
	q.After = page.Cursor
	reopened, err := Open(db, s.m.Cluster, s.m.Node, s.self)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.Page(q, now+6, accept); err != nil {
		t.Fatal("same original DB cursor lost", err)
	}
	wrong := q
	wrong.Tenant = "other"
	if _, err = s.Page(wrong, now+6, accept); !errors.Is(err, ErrInvalid) {
		t.Fatal("scope rebound", err)
	}
	if _, err = s.Page(q, now+RetentionMillis+100, accept); !errors.Is(err, ErrCursorExpired) {
		t.Fatal("expired cursor accepted", err)
	}
	if _, err = s.Append("new", taskEvent(now+RetentionMillis+100, "tenant", "task-exited"), now+RetentionMillis+100); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Page(q, now+RetentionMillis+100, accept); !errors.Is(err, ErrCursorExpired) {
		t.Fatal("pruned source cursor accepted", err)
	}
}

func TestSourceReplayAndSameCommittedEventAcrossNodesAreDeduplicated(t *testing.T) {
	a, _ := fixture(t, "node-a")
	b, _ := fixture(t, "node-b")
	receiver, _ := fixture(t, "node-c")
	e := taskEvent(1000, "tenant", "task-restarted")
	sum := sha256.Sum256([]byte("public-raft-index-and-slot"))
	e.Authority = hex.EncodeToString(sum[:])
	ra, err := a.Append("committed-a", e, 1000)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.Append("committed-b", e, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ra.ID() == rb.ID() || ra.PublicID() != rb.PublicID() {
		t.Fatal("source and public identities confused")
	}
	for _, source := range []*Store{a, b, a} {
		batch, err := source.Export(0, 1001)
		if err != nil {
			t.Fatal(err)
		}
		if err = receiver.Receive(batch, 1001); err != nil {
			t.Fatal(err)
		}
	}
	page, err := receiver.Page(Query{Tenant: "tenant"}, 1002, accept)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != ra.PublicID() {
		t.Fatal("duplicate committed observation", err)
	}
	for _, source := range []*Store{a, b} {
		receipt, err := receiver.Receipt(source.Source())
		if err != nil || receipt.Last != 1 {
			t.Fatal("duplicate source prefix not acknowledged", err)
		}
	}
	batch, _ := a.Export(0, 1002)
	batch.Records[0].Event.Detail.Code = "FORGED"
	if receiver.Receive(batch, 1002) == nil {
		t.Fatal("tampered event accepted")
	}
}

func TestEventAndSourcePositionAreAtomicAndGapsExpireExistingCursors(t *testing.T) {
	s, db := fixture(t, "node-a")
	now := uint64(2000)
	r, err := s.AppendRelated("exit", taskEvent(now, "tenant", "task-exited"), now, map[string][]byte{"source/position": []byte("1")})
	if err != nil {
		t.Fatal(err)
	}
	if raw, err := db.Get("source/position"); err != nil || string(raw) != "1" {
		t.Fatal("source cursor not stored", err)
	}
	page, err := s.Page(Query{Tenant: "tenant"}, now, accept)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := s.AppendRelated("exit", taskEvent(now+1, "tenant", "task-exited"), now+1, map[string][]byte{"source/position": []byte("2")})
	if err != nil || duplicate.ID() != r.ID() {
		t.Fatal("original source record was replaced", err)
	}
	if _, err = s.AppendRelated("escape", taskEvent(now, "tenant", "task-exited"), now, map[string][]byte{metaKey: []byte("bad")}); err == nil {
		t.Fatal("source overwrote journal metadata")
	}
	gap := Event{Kind: "event-source-gap", Scope: "node", At: now + 2, Target: Target{Node: "node-a"}, Detail: Detail{Code: "SOURCE_GAP"}}
	if _, err = s.Append("gap", gap, now+2); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Page(Query{Tenant: "tenant", After: page.Cursor}, now+2, accept); !errors.Is(err, ErrCursorExpired) {
		t.Fatal("silent collection hole", err)
	}
	fresh, err := s.Page(Query{Tenant: "tenant"}, now+2, accept)
	if err != nil || !fresh.Incomplete || len(fresh.Items) != 1 {
		t.Fatal("explicit reset lost gap metadata", err)
	}
	history, incomplete, err := s.History("tenant", "app", "workload/task/tenant/app/web", 20, now+2)
	if err != nil || !incomplete || len(history) != 1 || history[0].ID != r.PublicID() {
		t.Fatal("detail history/event identities differ", err)
	}
	public, _ := json.Marshal(fresh)
	for _, forbidden := range []string{"Signature", "SourceKey", "PrivateKey", "Password", "Environment"} {
		if bytes.Contains(public, []byte(forbidden)) {
			t.Fatal("non-public event field", forbidden)
		}
	}
}

func TestPermissionMatchingPrecedesEventPageLimit(t *testing.T) {
	s, _ := fixture(t, "node-a")
	for i, tenant := range []string{"other", "tenant", "other", "tenant"} {
		if _, err := s.Append(string(rune('a'+i)), taskEvent(3000+uint64(i), tenant, "task-exited"), 3004); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.Page(Query{Limit: 1}, 3005, func(r Record) bool { return r.Event.Target.Tenant == "tenant" })
	if err != nil || len(page.Items) != 1 || page.Items[0].Target.Tenant != "tenant" || !page.More {
		t.Fatal("private row consumed page budget", err)
	}
}

func TestBatchDedupUsesPendingWritesAndRejectsConflictingAuthorityAtomically(t *testing.T) {
	source, _ := fixture(t, "node-a")
	e := taskEvent(4000, "tenant", "task-restarted")
	digest := sha256.Sum256([]byte("committed-transition"))
	e.Authority = hex.EncodeToString(digest[:])
	if _, err := source.Append("first", e, 4000); err != nil {
		t.Fatal(err)
	}
	batch, err := source.Export(0, 4001)
	if err != nil {
		t.Fatal(err)
	}
	second := batch.Records[0]
	second.Sequence = 2
	tag := sha256.Sum256([]byte("second-source-position"))
	second.Tag = hex.EncodeToString(tag[:])
	second.Signature = ed25519.Sign(source.self.Private, SigningBytes(second))
	batch.Last = 2
	batch.Records = append(batch.Records, second)
	batch.Signature = ed25519.Sign(source.self.Private, BatchBytes(batch))
	if !batch.Valid() {
		t.Fatal("signed duplicate fixture invalid")
	}
	receiver, db := fixture(t, "node-b")
	if err = receiver.Receive(batch, 4001); err != nil {
		t.Fatal(err)
	}
	page, err := receiver.Page(Query{Tenant: "tenant"}, 4002, accept)
	if err != nil || len(page.Items) != 1 {
		t.Fatal("in-batch committed duplicate emitted twice", err)
	}
	receipt, err := receiver.Receipt(source.Source())
	if err != nil || receipt.Last != 2 {
		t.Fatal("deduplicated source suffix not acknowledged", err)
	}
	reopened, err := Open(db, receiver.m.Cluster, receiver.m.Node, receiver.self)
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.Receive(batch, 4002); err != nil {
		t.Fatal("exact source replay rejected", err)
	}
	// Both signatures are valid; the producer is trying to change the fact
	// behind one committed identity. No prefix of this batch may be stored.
	batch.Records[1].Event.Detail.Code = "CONFLICT"
	batch.Records[1].Signature = ed25519.Sign(source.self.Private, SigningBytes(batch.Records[1]))
	batch.Signature = ed25519.Sign(source.self.Private, BatchBytes(batch))
	clean, _ := fixture(t, "node-c")
	if err = clean.Receive(batch, 4002); !errors.Is(err, ErrInvalid) {
		t.Fatal("conflicting authority accepted", err)
	}
	page, err = clean.Page(Query{}, 4002, accept)
	if err != nil || len(page.Items) != 0 {
		t.Fatal("rejected batch wrote a prefix", err)
	}
	receipt, err = clean.Receipt(source.Source())
	if err != nil || receipt.Last != 0 {
		t.Fatal("rejected batch advanced source position", err)
	}
	// Retained source identity is immutable even with a fresh valid signature.
	batch.Records = batch.Records[:1]
	batch.Records[0].Event.Detail.Code = "CHANGED_SOURCE_FACT"
	batch.Records[0].Signature = ed25519.Sign(source.self.Private, SigningBytes(batch.Records[0]))
	batch.Signature = ed25519.Sign(source.self.Private, BatchBytes(batch))
	if err = receiver.Receive(batch, 4002); !errors.Is(err, ErrInvalid) {
		t.Fatal("retained source identity replaced", err)
	}
}

func TestAcceptedSourceClockSkewDoesNotLoseEventAndIdleHistoryExpires(t *testing.T) {
	s, _ := fixture(t, "node-a")
	now := uint64(100000)
	e := taskEvent(now+1000, "tenant", "task-exited")
	if _, err := s.Append("ahead-clock", e, now); err != nil {
		t.Fatal(err)
	}
	page, err := s.Page(Query{Tenant: "tenant"}, now, accept)
	if err != nil || len(page.Items) != 1 || page.Items[0].At != e.At {
		t.Fatal("accepted source event skipped behind cursor", err)
	}
	if _, err = s.Append("clock-too-far", taskEvent(now+30001, "tenant", "task-exited"), now); !errors.Is(err, ErrInvalid) {
		t.Fatal("unbounded future source clock accepted", err)
	}
	history, _, err := s.History("tenant", "app", e.Target.Task, 20, now+1001+RetentionMillis)
	if err != nil || len(history) != 0 {
		t.Fatal("idle detail retained expired history", err)
	}
	if err = s.UpdateRelated(nil, now+1001+RetentionMillis); err != nil {
		t.Fatal("idle retention with no source metadata update", err)
	}
}
