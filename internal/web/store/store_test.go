// SPDX-License-Identifier: Apache-2.0

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "web.db")
	s, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func TestOpsStateIndex(t *testing.T) {
	s, p := open(t)
	t0 := time.Unix(1000, 0)
	for i, id := range []string{"a", "b", "c"} {
		if ex, err := s.CreateOp(&Op{ID: id, User: "u", State: OpPending, SubmittedAt: t0.Add(time.Duration(i) * time.Second), UpdatedAt: t0}); err != nil || ex != nil {
			t.Fatal(ex, err)
		}
	}
	if ex, _ := s.CreateOp(&Op{ID: "a", User: "u", Digest: "other"}); ex == nil || ex.ID != "a" {
		t.Fatal("existing op must be returned, not overwritten")
	}
	o, _ := s.GetOp("u", "b")
	o.State, o.UpdatedAt = OpApplied, t0
	if err := s.UpdateOp(o); err != nil {
		t.Fatal(err)
	}
	pend, _ := s.ListOps("u", OpPending, 0)
	if len(pend) != 2 || pend[0].ID != "c" || pend[1].ID != "a" {
		t.Fatalf("pending newest first: %+v", pend)
	}
	all, _ := s.ListOps("u", "", 0)
	if len(all) != 3 || all[0].ID != "c" {
		t.Fatalf("all: %+v", all)
	}
	if other, _ := s.ListOps("v", "", 0); len(other) != 0 {
		t.Fatal("ops of another user leaked")
	}
	n, _ := s.PruneOps(t0.Add(time.Hour))
	if n != 1 {
		t.Fatalf("prune removes settled only, got %d", n)
	}
	if ap, _ := s.ListOps("u", OpApplied, 0); len(ap) != 0 {
		t.Fatal("index entry not pruned")
	}
	s.Close()
	// reopen keeps data and schema
	s2, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if pend, _ := s2.ListOps("u", OpPending, 0); len(pend) != 2 {
		t.Fatal("pending ops lost on reopen")
	}
}

func TestSecondOpenFails(t *testing.T) {
	s, p := open(t)
	defer s.Close()
	if _, err := Open(p); err == nil {
		t.Fatal("a second process must not open the same DB")
	}
}

func TestSessionsExpireOnStart(t *testing.T) {
	s, _ := open(t)
	defer s.Close()
	now := time.Unix(5000, 0)
	_ = s.PutSession(&SessionRow{Hash: "h1", User: "u", IssuedAt: now})
	_ = s.PutSession(&SessionRow{Hash: "h2", User: "u", IssuedAt: now})
	_ = s.EndSession("h2", "logout", now)
	if err := s.ExpireOpenSessions(now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.ListSessions("u")
	for _, r := range rows {
		if r.EndedAt.IsZero() {
			t.Fatalf("open row after restart: %+v", r)
		}
		if r.Hash == "h2" && r.EndReason != "logout" {
			t.Fatalf("ended row rewritten: %+v", r)
		}
	}
	_ = s.PruneSessions(now.Add(time.Hour))
	if rows, _ := s.ListSessions(""); len(rows) != 0 {
		t.Fatal("prune")
	}
}

func TestArchivedByTenant(t *testing.T) {
	s, _ := open(t)
	defer s.Close()
	at := time.Unix(100, 0)
	k1, _ := s.PutArchived(&ArchivedApp{Tenant: "shop", App: "web", Source: []byte("x"), DownAt: at})
	_, _ = s.PutArchived(&ArchivedApp{Tenant: "shop", App: "web", DownAt: at.Add(time.Second)})
	_, _ = s.PutArchived(&ArchivedApp{Tenant: "shopx", App: "web", DownAt: at})
	rows, _ := s.ListArchived("shop")
	if len(rows) != 2 || !rows[0].DownAt.After(rows[1].DownAt) {
		t.Fatalf("archived newest first, tenant prefix exact: %+v", rows)
	}
	if err := s.DeleteArchived(k1); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteArchived(k1); err != ErrNotFound {
		t.Fatal("double delete")
	}
}
